'use strict';

const { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');

const derive = promisify(scrypt);
const digest = value => createHash('sha256').update(value).digest('hex');
const emailOf = value => String(value || '').trim().toLowerCase();
const validPassword = value => typeof value === 'string' && value.length >= 12 && value.length <= 128;
const response = (status, data = {}) => ({ status, ok: status >= 200 && status < 300, json: async () => data });

module.exports = function createLocalAuth(pool, publicUrl) {
    const origin = new URL(publicUrl);
    if (origin.protocol !== 'https:' || origin.username || origin.password) {
        throw new Error('NEMS_PUBLIC_URL must use HTTPS');
    }

    let pendingDerivations = 0;
    async function passwordKey(password, salt) {
        if (pendingDerivations >= 3) {
            throw Object.assign(new Error('Password service busy'), { status: 503 });
        }
        pendingDerivations++;
        try {
            return await derive(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
        } finally {
            pendingDerivations--;
        }
    }

    async function passwordHash(password) {
        const salt = randomBytes(16);
        return salt.toString('hex') + ':' + (await passwordKey(password, salt)).toString('hex');
    }

    async function initialize() {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query("SELECT pg_advisory_xact_lock(hashtext('nems-local-auth-schema'))");
            await client.query(`
                CREATE SCHEMA IF NOT EXISTS nems_auth;
                REVOKE ALL ON SCHEMA nems_auth FROM PUBLIC;
                CREATE TABLE IF NOT EXISTS nems_auth.identities (
                    id uuid PRIMARY KEY,
                    email text NOT NULL UNIQUE,
                    password_hash text,
                    attempts integer NOT NULL DEFAULT 0,
                    window_started timestamptz NOT NULL DEFAULT now(),
                    recovery_requested_at timestamptz
                );
                CREATE TABLE IF NOT EXISTS nems_auth.tokens (
                    digest text PRIMARY KEY,
                    identity_id uuid NOT NULL REFERENCES nems_auth.identities(id) ON DELETE CASCADE,
                    purpose text NOT NULL CHECK (purpose IN ('session', 'recovery')),
                    expires_at timestamptz NOT NULL
                );
                CREATE INDEX IF NOT EXISTS nems_auth_tokens_identity ON nems_auth.tokens(identity_id);
                INSERT INTO nems_auth.identities (id, email)
                SELECT auth_user_id, lower(email) FROM public.users WHERE auth_user_id IS NOT NULL
                ON CONFLICT DO NOTHING;
            `);
            await client.query('COMMIT');
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async function transaction(operation) {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const result = await operation(client);
            await client.query('COMMIT');
            return result;
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }

    async function issueToken(client, identity, purpose, lifetime) {
        const token = randomBytes(32).toString('base64url');
        await client.query('DELETE FROM nems_auth.tokens WHERE identity_id=$1 AND expires_at <= now()', [identity]);
        await client.query(`
            INSERT INTO nems_auth.tokens (digest, identity_id, purpose, expires_at)
            VALUES ($1, $2, $3, now() + $4::interval)
        `, [digest(token), identity, purpose, lifetime]);
        return token;
    }

    async function login({ email, password }, issueSession) {
        if (typeof password !== 'string' || !password || password.length > 128) return response(401);
        const { rows: [identity] } = await pool.query(`
            UPDATE nems_auth.identities i
            SET attempts = CASE WHEN window_started <= now() - interval '15 minutes' THEN 1 ELSE attempts + 1 END,
                window_started = CASE WHEN window_started <= now() - interval '15 minutes' THEN now() ELSE window_started END
            WHERE i.email=$1 AND i.password_hash IS NOT NULL
              AND (attempts < 12 OR window_started <= now() - interval '15 minutes')
              AND EXISTS (SELECT 1 FROM public.users u WHERE u.auth_user_id=i.id AND lower(u.email)=i.email AND u.status='ACTIVE')
            RETURNING id, email, password_hash
        `, [emailOf(email)]);
        if (!identity) return response(401);
        const [salt, expected] = identity.password_hash.split(':');
        const actual = await passwordKey(password, Buffer.from(salt, 'hex'));
        if (!timingSafeEqual(actual, Buffer.from(expected, 'hex'))) return response(401);

        return transaction(async client => {
            const reset = await client.query(`
                UPDATE nems_auth.identities SET attempts=0 WHERE id=$1 AND password_hash=$2 RETURNING id
            `, [identity.id, identity.password_hash]);
            if (!reset.rowCount) return response(401);
            const user = { id: identity.id, email: identity.email };
            if (!issueSession) return response(200, { user });
            const access_token = await issueToken(client, identity.id, 'session', '8 hours');
            return response(200, { access_token, user });
        });
    }

    async function identify(token, purpose) {
        if (!/^[A-Za-z0-9_-]{43}$/.test(token || '')) return null;
        const { rows: [identity] } = await pool.query(`
            SELECT i.id, i.email FROM nems_auth.tokens t
            JOIN nems_auth.identities i ON i.id=t.identity_id
            WHERE t.digest=$1 AND t.purpose=$2 AND t.expires_at>now()
        `, [digest(token), purpose]);
        return identity || null;
    }

    async function setPassword(id, password, token, purpose) {
        if (!validPassword(password)) return response(400);
        const hash = await passwordHash(password);
        return transaction(async client => {
            const { rows: [identity] } = await client.query(
                'SELECT id,email FROM nems_auth.identities WHERE id=$1 FOR UPDATE', [id]
            );
            if (!identity) return response(404);
            if (purpose) {
                const consumed = await client.query(`
                    DELETE FROM nems_auth.tokens WHERE digest=$1 AND identity_id=$2
                      AND purpose=$3 AND expires_at>now() RETURNING digest
                `, [digest(token), id, purpose]);
                if (!consumed.rowCount) return response(401);
            }
            await client.query('UPDATE nems_auth.identities SET password_hash=$2,attempts=0,recovery_requested_at=NULL WHERE id=$1', [id, hash]);
            await client.query('DELETE FROM nems_auth.tokens WHERE identity_id=$1', [id]);
            return response(200, identity);
        });
    }

    async function recoveryLink(email) {
        return transaction(async client => {
            const { rows: [identity] } = await client.query(`
                UPDATE nems_auth.identities i SET recovery_requested_at=now()
                WHERE i.email=$1 AND (i.recovery_requested_at IS NULL OR i.recovery_requested_at <= now() - interval '1 minute')
                  AND EXISTS (SELECT 1 FROM public.users u WHERE u.auth_user_id=i.id AND lower(u.email)=i.email)
                RETURNING id
            `, [emailOf(email)]);
            if (!identity) return response(429, { message: 'Recovery unavailable or requested recently' });
            await client.query("DELETE FROM nems_auth.tokens WHERE identity_id=$1 AND purpose='recovery'", [identity.id]);
            const token = await issueToken(client, identity.id, 'recovery', '30 minutes');
            const link = new URL('/', origin);
            link.hash = new URLSearchParams({ type: 'recovery', access_token: token }).toString();
            return response(200, { action_link: link.href });
        });
    }

    async function ensureIdentity(client, linkedId, email) {
        const { rows: [identity] } = await client.query(`
            INSERT INTO nems_auth.identities (id,email) VALUES ($1,$2)
            ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email
            WHERE $3::uuid IS NULL OR nems_auth.identities.id=$3::uuid
            RETURNING id,email
        `, [linkedId || randomUUID(), email, linkedId]);
        if (!identity) throw new Error('AUTH_IDENTITY_MISMATCH');
        return identity;
    }

    // Internal adapter. No provider admin endpoints are exposed over HTTP.
    async function admin(path, method, body, client = pool) {
        const [route, parameters] = path.split('?');
        if (route === 'generate_link' && method === 'POST') return recoveryLink(body.email);
        if (route === 'users' && method === 'POST') {
            try {
                const { rows: [user] } = await client.query(
                    'INSERT INTO nems_auth.identities (id,email) VALUES ($1,$2) RETURNING id,email',
                    [randomUUID(), emailOf(body.email)]
                );
                return response(201, user);
            } catch (error) {
                if (error.code === '23505') return response(422, { message: 'Account already exists' });
                throw error;
            }
        }
        if (route === 'users' && method === 'GET') {
            const page = Number(new URLSearchParams(parameters).get('page')) || 1;
            const { rows: users } = await pool.query(
                'SELECT id,email FROM nems_auth.identities ORDER BY id LIMIT 1000 OFFSET $1', [(page - 1) * 1000]
            );
            return response(200, { users });
        }
        const id = route.match(/^users\/([0-9a-f-]{36})$/i)?.[1];
        if (!id) return response(404);
        if (method === 'PUT') return setPassword(id, body.password);
        if (method === 'DELETE') {
            await pool.query('DELETE FROM nems_auth.identities WHERE id=$1', [id]);
            return response(200);
        }
        const { rows: [user] } = await pool.query('SELECT id,email FROM nems_auth.identities WHERE id=$1', [id]);
        return user ? response(200, user) : response(404);
    }

    return { initialize, login, identify, setPassword, admin, ensureIdentity };
};
