'use strict';

 

// NEMS ADMIN User Management. This module never exposes the Supabase secret to browsers.

module.exports = function registerUserRoutes({ app, pool, authenticate, adminOnly }) {

    const secret = process.env.SUPABASE_SERVICE_ROLE_KEY;

    const base = (process.env.SUPABASE_URL || '').replace(/\/$/, '');

    const roles = new Set(['ADMIN', 'HEAD', 'AOM', 'AS', 'STORE']);

    const fail = (res, code, message) => res.status(code).json({ error: message });

    const emailOf = v => String(v || '').trim().toLowerCase();

    const integer = v => Number.isSafeInteger(Number(v)) && Number(v) > 0 ? Number(v) : null;

    const route = [authenticate, adminOnly];

 

    const nodemailer = require('nodemailer');

    const smtpUser = String(process.env.SMTP_USER || '').trim();

    const smtpPassword = String(process.env.SMTP_PASSWORD || '').replace(/\s/g, '');

    const smtpHost = String(process.env.SMTP_HOST || 'smtp.gmail.com').trim();

    const smtpPort = Number(process.env.SMTP_PORT || 465);

    const mailer = smtpUser && smtpPassword ? nodemailer.createTransport({

        host: smtpHost, port: smtpPort, secure: smtpPort === 465,

        auth: { user: smtpUser, pass: smtpPassword },

        connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 20000

    }) : null;

 

    async function sendInvitation(email) {

        if (!mailer) throw new Error('SMTP_NOT_CONFIGURED');

        const redirectTo = (process.env.NEMS_PUBLIC_URL || 'https://nems-app.onrender.com').replace(/\/$/, '') + '/';

        const generated = await authAdmin('generate_link', 'POST', {

            type: 'recovery', email, options: { redirect_to: redirectTo }

        });

        const link = generated.action_link || generated.properties?.action_link;

        if (!link) throw new Error('SUPABASE_LINK_NOT_RETURNED');

        await mailer.sendMail({

            from: { name: 'CARD INDOGROSIR NEMS', address: smtpUser },

            to: email,

            subject: 'NEMS - Set up your password',

            text: 'You have a NEMS account. Open the following private link to set your password:\n\n' +

                link + '\n\nIf you did not expect this invitation, ignore this message. ' +

                'You can sign in only after an ADMIN activates your account.',

            html: '<p>You have a NEMS account.</p><p><a href="' +

                link.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;') +

                '">Set up your NEMS password</a></p><p>If you did not expect this invitation, ignore this message. ' +

                'You can sign in only after an ADMIN activates your account.</p>'

        });

    }

 

 

    async function authAdmin(path, method, body) {

        if (!secret || !base) throw new Error('SUPABASE_ADMIN_NOT_CONFIGURED');

        const response = await fetch(`${base}/auth/v1/admin/${path}`, {

            method,

            headers: { apikey: secret, Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },

            ...(body === undefined ? {} : { body: JSON.stringify(body) })

        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {

            const err = new Error(data.msg || data.message || data.error || 'Supabase Auth request failed');

            err.status = response.status;

            throw err;

        }

        return data;

    }

 

    async function validateStoreIds(client, ids) {

        if (!Array.isArray(ids) || ids.some(x => !integer(x))) return null;

        const unique = [...new Set(ids.map(Number))];

        if (!unique.length) return [];

        const result = await client.query(

            `SELECT store_id FROM public.stores WHERE store_id = ANY($1::bigint[]) AND status = 'ACTIVE'`,

            [unique]

        );

        return result.rowCount === unique.length ? unique : null;

    }

 

    async function setASStores(client, email, ids) {

        await client.query('DELETE FROM public.as_store_assignments WHERE LOWER(as_email) = $1', [email]);

        for (const id of ids) {

            await client.query(

                'INSERT INTO public.as_store_assignments (as_email, store_id) VALUES ($1, $2)',

                [email, id]

            );

        }

    }

 

    // ADMIN sends a password invitation to an existing NEMS account.

    app.post('/api/admin/users/password-link', ...route, async (req, res) => {

        const email = emailOf(req.body?.email);

        if (!email) return fail(res, 400, 'Email required');

        try {

            const existing = await pool.query('SELECT 1 FROM public.users WHERE LOWER(email)=$1', [email]);

            if (!existing.rowCount) return fail(res, 404, 'NEMS account not found');

            await sendInvitation(email);

            res.set('Cache-Control', 'no-store');

            return res.json({ message: 'Password invitation emailed to ' + email, sent: true });

        } catch (err) {

            console.error('[NEMS USERS invitation]', err.message);

            return fail(res, 502, err.message === 'SMTP_NOT_CONFIGURED' ?

                'Email sender is not configured in Render' :

                'Unable to send invitation email. Check Render logs and Gmail settings.');

        }

    });

 

    // A recovery token changes only the authenticated Supabase user's password.

    // This does not approve/activate the corresponding NEMS account.

    app.post('/api/password/setup', async (req, res) => {

        const accessToken = req.body?.access_token;

        const password = req.body?.password;

        if (typeof accessToken !== 'string' || !accessToken ||

            typeof password !== 'string' || password.length < 12 || password.length > 128) {

            return fail(res, 400, 'Valid recovery token and password (12–128 characters) required');

        }

        try {

            const headers = { apikey: process.env.SUPABASE_ANON_KEY,

                Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };

            const identity = await fetch(`${base}/auth/v1/user`, { headers });

            if (!identity.ok) return fail(res, 401, 'Password setup link has expired or is invalid');

            const authUser = await identity.json();

            const account = await pool.query(

                'SELECT 1 FROM public.users WHERE auth_user_id=$1::uuid AND LOWER(email)=$2',

                [authUser.id, emailOf(authUser.email)]

            );

            if (!account.rowCount) return fail(res, 403, 'NEMS account not found');

            const changed = await fetch(`${base}/auth/v1/user`, {

                method: 'PUT', headers, body: JSON.stringify({ password })

            });

            if (!changed.ok) return fail(res, 400, 'Could not save password. Request a new link.');

            res.set('Cache-Control', 'no-store');

            return res.json({ message: 'Password saved. You may log in once ADMIN has activated your account.' });

        } catch (err) {

            console.error('[NEMS USERS password setup]', err.message);

            return fail(res, 500, 'Password setup temporarily unavailable');

        }

    });

 

    app.get('/api/admin/users/stores', ...route, async (req, res) => {

        try {

            const { rows } = await pool.query(

                `SELECT store_id, store_name, store_email, status FROM public.stores ORDER BY store_name`

            );

            res.json(rows);

        } catch (err) {

            console.error('[NEMS USERS stores]', err);

            fail(res, 500, 'Unable to load stores');

        }

    });

 

    app.get('/api/admin/users', ...route, async (req, res) => {

        try {

            const { rows } = await pool.query(`

                SELECT u.email, u.full_name, u.role, u.status, u.store_name, u.created_at,

                    COALESCE((SELECT array_agg(DISTINCT a.store_id ORDER BY a.store_id)

                              FROM public.as_store_assignments a

                              WHERE LOWER(a.as_email) = LOWER(u.email)), ARRAY[]::bigint[]) AS assigned_store_ids

                FROM public.users u

                ORDER BY u.created_at DESC NULLS LAST, u.email

            `);

            res.json(rows);

        } catch (err) {

            console.error('[NEMS USERS list]', err);

            fail(res, 500, 'Unable to load users');

        }

    });

 

    app.post('/api/admin/users', ...route, async (req, res) => {

        const body = req.body || {};

        const email = emailOf(body.email);

        const name = String(body.full_name || '').trim();

        const role = String(body.role || '').toUpperCase();

        const password = body.password;

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255 ||

            !name || name.length > 255 || !roles.has(role) ||

            typeof password !== 'string' || password.length < 12 || password.length > 128) {

            return fail(res, 400, 'Provide a valid email, name, role and password (12–128 characters)');

        }

        // New ADMIN accounts also require explicit activation by an existing ADMIN.

        const client = await pool.connect().catch(() => null);

        if (!client) return fail(res, 500, 'Database unavailable');

        let authId = null;

        let committed = false;

        try {

            await client.query('BEGIN');

            const duplicate = await client.query('SELECT 1 FROM public.users WHERE LOWER(email) = $1', [email]);

            if (duplicate.rowCount) {

                await client.query('ROLLBACK');

                return fail(res, 409, 'Email already exists in NEMS');

            }

            let storeName = null;

            let storeIds = [];

            if (role === 'STORE') {

                const id = integer(body.store_id);

                if (!id) { await client.query('ROLLBACK'); return fail(res, 400, 'Select a store'); }

                const store = await client.query(

                    `SELECT store_name, store_email FROM public.stores WHERE store_id=$1 AND status='ACTIVE'`, [id]

                );

                if (!store.rowCount || emailOf(store.rows[0].store_email) !== email) {

                    await client.query('ROLLBACK');

                    return fail(res, 400, 'STORE email must match the registered store email');

                }

                storeName = store.rows[0].store_name;

            } else if (role === 'AS') {

                storeIds = await validateStoreIds(client, body.store_ids);

                if (!storeIds || !storeIds.length) {

                    await client.query('ROLLBACK');

                    return fail(res, 400, 'Assign at least one active store to AS');

                }

            }

            const created = await authAdmin('users', 'POST', {

                email, password, email_confirm: true,

                app_metadata: { nems_pending_admin_approval: true }

            });

            authId = created.id || created.user?.id;

            if (!authId) throw new Error('Supabase did not return a user ID');

            await client.query(

                `INSERT INTO public.users (email, full_name, role, status, store_name, auth_user_id)

                 VALUES ($1, $2, $3, 'INACTIVE', $4, $5::uuid)`,

                [email, name, role, storeName, authId]

            );

            if (role === 'AS') await setASStores(client, email, storeIds);

            await client.query('COMMIT');

            committed = true;

            let invitationSent = false;

            try {

                await sendInvitation(email);

                invitationSent = true;

            } catch (mailError) {

                console.error('[NEMS USERS new user invitation failed]', mailError.message);

            }

            return res.status(201).json({ email, role, status: 'INACTIVE',

                invitation_sent: invitationSent,

                message: invitationSent ?

                    'User created and invitation emailed. ADMIN activation required.' :

                    'User created, but invitation email failed. Use Send Invitation to retry. ADMIN activation required.' });

        } catch (err) {

            if (!committed) await client.query('ROLLBACK').catch(() => {});

            if (authId && !committed) {

                try { await authAdmin(`users/${encodeURIComponent(authId)}`, 'DELETE'); }

                catch (cleanupError) { console.error('[NEMS USERS orphaned Auth user requires manual reconciliation]', authId, cleanupError); }

            }

            console.error('[NEMS USERS create]', err);

            return fail(res, err.status === 422 ? 409 : 500,

                err.message === 'SUPABASE_ADMIN_NOT_CONFIGURED' ? 'Supabase administrator key is not configured' :

                err.status === 422 ? 'Account already exists in Supabase Authentication' : 'Unable to create user');

        } finally { client.release(); }

    });

 

    app.patch('/api/admin/users/:email', ...route, async (req, res) => {

        const email = emailOf(req.params.email);

        const body = req.body || {};

        const role = String(body.role || '').toUpperCase();

        const name = String(body.full_name || '').trim();

        const status = String(body.status || '').toUpperCase();

        if (!roles.has(role) || !['ACTIVE', 'INACTIVE'].includes(status) || !name || name.length > 255) {

            return fail(res, 400, 'Invalid name, role or status');

        }

        if (email === emailOf(req.user.email) && (status !== 'ACTIVE' || role !== 'ADMIN')) {

            return fail(res, 403, 'Cannot deactivate or demote your own ADMIN account');

        }

        const client = await pool.connect().catch(() => null);

        if (!client) return fail(res, 500, 'Database unavailable');

        try {

            await client.query('BEGIN');

            const existing = await client.query(

                'SELECT email, role, status FROM public.users WHERE LOWER(email)=$1 FOR UPDATE', [email]

            );

            if (!existing.rowCount) { await client.query('ROLLBACK'); return fail(res, 404, 'User not found'); }

            if (existing.rows[0].role === 'ADMIN' && (role !== 'ADMIN' || status !== 'ACTIVE')) {

                const count = await client.query("SELECT COUNT(*)::integer AS n FROM public.users WHERE role='ADMIN' AND status='ACTIVE'");

                if (count.rows[0].n <= 1) {

                    await client.query('ROLLBACK');

                    return fail(res, 403, 'Cannot remove the last active ADMIN');

                }

            }

            let storeName = null;

            let storeIds = [];

            if (role === 'STORE') {

                const id = integer(body.store_id);

                const store = id ? await client.query(

                    `SELECT store_name, store_email FROM public.stores WHERE store_id=$1 AND status='ACTIVE'`, [id]

                ) : { rows: [] };

                if (!store.rows.length || emailOf(store.rows[0].store_email) !== email) {

                    await client.query('ROLLBACK');

                    return fail(res, 400, 'STORE email must match the registered store email');

                }

                storeName = store.rows[0].store_name;

            } else if (role === 'AS') {

                storeIds = await validateStoreIds(client, body.store_ids);

                if (!storeIds || !storeIds.length) {

                    await client.query('ROLLBACK');

                    return fail(res, 400, 'Assign at least one active store to AS');

                }

            }

            await client.query(

                'UPDATE public.users SET full_name=$1, role=$2, status=$3, store_name=$4 WHERE LOWER(email)=$5',

                [name, role, status, storeName, email]

            );

            await setASStores(client, email, role === 'AS' ? storeIds : []);

            await client.query('COMMIT');

            return res.json({ email, full_name: name, role, status, store_name: storeName });

        } catch (err) {

            await client.query('ROLLBACK').catch(() => {});

            console.error('[NEMS USERS update]', err);

            return fail(res, 500, 'Unable to update user');

        } finally { client.release(); }

    });

};
