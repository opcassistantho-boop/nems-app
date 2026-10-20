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
            return res.status(201).json({ email, role, status: 'INACTIVE', message: 'User created. ADMIN activation required.' });
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
