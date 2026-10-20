'use strict';
 
// ADMIN-only store registry. Does not create Supabase Auth accounts.
module.exports = function registerStoreManagement({ app, pool, authenticate, adminOnly }) {
    const guard = [authenticate, adminOnly];
    const clean = v => String(v == null ? '' : v).trim();
    const email = v => clean(v).toLowerCase();
    const bad = (res, status, message) => res.status(status).json({ error: message });
    const validEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 255;
 
    app.get('/api/admin/stores', ...guard, async (req, res) => {
        try {
            const { rows } = await pool.query(
                `SELECT store_id, store_name, store_email, status, created_at
                 FROM public.stores ORDER BY store_name, store_id`            );
            res.json(rows);
        } catch (err) {
            console.error('[STORE MANAGEMENT list]', err);
            bad(res, 500, 'Could not load stores');
        }
    });
 
    app.post('/api/admin/stores', ...guard, async (req, res) => {
        const name = clean(req.body?.store_name);
        const mail = email(req.body?.store_email);
        if (!name || name.length > 255) return bad(res, 400, 'Store name is required (maximum 255 characters)');
        if (!validEmail(mail)) return bad(res, 400, 'A valid store email is required');
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const duplicate = await client.query(
                `SELECT store_id FROM public.stores
                 WHERE LOWER(store_name) = LOWER($1)
                    OR LOWER(COALESCE(store_email, '')) = $2
                 LIMIT 1 FOR UPDATE`, [name, mail]
            );
            if (duplicate.rowCount) {
                await client.query('ROLLBACK');
                return bad(res, 409, 'A store with this name or email already exists');
            }
            const { rows } = await client.query(
                `INSERT INTO public.stores (store_name, store_email, status)
                 VALUES ($1, $2, 'ACTIVE')
                 RETURNING store_id, store_name, store_email, status, created_at`,
                [name, mail]
            );
            await client.query('COMMIT');
            res.status(201).json({ store: rows[0], login_created: false });
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            console.error('[STORE MANAGEMENT create]', err);
            bad(res, err.code === '23505' ? 409 : 500,
                err.code === '23505' ? 'Store name or email already exists' : 'Could not create store');
        } finally {
            client.release();
        }
    });
 
    // Store name/email are referenced elsewhere by existing NEMS records.
    // Permit identity edits only for a store without dependent user, task,
    // monitoring or AS assignment records, to avoid breaking existing links.
    app.patch('/api/admin/stores/:id', ...guard, async (req, res) => {
        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id <= 0) return bad(res, 400, 'Invalid store ID');
        const body = req.body || {};
        const hasName = Object.prototype.hasOwnProperty.call(body, 'store_name');
        const hasEmail = Object.prototype.hasOwnProperty.call(body, 'store_email');
        const hasStatus = Object.prototype.hasOwnProperty.call(body, 'status');
        if (!hasName && !hasEmail && !hasStatus) return bad(res, 400, 'No changes supplied');
        const name = hasName ? clean(body.store_name) : null;
        const mail = hasEmail ? email(body.store_email) : null;
        const status = hasStatus ? clean(body.status).toUpperCase() : null;
        if (hasName && (!name || name.length > 255)) return bad(res, 400, 'Invalid store name');
        if (hasEmail && !validEmail(mail)) return bad(res, 400, 'Invalid store email');
        if (hasStatus && !['ACTIVE', 'INACTIVE'].includes(status))
            return bad(res, 400, 'Status must be ACTIVE or INACTIVE');
 
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const current = await client.query(
                `SELECT store_id, store_name, store_email, status
                 FROM public.stores WHERE store_id = $1 FOR UPDATE`, [id]
            );
            if (!current.rowCount) {
                await client.query('ROLLBACK');
                return bad(res, 404, 'Store not found');
            }
            const old = current.rows[0];
            const changingIdentity = (hasName && name !== old.store_name) ||
                (hasEmail && mail !== email(old.store_email));
            if (changingIdentity) {
                // Check only tables known to exist in this NEMS installation.
                const linked = await client.query(
                    `SELECT
                      EXISTS (SELECT 1 FROM public.users WHERE store_name = $1) AS users,
                      EXISTS (SELECT 1 FROM public.as_store_assignments WHERE store_id = $2) AS assignments`,
                    [old.store_name, id]
                );
                if (linked.rows[0].users || linked.rows[0].assignments) {
                    await client.query('ROLLBACK');
                    return bad(res, 409,
                        'Store has linked users or AS assignments. To protect existing records, its name/email cannot be changed here.');
                }
                // Task/monitoring data may reference store_name or store_email;
                // never rename an existing store through this endpoint.
                await client.query('ROLLBACK');
                return bad(res, 409,
                    'Store name/email editing is locked to protect task and monitoring history. Contact the administrator for a coordinated rename.');
            }
            const updated = await client.query(
                `UPDATE public.stores SET status = COALESCE($2, status)
                 WHERE store_id = $1
                 RETURNING store_id, store_name, store_email, status, created_at`,
                [id, status]
            );
            await client.query('COMMIT');
            res.json({ store: updated.rows[0] });
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            console.error('[STORE MANAGEMENT update]', err);
            bad(res, 500, 'Could not update store');
        } finally {
            client.release();
        }
    });
};
