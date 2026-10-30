'use strict';
 
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const XLSX = require('xlsx');
 
const app = express();
 
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
 
// ==========================================
// DATABASE CONNECTION
// ==========================================
 
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL_DISABLE === 'true'
        ? false
        : { rejectUnauthorized: false },
    max: 10
});
 
// ==========================================
// SUPABASE AUTHENTICATION
// ==========================================
 
const SUPABASE_URL = (
    process.env.SUPABASE_URL || ''
).replace(/\/$/, '');
 
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
 
if (
    !process.env.DATABASE_URL ||
    !SUPABASE_URL ||
    !SUPABASE_ANON_KEY
) {
    console.error(
        'Missing DATABASE_URL, SUPABASE_URL, or SUPABASE_ANON_KEY'
    );
    process.exit(1);
}
 
app.use(
    express.static(
        path.join(__dirname, 'public'),
        { index: false }
    )
);
 
app.get('/', (req, res) => {
    res.sendFile(
        path.join(__dirname, 'index.html')
    );
});
 
// ==========================================
// HELPERS
// ==========================================
 
function sendError(res, status, message) {
    return res.status(status).json({
        error: message
    });}
 
function cleanEmail(email) {
    return String(email || '')
        .trim()
        .toLowerCase();
}
 
const VALID_ROLES = [
    'STORE',
    'AS',
    'AOM',
    'HEAD',
    'ADMIN'
];
 
function adminOnly(req, res, next) {
    if (req.user.role !== 'ADMIN') {
        return sendError(
            res,
            403,
            'ADMIN access required'
        );
    }
 
    next();
}
 
function requiredText(value, max = 255) {
    if (typeof value !== 'string') {
        return null;
    }
 
    const text = value.trim();
 
    return text && text.length <= max
        ? text
        : null;
}
 
function optionalText(value, max = 255) {
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return null;
    }
 
    if (
        typeof value !== 'string' ||
        value.trim().length > max
    ) {
        return undefined;
    }
 
    return value.trim() || null;
}
 
function optionalPrice(value) {
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return null;
    }
 
    const number = Number(value);
 
    return (
        Number.isFinite(number) &&
        number >= 0 &&
        number <= 999999999
    )
        ? number
        : undefined;
}
 
function validId(value) {
    const id = Number(value);
 
    return Number.isSafeInteger(id) && id > 0
        ? id
        : null;
}
 
function databaseError(res, error, fallback) {
    console.error(
        'Database error:',
        error.code || error.message
    );
 
    if (error.code === '23505') {
        return sendError(
            res,
            409,
            'This record already exists'
        );
    }
 
    if (error.code === '23503') {
        return sendError(
            res,
            409,
            'A related supplier or product record is missing or in use'
        );
    }
 
    return sendError(res, 500, fallback);
}
 
// ==========================================
// SECURE LOGIN
// ==========================================
 
app.post('/api/login', async (req, res) => {
    const email = cleanEmail(req.body.email);
    const password = req.body.password;
 
    if (
        !email ||
        typeof password !== 'string' ||
        !password
    ) {
        return sendError(
            res,
            400,
            'Email and password are required'
        );
    }
 
    try {
        const response = await fetch(
            `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
            {
                method: 'POST',
                headers: {
                    apikey: SUPABASE_ANON_KEY,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email,
                    password
                })
            }
        );
 
        const result = await response.json();
 
        if (
            !response.ok ||
            !result.access_token ||
            !result.user?.id
        ) {
            return sendError(
                res,
                401,
                'Invalid email or password'
            );
        }
 
        const { rows } = await pool.query(
            `
            SELECT
                email,
                store_name,
                role,
                status
            FROM public.users
            WHERE auth_user_id = $1::uuid
              AND LOWER(email) = $2
              AND status = 'ACTIVE'
            `,
            [
                result.user.id,
                email
            ]
        );
 
        if (
            !rows.length ||
            !VALID_ROLES.includes(rows[0].role)
        ) {
            return sendError(
                res,
                403,
                'Account not activated for NEMS'
            );
        }
 
        res.json({
            token: result.access_token,
            user: rows[0]
        });
 
    } catch (error) {
        console.error('Login error:', error);
 
        sendError(
            res,
            500,
            'Login temporarily unavailable'
        );
    }
});
 
// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================
 
async function authenticate(req, res, next) {
    const match = /^Bearer (.+)$/i.exec(
        req.headers.authorization || ''
    );
 
    const token = match?.[1];
 
    if (!token) {
        return sendError(
            res,
            401,
            'Login required'
        );
    }
 
    try {
        const response = await fetch(
            `${SUPABASE_URL}/auth/v1/user`,
            {
                headers: {
                    apikey: SUPABASE_ANON_KEY,
                    Authorization: `Bearer ${token}`
                }
            }
        );
 
        if (!response.ok) {
            return sendError(
                res,
                401,
                'Session expired. Log in again.'
            );
        }
 
        const authUser = await response.json();
 
        if (
            !authUser.id ||
            !authUser.email
        ) {
            return sendError(
                res,
                401,
                'Invalid session'
            );
        }
 
        const { rows } = await pool.query(
            `
            SELECT
                email,
                store_name,
                role
            FROM public.users
            WHERE auth_user_id = $1::uuid
              AND LOWER(email) = $2
              AND status = 'ACTIVE'
            `,
            [
                authUser.id,
                cleanEmail(authUser.email)
            ]
        );
 
        if (
            !rows.length ||
            !VALID_ROLES.includes(rows[0].role)
        ) {
            return sendError(
                res,
                403,
                'Account not active'
            );
        }
 
        req.user = rows[0];
 
        next();
 
    } catch (error) {
        console.error(
            'Authentication error:',
            error
        );
 
        sendError(
            res,
            500,
            'Authentication unavailable'
        );
    }
}
 
// ==========================================
// STORE ACCESS CONTROL
// ==========================================
 
function storeScope(user, alias = 'm') {
    if (
        ['ADMIN', 'AOM', 'HEAD'].includes(user.role)
    ) {
        return {
            sql: 'TRUE',
            args: []
        };
    }
 
    if (user.role === 'STORE') {
        return {
            sql: `
                LOWER(${alias}.store_email) = LOWER($1)
                AND ${alias}.store_name = $2
            `,
            args: [
                user.email,
                user.store_name
            ]
        };
    }
 
    if (user.role === 'AS') {
        return {
            sql: `
                EXISTS (
                    SELECT 1
                    FROM public.as_store_assignments a
                    JOIN public.stores s
                      ON s.store_id = a.store_id
                    WHERE LOWER(a.as_email) = LOWER($1)
                      AND s.store_name = ${alias}.store_name
                )
            `,
            args: [user.email]
        };
    }
 
    return {
        sql: 'FALSE',
        args: []
    };
}
 
// ==========================================
// MONITORING DATA QUERY
// ==========================================
 
const monitoringEntries = `
    SELECT
        m.monitoring_id,
        m.store_name,
        m.store_email,
        m.product_id,
        m.sku,
        m.product_name,
        m.supplier,
        m.store_barcode,
        m.srp,
        m.updated_at,
        m.updated_by,
        p.shelf_life,
        p.condition,
        p.remarks,
        p.master_barcode,
        v.expiration_date,
        v.quantity,
        v.slot,
        (SELECT ar.action_remarks FROM public.nems_monitoring_action_remarks ar
         WHERE ar.monitoring_id = m.monitoring_id
           AND ar.expiration_date = v.expiration_date
         LIMIT 1) AS action_remarks
 
    FROM public.monitoring m
 
    JOIN public.products p
      ON p.product_id = m.product_id
 
    CROSS JOIN LATERAL (
        SELECT legacy.expiration_date, legacy.quantity, legacy.slot
        FROM (VALUES
            (m.expiration_1, m.qty_1, 1),
            (m.expiration_2, m.qty_2, 2),
            (m.expiration_3, m.qty_3, 3)
        ) AS legacy(expiration_date, quantity, slot)
        UNION ALL
        SELECT (extra.item->>'expiration_date')::date,
               (extra.item->>'quantity')::integer,
               extra.ordinality::integer + 3
        FROM jsonb_array_elements(COALESCE(m.extra_expirations, '[]'::jsonb))
             WITH ORDINALITY AS extra(item, ordinality)
    ) AS v
 
    WHERE v.expiration_date IS NOT NULL
      AND v.quantity > 0
`;
 
// ==========================================
// EXPIRATION CATEGORY
// ==========================================
 
function expiryCategory(date) {
    const today = new Date();
    const todayUTC = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
    const expiration = new Date(date);
    const expiryUTC = Date.UTC(expiration.getUTCFullYear(), expiration.getUTCMonth(), expiration.getUTCDate());
    const days = Math.round((expiryUTC - todayUTC) / 86400000);
 
    if (days < 0) return 'EXPIRED';
    if (days <= 30) return 'RED';
    if (days <= 60) return 'BLUE';
    if (days <= 90) return 'GREEN';
 
    const sixMonths = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth() + 6, 1));
    const lastDay = new Date(Date.UTC(sixMonths.getUTCFullYear(), sixMonths.getUTCMonth() + 1, 0)).getUTCDate();
    const sixMonthLimit = Date.UTC(sixMonths.getUTCFullYear(), sixMonths.getUTCMonth(), Math.min(today.getUTCDate(), lastDay));
    return expiryUTC <= sixMonthLimit ? 'ORANGE' : 'LATER';
}
 
// ==========================================
// CURRENT USER
// ==========================================
 
app.get('/api/me', authenticate, (req, res) => {
    res.json(req.user);
});
 
// ==========================================
// GET ACTIVE SUPPLIERS
// ==========================================
 
app.get(
    '/api/suppliers',
    authenticate,
    async (req, res) => {
        try {
            const { rows } = await pool.query(`
                SELECT supplier_name
                FROM public.suppliers
                WHERE status = 'ACTIVE'
                ORDER BY supplier_name
            `);
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load suppliers'
            );
        }
    }
);
 
// ==========================================
// SEARCH ACTIVE PRODUCTS
// ==========================================
 
app.get(
    '/api/products',
    authenticate,
    async (req, res) => {
        const supplier = String(
            req.query.supplier || ''
        ).slice(0, 255);
 
        const search = String(
            req.query.search || ''
        ).trim().slice(0, 100);
 
        try {
            const { rows } = await pool.query(
                `
                SELECT
                    product_id,
                    sku,
                    product_name,
                    master_barcode,
                    master_srp,
                    supplier_name,
                    shelf_life,
                    condition,
                    remarks,
                    status
                FROM public.products
                WHERE status = 'ACTIVE'
                  AND (
                      $1 = ''
                      OR supplier_name = $1
                  )
                  AND (
                      $2 = ''
                      OR sku ILIKE '%' || $2 || '%'
                      OR product_name ILIKE '%' || $2 || '%'
                      OR master_barcode ILIKE '%' || $2 || '%'
                  )
                ORDER BY
                    product_name,
                    product_id
                LIMIT 300
                `,
                [supplier, search]
            );
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load products'
            );
        }
    }
);
 
// ==========================================
// GET ACCESSIBLE STORES
// ==========================================
 
app.get(
    '/api/stores',
    authenticate,
    async (req, res) => {
        try {
            const user = req.user;
 
            let query = `
                SELECT s.store_name
                FROM public.stores s
                WHERE s.status = 'ACTIVE'
            `;
 
            let args = [];
 
            if (user.role === 'STORE') {
                query += `
                    AND s.store_name = $1
                    AND LOWER(s.store_email) = LOWER($2)
                `;
 
                args = [
                    user.store_name,
                    user.email
                ];
 
            } else if (user.role === 'AS') {
                query += `
                    AND EXISTS (
                        SELECT 1
                        FROM public.as_store_assignments a
                        WHERE a.store_id = s.store_id
                          AND LOWER(a.as_email) = LOWER($1)
                    )
                `;
 
                args = [user.email];
            }
 
            query += ' ORDER BY s.store_name';
 
            const { rows } = await pool.query(
                query,
                args
            );
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load stores'
            );
        }
    }
);
 
// ==========================================
// GET MONITORING RECORDS
// ==========================================
 
app.get(
    '/api/monitoring',
    authenticate,
    async (req, res) => {
        try {
            const scope = storeScope(req.user);
 
            const { rows } = await pool.query(
                `
                SELECT *
                FROM (${monitoringEntries}) m
                WHERE ${scope.sql}
                ORDER BY
                    expiration_date ASC,
                    store_name
                LIMIT 10000
                `,
                scope.args
            );
 
            const records = rows.map(record => ({
                ...record,
                action_remarks: req.user.role === "ADMIN" ? record.action_remarks : undefined,
                category: expiryCategory(
                    record.expiration_date
                )
            }));
 
            res.json(records);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load monitoring'
            );
        }
    }
);
 
// ==========================================
app.put('/api/admin/monitoring/action-remarks', authenticate, adminOnly, async (req, res) => {
    const id = validId(req.body?.monitoring_id);
    const date = req.body?.expiration_date;
    const remarks = req.body?.action_remarks;
    if (!id || typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
        Number.isNaN(Date.parse(date + 'T00:00:00Z')) ||
        new Date(date + 'T00:00:00Z').toISOString().slice(0,10) !== date ||
        typeof remarks !== 'string' || remarks.length > 2000) {
        return sendError(res, 400, 'Invalid date, record, or remarks (maximum 2000 characters)');
    }
    try {
        const found = await pool.query(
            `SELECT 1 FROM (${monitoringEntries}) m
             WHERE m.monitoring_id=$1 AND m.expiration_date=$2::date LIMIT 1`, [id, date]);
        if (!found.rowCount) return sendError(res, 404, 'Monitoring entry not found');
        await pool.query(
            `INSERT INTO public.nems_monitoring_action_remarks
             (monitoring_id, expiration_date, action_remarks, updated_by)
             VALUES ($1,$2::date,$3,$4)
             ON CONFLICT (monitoring_id, expiration_date)
             DO UPDATE SET action_remarks=EXCLUDED.action_remarks,
                           updated_by=EXCLUDED.updated_by, updated_at=NOW()`,
            [id,date,remarks.trim(),req.user.email]);
        res.json({message:'Remarks saved'});
    } catch(error) { databaseError(res,error,'Could not save remarks'); }
});
 
// DASHBOARD SUMMARY
// ==========================================
 
app.get(
    '/api/dashboard',
    authenticate,
    async (req, res) => {
        try {
            const scope = storeScope(req.user);
 
            const { rows } = await pool.query(
                `
                SELECT expiration_date
                FROM (${monitoringEntries}) m
                WHERE ${scope.sql}
                `,
                scope.args
            );
 
            const counts = {
                RED: 0,
                BLUE: 0,
                GREEN: 0,
                EXPIRED: 0,
                LATER: 0
            };
 
            for (const record of rows) {
                const category = expiryCategory(
                    record.expiration_date
                );
 
                counts[category]++;
            }
 
            res.json(counts);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load dashboard'
            );
        }
    }
);
 
// ==========================================
// SAVE STORE MONITORING
// ==========================================
 
app.post(
    '/api/store/monitoring',
    authenticate,
    async (req, res) => {
        if (req.user.role !== 'STORE') {
            return sendError(
                res,
                403,
                'Only STORE accounts can encode monitoring'
            );
        }
 
        const user = req.user;
 
        const productId = Number(
            req.body.product_id
        );
 
        if (
            !Number.isSafeInteger(productId) ||
            productId <= 0
        ) {
            return sendError(
                res,
                400,
                'Invalid product'
            );
        }
 
        const rawEntries = Array.isArray(req.body.expirations)
            ? req.body.expirations
            : [1, 2, 3].map(i => ({
                expiration_date: req.body[`exp${i}`],
                quantity: req.body[`qty${i}`]
            }));
 
        if (rawEntries.length > 100) {
            return sendError(res, 400, 'Maximum 100 expiration entries per product');
        }
 
        const entries = [];
        for (let i = 0; i < rawEntries.length; i++) {
            const entry = rawEntries[i] || {};
            const date = entry.expiration_date;
            const qty = entry.quantity;
            if ((date == null || date === '') && (qty == null || qty === '')) continue;
            if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
                Number.isNaN(Date.parse(date + 'T00:00:00Z')) ||
                new Date(date + 'T00:00:00Z').toISOString().slice(0, 10) !== date) {
                return sendError(res, 400, `Invalid expiration date ${i + 1}`);
            }
            const number = Number(qty);
            if (qty == null || qty === '' || !Number.isInteger(number) || number < 0 || number > 500) {
                return sendError(res, 400, `Quantity ${i + 1} must be 0–500 pieces`);
            }
            entries.push({expiration_date: date, quantity: number});
        }
        if (!entries.length) {
            return sendError(res, 400, 'Enter at least one expiration date and quantity');
        }
        const dates = [0, 1, 2].map(i => entries[i]?.expiration_date ?? null);
        const quantities = [0, 1, 2].map(i => entries[i]?.quantity ?? null);
        const extraExpirations = JSON.stringify(entries.slice(3));
 
        const srp = (
            req.body.srp == null ||
            req.body.srp === ''
        )
            ? null
            : Number(req.body.srp);
 
        if (
            srp !== null &&
            (
                !Number.isFinite(srp) ||
                srp < 0
            )
        ) {
            return sendError(
                res,
                400,
                'Invalid retail price'
            );
        }
 
        const barcode = String(
            req.body.store_barcode || ''
        ).trim().slice(0, 150);
 
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const storeResult = await client.query(
                `
                SELECT store_name
                FROM public.stores
                WHERE LOWER(store_email) = LOWER($1)
                  AND store_name = $2
                  AND status = 'ACTIVE'
                `,
                [
                    user.email,
                    user.store_name
                ]
            );
 
            if (!storeResult.rows.length) {
                return sendError(
                    res,
                    403,
                    'Store profile does not match registered store'
                );
            }
 
            const productResult = await client.query(
                `
                SELECT
                    product_id,
                    sku,
                    product_name,
                    supplier_name,
                    master_barcode,
                    master_srp
                FROM public.products
                WHERE product_id = $1
                  AND status = 'ACTIVE'
                `,
                [productId]
            );
 
            if (!productResult.rows.length) {
                return sendError(
                    res,
                    404,
                    'Product not found'
                );
            }
 
            const product = productResult.rows[0];
 
            // Lock matching task assignments before writing monitoring.
            // This protects submitted and expired tasks even through the
            // existing Store Monitoring screen, not only the task screen.
            const taskLocks = await client.query(
                `
                SELECT a.assignment_id, a.due_at, a.status,
                       EXISTS (
                           SELECT 1
                           FROM public.nems_monitoring_submissions sub
                           WHERE sub.assignment_id = a.assignment_id
                       ) AS submitted
                FROM public.nems_task_assignments a
                JOIN public.stores s ON s.store_id = a.store_id
                JOIN public.suppliers sp ON sp.supplier_id = a.supplier_id
                WHERE LOWER(TRIM(s.store_email)) = LOWER(TRIM($1))
                  AND LOWER(TRIM(s.store_name)) = LOWER(TRIM($2))
                  AND LOWER(TRIM(sp.supplier_name)) = LOWER(TRIM($3))
                FOR UPDATE OF a
                `,
                [user.email, user.store_name, product.supplier_name]
            );
 
            for (const task of taskLocks.rows) {
                if (task.status !== 'ACTIVE' || task.submitted ||
                    (task.due_at && new Date(task.due_at).getTime() <= Date.now())) {
                    await client.query('ROLLBACK');
                    return sendError(res, 409,
                        'This supplier task is submitted, expired, or inactive. Only ADMIN can reopen it.');
                }
            }
 
            const { rows } = await client.query(
                `
                INSERT INTO public.monitoring
                (
                    store_email,
                    store_name,
                    product_id,
                    sku,
                    product_name,
                    supplier,
                    store_barcode,
                    srp,
                    expiration_1,
                    qty_1,
                    expiration_2,
                    qty_2,
                    expiration_3,
                    qty_3,
                    extra_expirations,
                    updated_at,
                    updated_by
                )
                VALUES
                (
                    $1, $2, $3, $4, $5,
                    $6, $7, $8, $9, $10,
                    $11, $12, $13, $14,
                    $16::jsonb, NOW(), $15
                )
                ON CONFLICT (store_email, product_id)
                DO UPDATE SET
                    store_barcode = EXCLUDED.store_barcode,
                    srp = EXCLUDED.srp,
                    expiration_1 = EXCLUDED.expiration_1,
                    qty_1 = EXCLUDED.qty_1,
                    expiration_2 = EXCLUDED.expiration_2,
                    qty_2 = EXCLUDED.qty_2,
                    expiration_3 = EXCLUDED.expiration_3,
                    qty_3 = EXCLUDED.qty_3,
                    extra_expirations = EXCLUDED.extra_expirations,
                    updated_at = NOW(),
                    updated_by = EXCLUDED.updated_by
                RETURNING monitoring_id
                `,
                [
                    user.email,
                    user.store_name,
                    product.product_id,
                    product.sku,
                    product.product_name,
                    product.supplier_name,
                    barcode || product.master_barcode,
                    srp === null
                        ? product.master_srp
                        : srp,
                    dates[0],
                    quantities[0],
                    dates[1],
                    quantities[1],
                    dates[2],
                    quantities[2],
                    user.email,
                    extraExpirations
                ]
            );
 
            await client.query('COMMIT');
            res.json({
                message: 'Monitoring saved',
                monitoring_id: rows[0].monitoring_id
            });
 
        } catch (error) {
            if (client) {
                try { await client.query('ROLLBACK'); } catch (_) {}
            }
            databaseError(
                res,
                error,
                'Unable to save monitoring'
            );
        } finally {
            if (client) client.release();
        }
    }
);
 
// ADMIN ONLY: dispose one expired expiration-date entry, preserving all other dates.
app.post('/api/admin/monitoring/dispose-expired', authenticate, adminOnly, async (req, res) => {
    const monitoringId = Number(req.body?.monitoring_id);
    const expirationDate = req.body?.expiration_date;
    if (!Number.isSafeInteger(monitoringId) || monitoringId <= 0 ||
        typeof expirationDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(expirationDate) ||
        Number.isNaN(Date.parse(expirationDate + 'T00:00:00Z')) ||
        new Date(expirationDate + 'T00:00:00Z').toISOString().slice(0, 10) !== expirationDate) {
        return sendError(res, 400, 'Valid monitoring ID and expiration date required');
    }
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');
        const result = await client.query(
            'SELECT * FROM public.monitoring WHERE monitoring_id = $1 FOR UPDATE', [monitoringId]
        );
        if (!result.rowCount) {
            await client.query('ROLLBACK');
            return sendError(res, 404, 'Monitoring record not found');
        }
        const m = result.rows[0];
        const asDate = v => v == null ? null :
            (v instanceof Date ? v.toISOString().slice(0, 10) : String(v).slice(0, 10));
        const entries = [1, 2, 3].map(i => ({
            expiration_date: asDate(m['expiration_' + i]),
            quantity: m['qty_' + i]
        })).filter(e => e.expiration_date !== null);
        const extras = Array.isArray(m.extra_expirations) ? m.extra_expirations : [];
        for (const e of extras) {
            if (e && e.expiration_date) entries.push({
                expiration_date: asDate(e.expiration_date), quantity: Number(e.quantity)
            });
        }
        const matching = entries.filter(e => e.expiration_date === expirationDate);
        if (!matching.length) {
            await client.query('ROLLBACK');
            return sendError(res, 404, 'Expiration date not found in monitoring');
        }
        const todayResult = await client.query('SELECT CURRENT_DATE::text AS today');
        const today = todayResult.rows[0].today;
        if (expirationDate >= today) {
            await client.query('ROLLBACK');
            return sendError(res, 409, 'Only expired stock may be disposed');
        }
        const qty = matching.reduce((sum, e) => sum + Number(e.quantity || 0), 0);
        if (!Number.isSafeInteger(qty) || qty <= 0) {
            await client.query('ROLLBACK');
            return sendError(res, 409, 'No positive expired quantity to dispose');
        }
        const remaining = entries.filter(e => e.expiration_date !== expirationDate);
        await client.query(`
            INSERT INTO public.nems_expired_disposal_history
            (monitoring_id, store_name, store_email, product_id, sku, product_name,
             supplier, expiration_date, quantity_disposed, disposed_by)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        `, [m.monitoring_id, m.store_name, m.store_email, m.product_id, m.sku,
            m.product_name, m.supplier, expirationDate, qty, req.user.email]);
        if (remaining.length === 0) {
            await client.query('DELETE FROM public.monitoring WHERE monitoring_id = $1', [monitoringId]);
        } else {
            const primary = remaining.slice(0, 3);
            const get = (i, key) => primary[i]?.[key] ?? null;
            await client.query(`
                UPDATE public.monitoring SET
                    expiration_1=$2, qty_1=$3, expiration_2=$4, qty_2=$5,
                    expiration_3=$6, qty_3=$7, extra_expirations=$8::jsonb,
                    updated_at=NOW(), updated_by=$9
                WHERE monitoring_id=$1
            `, [monitoringId, get(0,'expiration_date'), get(0,'quantity'),
                get(1,'expiration_date'), get(1,'quantity'),
                get(2,'expiration_date'), get(2,'quantity'),
                JSON.stringify(remaining.slice(3)), req.user.email]);
        }
        await client.query('COMMIT');
        return res.json({message:'Expired stock disposed', quantity_disposed:qty,
            expiration_date:expirationDate});
    } catch (error) {
        if (client) await client.query('ROLLBACK').catch(() => {});
        return databaseError(res, error, 'Unable to dispose expired stock');
    } finally {
        if (client) client.release();
    }
});
 
// ==========================================
// EXPORT MONITORING TO EXCEL
// ==========================================
 
app.get(
    '/api/export/monitoring',
    authenticate,
    async (req, res) => {
        try {
            const scope = storeScope(req.user);
            const allowedCategories = new Set(['EXPIRED', 'RED', 'BLUE', 'GREEN', 'ORANGE', 'LATER']);
            const rawCategories = req.query.category == null ? [] :
                (Array.isArray(req.query.category) ? req.query.category : [req.query.category]);
            const categories = [...new Set(rawCategories.map(value => String(value).trim().toUpperCase()))];
            if (categories.length > 6 || categories.some(value => !allowedCategories.has(value))) {
                return sendError(res, 400, 'Invalid monitoring category');
            }
            const rawSuppliers = req.query.supplier == null ? [] :
                (Array.isArray(req.query.supplier) ? req.query.supplier : [req.query.supplier]);
            if (rawSuppliers.length > 500 || rawSuppliers.some(name => typeof name !== 'string' || !name.trim() || name.length > 255)) {
                return sendError(res, 400, 'Invalid supplier selection');
            }
            const suppliers = [...new Set(rawSuppliers.map(name => name.trim()))];
            const supplierCondition = suppliers.length ?
                ` AND m.supplier = ANY($${scope.args.length + 1}::text[])` : '';
            const queryArgs = suppliers.length ? [...scope.args, suppliers] : scope.args;
 
            const { rows } = await pool.query(
                `
                SELECT *
                FROM (${monitoringEntries}) m
                WHERE ${scope.sql}${supplierCondition}
                ORDER BY
                    store_name,
                    expiration_date
                LIMIT 50000
                `,
                queryArgs
            );
 
            const filteredRows = categories.length ? rows.filter(record => categories.includes(expiryCategory(record.expiration_date))) : rows;
            const records = filteredRows.map(record => ({
                Store: record.store_name,
                Supplier: record.supplier,
                SKU: record.sku,
                Product: record.product_name,
                Barcode: record.store_barcode,
                'Retail Price': record.srp,
                'Expiration Date':
                    record.expiration_date
                        ?.toISOString?.()
                        .slice(0, 10)
                    || String(
                        record.expiration_date
                    ).slice(0, 10),
                'Quantity (Pieces)': record.quantity,
                Category: expiryCategory(
                    record.expiration_date
                ),
                'Updated By': record.updated_by,
                ...(req.user.role === 'ADMIN' ? {'ACTION / REMARKS': record.action_remarks || ''} : {})
            }));
 
            const workbook = XLSX.utils.book_new();
 
            const worksheet = XLSX.utils.json_to_sheet(
                records.length
                    ? records
                    : [{ Message: 'No monitoring records' }]
            );
 
            XLSX.utils.book_append_sheet(
                workbook,
                worksheet,
                'Monitoring'
            );
 
            const file = XLSX.write(
                workbook,
                {
                    type: 'buffer',
                    bookType: 'xlsx'
                }
            );
 
            res.set({
                'Content-Type':
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'Content-Disposition':
                    'attachment; filename="NEMS_Monitoring.xlsx"',
                'Cache-Control': 'no-store'
            });
 
            res.send(file);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Export failed'
            );
        }
    }
);
 
// ==========================================
// DISABLE OUTDATED MASTERLIST IMPORT
// ==========================================
 
app.post(
    '/api/admin/import-excel',
    authenticate,
    adminOnly,
    (req, res) => {
        return sendError(
            res,
            403,
            'Master import disabled until safe preview and validation are implemented'
        );
    }
);
 
// ==========================================
// ADMIN SUPPLIER MANAGEMENT
// ==========================================
 
// ADMIN: LIST ALL SUPPLIERS
 
app.get(
    '/api/admin/suppliers',
    authenticate,
    adminOnly,
    async (req, res) => {
        try {
            const { rows } = await pool.query(`
                SELECT
                    supplier_id,
                    supplier_name,
                    status
                FROM public.suppliers
                ORDER BY
                    supplier_name,
                    supplier_id
            `);
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load suppliers'
            );
        }
    }
);
 
// ADMIN: ADD SUPPLIER
 
app.post(
    '/api/admin/suppliers',
    authenticate,
    adminOnly,
    async (req, res) => {
        const name = requiredText(
            req.body.supplier_name
        );
 
        if (!name) {
            return sendError(
                res,
                400,
                'Valid supplier name required'
            );
        }
 
        try {
            const { rows } = await pool.query(
                `
                INSERT INTO public.suppliers (
                    supplier_name,
                    status
                )
                SELECT $1, 'ACTIVE'
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM public.suppliers
                    WHERE LOWER(TRIM(supplier_name)) =
                          LOWER(TRIM($1))
                )
                RETURNING
                    supplier_id,
                    supplier_name,
                    status
                `,
                [name]
            );
 
            if (!rows.length) {
                return sendError(
                    res,
                    409,
                    'Supplier already exists'
                );
            }
 
            res.status(201).json(rows[0]);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not add supplier'
            );
        }
    }
);
 
// ADMIN: EDIT OR DEACTIVATE SUPPLIER
 
app.patch(
    '/api/admin/suppliers/:id',
    authenticate,
    adminOnly,
    async (req, res) => {
        const id = validId(req.params.id);
 
        const name = requiredText(
            req.body.supplier_name
        );
 
        const status = req.body.status;
 
        if (
            !id ||
            !name ||
            !['ACTIVE', 'INACTIVE'].includes(status)
        ) {
            return sendError(
                res,
                400,
                'Invalid supplier information'
            );
        }
 
        try {
            const duplicate = await pool.query(
                `
                SELECT supplier_id
                FROM public.suppliers
                WHERE LOWER(TRIM(supplier_name)) =
                      LOWER(TRIM($1))
                  AND supplier_id <> $2
                LIMIT 1
                `,
                [name, id]
            );
 
            if (duplicate.rows.length) {
                return sendError(
                    res,
                    409,
                    'Supplier name already exists'
                );
            }
 
            const { rows } = await pool.query(
                `
                UPDATE public.suppliers
                SET
                    supplier_name = $1,
                    status = $2
                WHERE supplier_id = $3
                RETURNING
                    supplier_id,
                    supplier_name,
                    status
                `,
                [name, status, id]
            );
 
            if (!rows.length) {
                return sendError(
                    res,
                    404,
                    'Supplier not found'
                );
            }
 
            res.json(rows[0]);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not update supplier'
            );
        }
    }
);
 
// ==========================================
// ADMIN PRODUCT MANAGEMENT
// ==========================================
 
// ADMIN: LIST PRODUCTS INCLUDING LANDED COST
 
app.get(
    '/api/admin/products',
    authenticate,
    adminOnly,
    async (req, res) => {
        try {
            const search = String(
                req.query.search || ''
            ).trim().slice(0, 100);
 
            const { rows } = await pool.query(
                `
                SELECT
                    product_id,
                    sku,
                    product_name,
                    master_barcode,
                    master_srp,
                    supplier_name,
                    condition,
                    remarks,
                    category,
                    status,
                    shelf_life,
                    landed_cost
                FROM public.products
                WHERE
                    $1 = ''
                    OR sku ILIKE '%' || $1 || '%'
                    OR product_name ILIKE '%' || $1 || '%'
                    OR supplier_name ILIKE '%' || $1 || '%'
                    OR master_barcode ILIKE '%' || $1 || '%'
                ORDER BY product_id
                LIMIT 3000
                `,
                [search]
            );
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load products'
            );
        }
    }
);
 
// ==========================================
// PRODUCT VALIDATION
// ==========================================
 
function productInput(body) {
    const sku = requiredText(body.sku);
 
    const productName = requiredText(
        body.product_name
    );
 
    const supplierName = requiredText(
        body.supplier_name
    );
 
    const barcode = optionalText(
        body.master_barcode
    );
 
    const condition = optionalText(
        body.condition
    );
 
    const remarks = optionalText(
        body.remarks,
        10000
    );
 
    const category = optionalText(
        body.category
    );
 
    const shelfLife = optionalText(
        body.shelf_life,
        1000
    );
 
    const srp = optionalPrice(
        body.master_srp
    );
 
    const landedCost = optionalPrice(
        body.landed_cost
    );
 
    const status = body.status || 'ACTIVE';
 
    if (
        !sku ||
        !productName ||
        !supplierName ||
        barcode === undefined ||
        condition === undefined ||
        remarks === undefined ||
        category === undefined ||
        shelfLife === undefined ||
        srp === undefined ||
        landedCost === undefined ||
        !['ACTIVE', 'INACTIVE'].includes(status)
    ) {
        return null;
    }
 
    return {
        sku,
        productName,
        supplierName,
        barcode,
        condition,
        remarks,
        category,
        shelfLife,
        srp,
        landedCost,
        status
    };
}
 
function productValues(p) {
    return [
        p.sku,
        p.productName,
        p.barcode,
        p.srp,
        p.supplierName,
        p.condition,
        p.remarks,
        p.category,
        p.status,
        p.shelfLife,
        p.landedCost
    ];
}
 
// ADMIN: ADD PRODUCT
 
app.post(
    '/api/admin/products',
    authenticate,
    adminOnly,
    async (req, res) => {
        const p = productInput(req.body);
 
        if (!p) {
            return sendError(
                res,
                400,
                'Invalid product information'
            );
        }
 
        try {
            const { rows } = await pool.query(
                `
                INSERT INTO public.products (
                    sku,
                    product_name,
                    master_barcode,
                    master_srp,
                    supplier_name,
                    condition,
                    remarks,
                    category,
                    status,
                    shelf_life,
                    landed_cost
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10, $11
                )
                RETURNING
                    product_id,
                    sku,
                    product_name
                `,
                productValues(p)
            );
 
            res.status(201).json(rows[0]);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not add product'
            );
        }
    }
);
 
// ADMIN: EDIT PRODUCT BY PRODUCT ID
 
app.patch(
    '/api/admin/products/:id',
    authenticate,
    adminOnly,
    async (req, res) => {
        const id = validId(req.params.id);
 
        const p = productInput(req.body);
 
        if (!id || !p) {
            return sendError(
                res,
                400,
                'Invalid product information'
            );
        }
 
        try {
            const { rows } = await pool.query(
                `
                UPDATE public.products
                SET
                    sku = $1,
                    product_name = $2,
                    master_barcode = $3,
                    master_srp = $4,
                    supplier_name = $5,
                    condition = $6,
                    remarks = $7,
                    category = $8,
                    status = $9,
                    shelf_life = $10,
                    landed_cost = $11
                WHERE product_id = $12
                RETURNING
                    product_id,
                    sku,
                    product_name,
                    status
                `,
                [
                    ...productValues(p),
                    id
                ]
            );
 
            if (!rows.length) {
                return sendError(
                    res,
                    404,
                    'Product not found'
                );
            }
 
            res.json(rows[0]);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not update product'
            );
        }
    }
);
 
// ==========================================
// ACTIVITY HISTORY ACCESS CONTROL
// ==========================================
 
function historyScope(user) {
    if (user.role === 'ADMIN') {
        return {
            sql: 'TRUE',
            args: []
        };
    }
 
    if (user.role === 'STORE') {
        return {
            sql: `
                LOWER(h.store_email) = LOWER($1)
                AND h.store_name = $2
            `,
            args: [
                user.email,
                user.store_name
            ]
        };
    }
 
    // Other roles are not granted activity-history
    // access until their permissions are defined.
 
    return null;
}
 
function historyQueryParameters(req, scope) {
    const clauses = [scope.sql];
    const args = [...scope.args];
 
    function addCondition(value, sqlBuilder) {
        if (!value) return;
 
        args.push(value);
 
        clauses.push(
            sqlBuilder(`$${args.length}`)
        );
    }
 
    const store = String(
        req.query.store || ''
    ).trim().slice(0, 255);
 
    const supplier = String(
        req.query.supplier || ''
    ).trim().slice(0, 255);
 
    const search = String(
        req.query.search || ''
    ).trim().slice(0, 100);
 
    const action = String(
        req.query.action || ''
    ).trim().toUpperCase();
 
    const from = String(
        req.query.from || ''
    ).trim();
 
    const to = String(
        req.query.to || ''
    ).trim();
 
    addCondition(
        store,
        p => `h.store_name = ${p}`
    );
 
    addCondition(
        supplier,
        p => `h.supplier = ${p}`
    );
 
    addCondition(
        search,
        p => `(
            h.product_name ILIKE '%' || ${p} || '%'
            OR h.sku ILIKE '%' || ${p} || '%'
        )`
    );
 
    if (
        ['INSERT', 'UPDATE', 'DELETE'].includes(action)
    ) {
        addCondition(
            action,
            p => `h.action = ${p}`
        );
    }
 
    if (/^\d{4}-\d{2}-\d{2}$/.test(from)) {
        addCondition(
            from,
            p => `h.changed_at >= ${p}::date`
        );
    }
 
    if (/^\d{4}-\d{2}-\d{2}$/.test(to)) {
        addCondition(
            to,
            p => `h.changed_at < (${p}::date + INTERVAL '1 day')`
        );
    }
 
    return {
        where: clauses.join(' AND '),
        args
    };
}
 
// ==========================================
// FULL ACTIVITY HISTORY
// ==========================================
 
app.get(
    '/api/history',
    authenticate,
    async (req, res) => {
        const scope = historyScope(req.user);
 
        if (!scope) {
            return sendError(
                res,
                403,
                'History access not available for this role'
            );
        }
 
        const filters = historyQueryParameters(
            req,
            scope
        );
 
        const limit = Math.min(
            Math.max(
                parseInt(req.query.limit, 10) || 100,
                1
            ),
            500
        );
 
        const page = Math.min(
            Math.max(
                parseInt(req.query.page, 10) || 1,
                1
            ),
            100000
        );
 
        const offset = (page - 1) * limit;
 
        try {
            const countResult = await pool.query(
                `
                SELECT COUNT(*)::integer AS total
                FROM public.nems_monitoring_history h
                WHERE ${filters.where}
                `,
                filters.args
            );
 
            const dataArgs = [
                ...filters.args,
                limit,
                offset
            ];
 
            const limitIndex = dataArgs.length - 1;
            const offsetIndex = dataArgs.length;
 
            const { rows } = await pool.query(
                `
                SELECT
                    h.history_id,
                    h.monitoring_id,
                    h.store_email,
                    h.store_name,
                    h.supplier,
                    h.product_id,
                    h.sku,
                    h.product_name,
                    h.action,
                    h.changed_by,
                    h.old_values,
                    h.new_values,
                    h.changed_fields,
                    h.changed_at
                FROM public.nems_monitoring_history h
                WHERE ${filters.where}
                ORDER BY
                    h.changed_at DESC,
                    h.history_id DESC
                LIMIT $${limitIndex}
                OFFSET $${offsetIndex}
                `,
                dataArgs
            );
 
            res.json({
                records: rows,
                total: countResult.rows[0].total,
                page,
                limit
            });
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load activity history'
            );
        }
    }
);
 
// ==========================================
// RECENT DASHBOARD ACTIVITIES
// ==========================================
 
app.get(
    '/api/history/recent',
    authenticate,
    async (req, res) => {
        const scope = historyScope(req.user);
 
        if (!scope) {
            return sendError(
                res,
                403,
                'History access not available for this role'
            );
        }
 
        try {
            const { rows } = await pool.query(
                `
                SELECT
                    h.history_id,
                    h.monitoring_id,
                    h.store_name,
                    h.store_email,
                    h.supplier,
                    h.sku,
                    h.product_name,
                    h.action,
                    h.changed_by,
                    h.changed_fields,
                    h.changed_at
                FROM public.nems_monitoring_history h
                WHERE ${scope.sql}
                ORDER BY
                    h.changed_at DESC,
                    h.history_id DESC
                LIMIT 10
                `,
                scope.args
            );
 
            res.json(rows);
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Could not load recent activities'
            );
        }
    }
);
 
// ==========================================
// TASK ASSIGNMENT ROUTES
// ==========================================
// Requires nems-tasks.js in the same folder as server.js.
require('./nems-tasks')({
    app,
    pool,
    authenticate,
    adminOnly
});
 
// ADMIN USER MANAGEMENT ROUTES
require('./nems-users')({ app, pool, authenticate, adminOnly });
 
// ADMIN STORE MANAGEMENT ROUTES
require('./nems-stores')({ app, pool, authenticate, adminOnly });
 
// ==========================================
// START SERVER
// ==========================================
 
const PORT = Number(
    process.env.PORT || 3000
);
 
app.listen(
    PORT,
    '0.0.0.0',
    () => {
        console.log(
            `NEMS listening on ${PORT}`
        );
    }
);
