'use strict';
 
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const XLSX = require('xlsx');
const lateEncoding=require('./nems-late-encoding');
const {pageQuery:scalePageQuery,createServices}=require('./nems-scale');
 
const app = express();
 
app.disable('x-powered-by');
app.use(express.json({ limit: '6mb' }));
 
// ==========================================
// DATABASE CONNECTION
// ==========================================
 
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL_DISABLE === 'true'
        ? false
        : { rejectUnauthorized: false },
    max: Math.max(2,Math.min(20,parseInt(process.env.DB_POOL_MAX,10)||10)),
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    statement_timeout: 30000,
    application_name: 'nems-app'
});
const scaleServices=createServices(pool,{scopeSignature:async user=>user.role+':'+exportScopeKey(await accessibleStores(pool,user))});
pool.on('error',error=>console.error('[NEMS idle database connection]',error.code||error.message));
 
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
    if (error.status) return sendError(res,error.status,error.message);
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
 
// Password recovery uses Supabase Auth; always return a generic response to avoid account enumeration.
const nemsPasswordResetAttempts = new Map();
app.post('/api/password/forgot', async (req, res) => {
    const email = cleanEmail(req.body?.email);
    if (!email || email.length > 255 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return sendError(res, 400, 'Enter a valid email address');
    }
    const ip = req.ip || 'unknown';
    const key = ip + ':' + email;
    const now = Date.now();
    for (const [k,v] of nemsPasswordResetAttempts) if (now - v > 3600000) nemsPasswordResetAttempts.delete(k);
    if (nemsPasswordResetAttempts.has(key) && now - nemsPasswordResetAttempts.get(key) < 60000) {
        return res.json({message:'If registered, a reset link will be sent.'});
    }
    nemsPasswordResetAttempts.set(key, now);
    try {
        const redirectTo = (process.env.NEMS_PUBLIC_URL || 'https://nems-app.onrender.com').replace(/\/$/, '') + '/';
        const response = await fetch(`${SUPABASE_URL}/auth/v1/recover?redirect_to=${encodeURIComponent(redirectTo)}`, {
            method:'POST', headers:{apikey:SUPABASE_ANON_KEY,'Content-Type':'application/json'},
            body:JSON.stringify({email})
        });
        if (!response.ok) console.warn('Supabase password recovery request rejected:', response.status);
        return res.json({message:'If registered, a reset link will be sent.'});
    } catch(error) {
        console.error('Password recovery request error:', error.message);
        return sendError(res, 503, 'Password reset temporarily unavailable');
    }
});
 
app.post('/api/password/change', authenticate, async (req, res) => {
    const current = req.body?.current_password;
    const password = req.body?.new_password;
    if (typeof current !== 'string' || !current || typeof password !== 'string' ||
        password.length < 12 || password.length > 128 || current === password) {
        return sendError(res, 400, 'Current password required; new password must be different and 12–128 characters');
    }
    try {
        const verify = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
            method:'POST', headers:{apikey:SUPABASE_ANON_KEY,'Content-Type':'application/json'},
            body:JSON.stringify({email:req.user.email,password:current})
        });
        if (!verify.ok) return sendError(res, 401, 'Current password is incorrect');
        const verified = await verify.json();
        const bearer = /^Bearer (.+)$/i.exec(req.headers.authorization || '')?.[1];
        if (!verified.user?.id || verified.user.email?.toLowerCase() !== req.user.email.toLowerCase()) {
            return sendError(res, 401, 'Current password verification failed');
        }
        const changed = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method:'PUT', headers:{apikey:SUPABASE_ANON_KEY,Authorization:`Bearer ${bearer}`,'Content-Type':'application/json'},
            body:JSON.stringify({password})
        });
        if (!changed.ok) return sendError(res, 400, 'Unable to change password. Try again.');
        res.set('Cache-Control','no-store');
        return res.json({message:'Password changed successfully.'});
    } catch(error) {
        console.error('Password change error:', error.message);
        return sendError(res, 503, 'Password change temporarily unavailable');
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
        return await scaleServices.idempotency(req,res,next);
 
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
        ['ADMIN', 'HEAD'].includes(user.role)
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
 
    if (['AS', 'AOM'].includes(user.role)) {
        const assignmentTable = user.role === 'AS' ? 'as_store_assignments' : 'aom_store_assignments';
        const assignmentEmail = user.role === 'AS' ? 'as_email' : 'aom_email';
        return {sql:`EXISTS (SELECT 1 FROM public.${assignmentTable} scope_assignment
            JOIN public.stores scope_store ON scope_store.store_id=scope_assignment.store_id
            WHERE LOWER(scope_assignment.${assignmentEmail})=LOWER($1)
              AND scope_store.store_name=${alias}.store_name
              AND LOWER(scope_store.store_email)=LOWER(${alias}.store_email))`,args:[user.email]};
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
 
// Both Store Encoding and saved task progress are live stock sources.
// Creating an assignment alone never suppresses stock. Task submission is independent.
const taskDateInScopeSQL=(scope,date,savedAt)=>{
    const day=`(${savedAt} AT TIME ZONE 'Asia/Manila')::date`;
    return `(${scope}='BOTH' AND ${date}<=(${day}+90)
        OR ${scope}='EXPIRED' AND ${date}<${day}
        OR ${scope}='NEAR' AND ${date} BETWEEN ${day} AND (${day}+90))`;
};
const currentStockSQL = `WITH task_snapshots AS (
    SELECT pr.*,a.expiry_scope,s.store_name,s.store_email,p.sku,p.product_name,
           p.supplier_name,p.master_barcode,p.master_srp,p.shelf_life,p.condition,p.remarks
    FROM public.nems_task_product_progress pr
    JOIN public.nems_task_assignments a ON a.assignment_id=pr.assignment_id
    JOIN public.stores s ON s.store_id = a.store_id
    JOIN public.products p ON p.product_id=pr.product_id
    WHERE s.store_email IS NOT NULL AND pr.saved_at IS NOT NULL
), task_dates AS (
    SELECT ts.*,v.expiration_date,v.quantity,v.slot
    FROM task_snapshots ts CROSS JOIN LATERAL (
        SELECT x.expiration_date,x.quantity,x.slot FROM (VALUES
          (ts.expiration_1,ts.qty_1,1),(ts.expiration_2,ts.qty_2,2),(ts.expiration_3,ts.qty_3,3)
        ) x(expiration_date,quantity,slot)
        UNION ALL
        SELECT COALESCE(e.item->>'date',e.item->>'expiration_date')::date,
               COALESCE(e.item->>'qty',e.item->>'quantity')::integer,e.ordinality::integer+3
        FROM jsonb_array_elements(COALESCE(ts.extra_expirations,'[]'::jsonb)) WITH ORDINALITY e(item,ordinality)
    ) v WHERE NOT COALESCE(ts.no_stock,FALSE) AND v.expiration_date IS NOT NULL
), task_rows AS (
    SELECT DISTINCT ON (LOWER(TRIM(t.store_email)),t.product_id,t.expiration_date)
        NULL::integer AS monitoring_id,t.store_name,t.store_email,t.product_id,t.sku,t.product_name,
        t.supplier_name AS supplier,t.master_barcode AS store_barcode,t.master_srp AS srp,
        t.saved_at AS updated_at,t.saved_by AS updated_by,t.shelf_life,t.condition,t.remarks,t.master_barcode,
        t.expiration_date,t.quantity,t.slot,
        (SELECT ar.action_remarks FROM public.nems_task_action_remarks ar
          WHERE LOWER(ar.store_email)=LOWER(t.store_email) AND ar.product_id=t.product_id
          AND ar.expiration_date=t.expiration_date LIMIT 1) AS action_remarks
    FROM task_dates t WHERE t.quantity>0
      AND NOT EXISTS(SELECT 1 FROM public.monitoring m
          WHERE LOWER(TRIM(m.store_email))=LOWER(TRIM(t.store_email)) AND m.product_id=t.product_id
          AND m.updated_at>t.saved_at)
      AND NOT EXISTS(SELECT 1 FROM task_snapshots newer
          WHERE LOWER(TRIM(newer.store_email))=LOWER(TRIM(t.store_email)) AND newer.product_id=t.product_id
          AND (newer.saved_at>t.saved_at OR newer.saved_at=t.saved_at AND newer.assignment_id>t.assignment_id)
          AND (${taskDateInScopeSQL('newer.expiry_scope','t.expiration_date','newer.saved_at')}
               OR EXISTS(SELECT 1 FROM task_dates nd WHERE nd.assignment_id=newer.assignment_id
                  AND nd.product_id=newer.product_id AND nd.expiration_date=t.expiration_date)))
    ORDER BY LOWER(TRIM(t.store_email)),t.product_id,t.expiration_date,t.saved_at DESC,t.assignment_id DESC,t.slot
), combined AS (
    SELECT m.* FROM (${monitoringEntries}) m
    WHERE NOT EXISTS(SELECT 1 FROM task_snapshots ts
       WHERE LOWER(TRIM(ts.store_email))=LOWER(TRIM(m.store_email)) AND ts.product_id=m.product_id
       AND ts.saved_at>=COALESCE(m.updated_at,'-infinity'::timestamptz)
       AND (${taskDateInScopeSQL('ts.expiry_scope','m.expiration_date','ts.saved_at')}
            OR EXISTS(SELECT 1 FROM task_dates td WHERE td.assignment_id=ts.assignment_id
              AND td.product_id=ts.product_id AND td.expiration_date=m.expiration_date)))
    UNION ALL SELECT * FROM task_rows
)`;
const rawCombinedMonitoringEntries = `${currentStockSQL} SELECT * FROM combined`;
const combinedMonitoringEntries = `${currentStockSQL} SELECT * FROM combined c WHERE NOT EXISTS (
    SELECT 1 FROM public.nems_expired_archive ar WHERE LOWER(ar.store_email)=LOWER(c.store_email)
      AND ar.product_id=c.product_id AND ar.restored_at IS NULL
      AND (ar.monitoring_snapshot->>'expiration_date')::date=c.expiration_date)`;

// ==========================================
// EXPIRATION CATEGORY
// ==========================================
 
function expiryCategory(date) {
    const today = new Date(businessDate() + "T00:00:00Z");
    const todayUTC = today.getTime();
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
 
            } else if (['AS', 'AOM'].includes(user.role)) {
                const table = user.role === 'AS' ? 'as_store_assignments' : 'aom_store_assignments';
                const field = user.role === 'AS' ? 'as_email' : 'aom_email';
                query += ` AND EXISTS (SELECT 1 FROM public.${table} a
                    WHERE a.store_id=s.store_id AND LOWER(a.${field})=LOWER($1))`;
                args = [user.email];
            } else if (!['ADMIN', 'HEAD'].includes(user.role)) {
                query += ' AND FALSE';
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
                SELECT * FROM (${combinedMonitoringEntries}) m
                WHERE ${scope.sql}
                ORDER BY expiration_date ASC, store_name
                LIMIT 10000
                `,
                scope.args
            );
 
            const enrichedRows = await enrichMonitoring(pool, rows);
            const records = enrichedRows.map(record => ({
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
 
// My Tasks remarks are separate from stock and existing monitoring remarks.
app.put('/api/admin/monitoring/task-action-remarks', authenticate, adminOnly, async (req, res) => {
    const storeEmail = cleanEmail(req.body?.store_email);
    const productId = validId(req.body?.product_id);
    const date = req.body?.expiration_date;
    const remarks = req.body?.action_remarks;
    if (!storeEmail || storeEmail.length > 255 || !productId ||
        typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
        Number.isNaN(Date.parse(date + 'T00:00:00Z')) ||
        new Date(date + 'T00:00:00Z').toISOString().slice(0, 10) !== date ||
        typeof remarks !== 'string' || remarks.length > 2000) {
        return sendError(res, 400, 'Invalid task record or remarks');
    }
    try {
        const found = await pool.query(`
            SELECT 1 FROM public.nems_task_product_progress pr
            JOIN public.nems_task_assignments a ON a.assignment_id = pr.assignment_id
            JOIN public.stores s ON s.store_id = a.store_id
            CROSS JOIN LATERAL (
                SELECT x.expiration_date, x.quantity FROM (VALUES
                    (pr.expiration_1, pr.qty_1), (pr.expiration_2, pr.qty_2),
                    (pr.expiration_3, pr.qty_3)
                ) x(expiration_date, quantity)
                UNION ALL
                SELECT COALESCE(e.item->>'date', e.item->>'expiration_date')::date,
                       COALESCE(e.item->>'qty', e.item->>'quantity')::integer
                FROM jsonb_array_elements(COALESCE(pr.extra_expirations, '[]'::jsonb)) e(item)
            ) v
            WHERE LOWER(TRIM(s.store_email)) = $1 AND pr.product_id = $2
              AND v.expiration_date = $3::date AND v.quantity > 0
              AND COALESCE(pr.no_stock, FALSE) = FALSE
            LIMIT 1`, [storeEmail, productId, date]);
        if (!found.rowCount) return sendError(res, 404, 'Saved task monitoring entry not found');
        await pool.query(`
            INSERT INTO public.nems_task_action_remarks
              (store_email, product_id, expiration_date, action_remarks, updated_by)
            VALUES ($1, $2, $3::date, $4, $5)
            ON CONFLICT (store_email, product_id, expiration_date)
            DO UPDATE SET action_remarks = EXCLUDED.action_remarks,
                          updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
            [storeEmail, productId, date, remarks.trim(), req.user.email]);
        res.json({message:'Remarks saved'});
    } catch (error) { databaseError(res, error, 'Could not save task remarks'); }
});
 
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
            `SELECT 1 FROM (${combinedMonitoringEntries}) m
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
 
            const today=businessDate(),d=new Date(today+'T00:00:00Z');const endDate=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+6,1));endDate.setUTCDate(Math.min(d.getUTCDate(),new Date(Date.UTC(endDate.getUTCFullYear(),endDate.getUTCMonth()+1,0)).getUTCDate()));
            const args=[...scope.args,today,endDate.toISOString().slice(0,10)],t='$'+(args.length-1)+'::date',six='$'+args.length+'::date';
            const category=`CASE WHEN m.expiration_date<${t} THEN 'EXPIRED' WHEN m.expiration_date<=${t}+30 THEN 'RED' WHEN m.expiration_date<=${t}+60 THEN 'BLUE' WHEN m.expiration_date<=${t}+90 THEN 'GREEN' WHEN m.expiration_date<=${six} THEN 'ORANGE' ELSE 'LATER' END`;
            const {rows}=await pool.query(`SELECT ${category} AS category,COUNT(*)::int AS count FROM (${scopedMonitoringSQL(req.user)}) m WHERE ${scope.sql} GROUP BY 1`,args);
            const counts={RED:0,BLUE:0,GREEN:0,EXPIRED:0,LATER:0,ORANGE:0};for(const r of rows)counts[r.category]=r.count;
            res.json(counts);
        } catch (error) {
            databaseError(res, error, 'Could not load dashboard');
        }
    }
);
 
 
// Store remarks are shared only with users authorized for the store.
app.get('/api/store/remarks', authenticate, async (req,res) => {
    const productId = validId(req.query.product_id);
    if (!productId) return sendError(res,400,'Valid product ID required');
    try {
        const scope=storeScope(req.user,'r');
        const {rows}=await pool.query(`SELECT r.store_name,r.employee_name,r.remarks,r.source,r.created_at
            FROM public.nems_store_remarks r WHERE r.product_id=$${scope.args.length+1}
            AND ${scope.sql} ORDER BY r.created_at DESC,r.remark_id DESC LIMIT 100`,[...scope.args,productId]);
        return res.json(rows);
    } catch(e){return databaseError(res,e,'Could not load Store Remarks');}
});
 
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
        const employeeName = typeof req.body.employee_name === 'string' ? req.body.employee_name.trim() : '';
        const storeRemarks = typeof req.body.store_remarks === 'string' ? req.body.store_remarks.trim() : '';
        if (!employeeName || employeeName.length > 120 || !storeRemarks || storeRemarks.length > 2000)
            return sendError(res, 400, 'Employee full name and Store Remarks are required');
 
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
            if (qty == null || qty === '' || !Number.isInteger(number) || number < 0) {
                return sendError(res, 400, `Quantity ${i + 1} must be a nonnegative whole number`);
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
                await client.query('ROLLBACK');
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
                await client.query('ROLLBACK');
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
                SELECT a.assignment_id, COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at, a.status,
                       EXISTS (
                           SELECT 1
                           FROM public.nems_monitoring_submissions sub
                           WHERE sub.assignment_id = a.assignment_id
                             AND sub.submitted_at > COALESCE((SELECT MAX(reopened_at) FROM public.nems_task_reopen_history rh WHERE rh.assignment_id=a.assignment_id), '-infinity'::timestamptz)
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
 
            // Store Monitoring stays open; deadline locks apply only to My Task.

            await lockProduct(client, user.email, productId);
            const previous = await client.query(`SELECT m.*, xmin::text AS revision
                FROM public.monitoring m WHERE store_email=$1 AND product_id=$2 FOR UPDATE`, [user.email, productId]);
            if (!Object.hasOwn(req.body, 'expected_revision') ||
                (req.body.expected_revision ?? null) !== (previous.rows[0]?.revision ?? null)) {
                await client.query('ROLLBACK');
                return sendError(res, 409, 'Another session changed this product. Reload the product before saving. Your draft has not been saved.');
            }
            await assertDatesNotArchived(client, user.email, productId, entries.map(e => e.expiration_date));
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
                    $16::jsonb, clock_timestamp(), $15
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
                    updated_at = clock_timestamp(),
                    updated_by = EXCLUDED.updated_by
                RETURNING monitoring_id, updated_at, xmin::text AS revision
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
 
            // The trigger writes history in this transaction. Link its immutable IDs
            // directly; clock timestamps need not be equal to the trigger timestamp.
            const savedHistory = await client.query(`
                SELECT history_id FROM public.nems_monitoring_history
                WHERE monitoring_id=$1 AND xmin::text=$2
                  AND LOWER(changed_by)=LOWER($3)
                ORDER BY history_id`, [rows[0].monitoring_id, rows[0].revision, user.email]);
            const taskExclusions=lateEncoding.exclusions(taskLocks.rows,rows[0].updated_at?new Date(rows[0].updated_at).getTime():Date.now());
            await client.query(`INSERT INTO public.nems_store_remarks
                (store_name, store_email, product_id, employee_name, remarks, source, account_email, details, created_at)
                VALUES ($1,$2,$3,$4,$5,'STORE_ENCODING',$6,$7::jsonb,clock_timestamp())`,
                [user.store_name,user.email,productId,employeeName,storeRemarks,user.email,
                 JSON.stringify({expirations:entries,store_barcode:barcode,srp,before:previous.rows[0]||null,monitoring_id:rows[0].monitoring_id,revision:rows[0].revision,history_ids:savedHistory.rows.map(h=>String(h.history_id)),task_exclusions:taskExclusions})]);
            await client.query('COMMIT');
            res.json({
                message: 'Monitoring saved',
                task_warning:lateEncoding.warningText(taskExclusions),
                excluded_tasks:taskExclusions,
                monitoring_id: rows[0].monitoring_id, revision: rows[0].revision
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
 
// Existing ADMIN URLs retained; archiving never deletes or rewrites original stock.
app.post('/api/admin/monitoring/dispose-expired', authenticate, adminOnly, archiveLegacyMonitoring);
app.post('/api/admin/monitoring/dispose-task-expired', authenticate, adminOnly, archiveLegacyMonitoring);

// ==========================================
// EXPORT MONITORING TO EXCEL
// ==========================================
 
app.get('/api/export/monitoring',authenticate,secureRoute(async(req,res)=>{
    const user={...req.user},query={...req.query};
    const scope=exportScopeKey(await accessibleStores(pool,user));
    const job=scaleServices.queueExport(user,scope,async()=>({databaseExport:true,request:{user,query},monitoringSQL:scopedMonitoringSQL(user),scopes:{m:storeScope(user),ar:storeScope(user,'ar')}}));
    res.status(202).json(job);
}));
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
            'Use Products / Suppliers Import under Messages and Follow-up to preview and explicitly confirm your import'
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
                SELECT $1::text, 'ACTIVE'
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM public.suppliers
                    WHERE LOWER(TRIM(supplier_name)) =
                          LOWER(TRIM($1::text))
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
 
function historyScope(user) { return storeScope(user, 'h'); }

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
                    h.changed_at,
                    sr.employee_name,
                    sr.remarks AS store_remarks,
                    sr.account_email AS store_account_email
                FROM public.nems_monitoring_history h
                LEFT JOIN LATERAL (
                    SELECT r.employee_name, r.remarks, r.account_email, r.created_at AS remark_created_at
                    FROM public.nems_store_remarks r
                    WHERE r.product_id = h.product_id
                      AND r.store_name = h.store_name
                      AND LOWER(r.store_email) = LOWER(h.store_email)
                      AND r.source = 'STORE_ENCODING'
                      AND LOWER(r.account_email) = LOWER(h.changed_by)
                      AND r.details->>'monitoring_id' = h.monitoring_id::text
                      AND (
                        COALESCE(r.details->'history_ids','[]'::jsonb) @> jsonb_build_array(h.history_id::text)
                        OR (NOT (r.details ? 'history_ids') AND (
                            r.details->>'revision' = h.xmin::text
                            OR r.created_at = h.changed_at
                        ))
                      )
                    ORDER BY ABS(EXTRACT(EPOCH FROM (r.created_at - h.changed_at))), r.remark_id DESC
                    LIMIT 1
                ) sr ON TRUE
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
                    h.changed_at,
                    sr.employee_name,
                    sr.remarks AS store_remarks,
                    sr.account_email AS store_account_email
                FROM public.nems_monitoring_history h
                LEFT JOIN LATERAL (
                    SELECT r.employee_name, r.remarks, r.account_email, r.created_at AS remark_created_at
                    FROM public.nems_store_remarks r
                    WHERE r.product_id = h.product_id
                      AND r.store_name = h.store_name
                      AND LOWER(r.store_email) = LOWER(h.store_email)
                      AND r.source = 'STORE_ENCODING'
                      AND LOWER(r.account_email) = LOWER(h.changed_by)
                      AND r.details->>'monitoring_id' = h.monitoring_id::text
                      AND (
                        COALESCE(r.details->'history_ids','[]'::jsonb) @> jsonb_build_array(h.history_id::text)
                        OR (NOT (r.details ? 'history_ids') AND (
                            r.details->>'revision' = h.xmin::text
                            OR r.created_at = h.changed_at
                        ))
                      )
                    ORDER BY ABS(EXTRACT(EPOCH FROM (r.created_at - h.changed_at))), r.remark_id DESC
                    LIMIT 1
                ) sr ON TRUE
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
    getMonitoringStock: async (user,supplier) => {
        const scope=storeScope(user);
        return lateEncoding.enrich(pool,(await pool.query(`SELECT m.product_id,m.expiration_date,m.quantity,m.updated_at,m.monitoring_id FROM (${scopedMonitoringSQL(user)}) m WHERE ${scope.sql} AND LOWER(TRIM(m.supplier))=LOWER(TRIM($${scope.args.length+1}::text)) ORDER BY m.product_id,m.expiration_date`,[...scope.args,supplier])).rows);
    },
    app,
    pool,
    authenticate,
    adminOnly, storeScope, lockProduct, assertDatesNotArchived, businessDate, scanOverdueTasks: async()=>{}
});
 
// ADMIN USER MANAGEMENT ROUTES
require('./nems-users')({ app, pool, authenticate, adminOnly });
 
// ADMIN STORE MANAGEMENT ROUTES
require('./nems-stores')({ app, pool, authenticate, adminOnly });
 
// NEMS additions use the verified November 4 schema. No startup migrations.
function businessDate() {
    return new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Manila',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
}
function dateKey(v) { return v instanceof Date ? v.toISOString().slice(0,10) : String(v || '').slice(0,10); }
function expiryDays(v) { return Math.round((Date.parse(dateKey(v)+'T00:00:00Z')-Date.parse(businessDate()+'T00:00:00Z'))/86400000); }
function appError(status,message) { const e=new Error(message); e.status=status; return e; }
async function lockProduct(client,email,id) {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`nems-stock:${cleanEmail(email)}:${id}`]);
}
async function assertDatesNotArchived(client,email,id,dates) {
    if (!dates.length) return;
    const r=await client.query(`SELECT 1 FROM public.nems_expired_archive WHERE LOWER(store_email)=LOWER($1)
        AND product_id=$2 AND restored_at IS NULL AND monitoring_snapshot->>'expiration_date'=ANY($3::text[]) LIMIT 1`,[email,id,dates]);
    if(r.rowCount) throw appError(409,'An entered expiration date is archived. Ask ADMIN to restore it before encoding that date.');
}
async function accessibleStores(client,user) {
    const scope=storeScope(user,'s');
    return (await client.query(`SELECT s.store_id,s.store_name,s.store_email,s.status FROM public.stores s WHERE ${scope.sql} ORDER BY s.store_name`,scope.args)).rows;
}
async function requireStore(client,user,id) {
    const rows=await accessibleStores(client,user);
    const s=rows.find(s=>String(s.store_id)===String(id));
    if(!s) throw appError(403,'Store is outside your authorized assignments');
    return s;
}
async function managersForStore(client,storeId) {
    return (await client.query(`SELECT DISTINCT u.email FROM public.users u WHERE u.status='ACTIVE' AND (
        u.role IN ('ADMIN','HEAD') OR
        (u.role='AS' AND EXISTS(SELECT 1 FROM public.as_store_assignments a WHERE a.store_id=$1 AND LOWER(a.as_email)=LOWER(u.email))) OR
        (u.role='AOM' AND EXISTS(SELECT 1 FROM public.aom_store_assignments a WHERE a.store_id=$1 AND LOWER(a.aom_email)=LOWER(u.email))))`,[storeId])).rows.map(x=>x.email);
}
async function notify(client,recipient,sender,type,title,message,refType,refId,sendEmail=true) {
    const r=await client.query(`INSERT INTO public.nems_notifications
        (recipient_email,sender_email,notification_type,title,message,reference_type,reference_id)
        VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING notification_id`,[cleanEmail(recipient),sender,type,title,message,refType,refId]);
    if(sendEmail && ['EXPIRED_REPORT','VALIDATION'].includes(type))await client.query(`INSERT INTO public.nems_email_notifications(recipient_email,subject,message)
        VALUES($1,$2,$3)`,[cleanEmail(recipient),title,message]);
    return r.rows[0];
}
function secureRoute(handler) {
    return async(req,res)=>{try{await handler(req,res);}catch(e){
        if(e.status) return sendError(res,e.status,e.message);
        return databaseError(res,e,'Unable to complete this request');
    }};
}
async function transaction(fn) {
    const client=await pool.connect();
    try{await client.query('BEGIN');const value=await fn(client);await client.query('COMMIT');return value;}
    catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}
function employeeFields(body) {
    const employee=requiredText(body.employee_name,120),remarks=requiredText(body.store_remarks,2000);
    if(!employee||!remarks) throw appError(400,'Employee Full Name and Store Remarks are required');
    return {employee,remarks};
}
async function enrichMonitoring(client,rows) {
    if(!rows.length)return rows;
    const keys=rows.map((r,i)=>({i,store_email:r.store_email,product_id:r.product_id,date:dateKey(r.expiration_date),source:r.monitoring_id==null?'MY_TASKS':'STORE_ENCODING'}));
    const result=await client.query(`SELECT k.i, sr.employee_name,sr.remarks AS store_remarks,
        CASE WHEN rp.product_status IN ('DISPOSE','TRANSFER TO DC') AND rp.validation_status='APPROVED' THEN 'RESTORED / ACTIVE' ELSE rp.product_status END AS product_status,rp.validation_status,rp.validated_by,rp.validated_at,rp.validation_remarks
        FROM jsonb_to_recordset($1::jsonb) AS k(i int,store_email text,product_id int,date text,source text)
        LEFT JOIN LATERAL(SELECT r.employee_name,r.remarks FROM public.nems_store_remarks r
            WHERE LOWER(r.store_email)=LOWER(k.store_email) AND r.product_id=k.product_id AND r.source=k.source
            ORDER BY r.created_at DESC,r.remark_id DESC LIMIT 1) sr ON TRUE
        LEFT JOIN LATERAL(SELECT r.product_status,r.validation_status,r.validated_by,r.validated_at,r.validation_remarks
            FROM public.nems_expired_status_reports r WHERE LOWER(r.store_email)=LOWER(k.store_email)
            AND r.product_id=k.product_id AND r.expiration_date=k.date::date
            ORDER BY r.reported_at DESC,r.report_id DESC LIMIT 1) rp ON TRUE`,[JSON.stringify(keys)]);
    const map=new Map(result.rows.map(r=>[r.i,r]));
    return lateEncoding.enrich(client,rows.map((r,i)=>({...r,...map.get(i),days_remaining:expiryDays(r.expiration_date),days_overdue:Math.max(0,-expiryDays(r.expiration_date))})));
}

app.get('/api/products/barcode',authenticate,secureRoute(async(req,res)=>{
    const barcode=requiredText(req.query.barcode,150);
    if(!barcode)throw appError(400,'Exact barcode required');
    const result=await pool.query(`SELECT p.* FROM public.products p WHERE p.status='ACTIVE' AND
        (TRIM(p.master_barcode)=$1 OR EXISTS(SELECT 1 FROM public.nems_product_barcodes b WHERE b.product_id=p.product_id AND b.barcode=$1))
        ORDER BY p.product_id`,[barcode]);
    // Return every exact match; the interface never auto-selects an ambiguous barcode.
    res.json(result.rows);
}));
app.post('/api/admin/products/:id/barcodes',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const id=validId(req.params.id),barcode=requiredText(req.body.barcode,150);
    if(!id||!barcode)throw appError(400,'Product ID and barcode required');
    const value=await transaction(async c=>{
        await c.query('LOCK TABLE public.products, public.nems_product_barcodes IN SHARE ROW EXCLUSIVE MODE');
        const p=await c.query('SELECT 1 FROM public.products WHERE product_id=$1',[id]);
        if(!p.rowCount)throw appError(404,'Product not found');
        const conflict=await c.query(`SELECT product_id FROM public.products WHERE TRIM(master_barcode)=$1 AND product_id<>$2
            UNION ALL SELECT product_id FROM public.nems_product_barcodes WHERE barcode=$1 AND product_id<>$2`,[barcode,id]);
        if(conflict.rowCount)throw appError(409,'Barcode is registered to another product');
        return (await c.query(`INSERT INTO public.nems_product_barcodes(product_id,barcode,registered_by) VALUES($1,$2,$3)
            ON CONFLICT(barcode) DO NOTHING RETURNING *`,[id,barcode,req.user.email])).rows[0]||{product_id:id,barcode};
    });res.json(value);
}));
app.get('/api/store/monitoring/:productId',authenticate,secureRoute(async(req,res)=>{
    if(req.user.role!=='STORE')throw appError(403,'STORE access required');
    const id=validId(req.params.productId);if(!id)throw appError(400,'Invalid product ID');
    const r=await pool.query(`SELECT m.*,xmin::text AS revision FROM public.monitoring m
        WHERE m.store_email=$1 AND m.store_name=$2 AND m.product_id=$3`,[req.user.email,req.user.store_name,id]);
    const row=r.rows[0];
    if(row){
        const archived=(await pool.query(`SELECT monitoring_snapshot->>'expiration_date' AS date FROM public.nems_expired_archive
            WHERE LOWER(store_email)=LOWER($1) AND product_id=$2 AND restored_at IS NULL`,[req.user.email,id])).rows;
        const hidden=new Set(archived.map(a=>a.date));
        const dates=stockDates(row,'monitoring').filter(e=>!hidden.has(e.date));
        for(let i=1;i<=3;i++){row['expiration_'+i]=dates[i-1]?.date??null;row['qty_'+i]=dates[i-1]?.qty??null;}
        row.extra_expirations=dates.slice(3).map(e=>({expiration_date:e.date,quantity:e.qty}));
    }
    res.json(row||{revision:null});
}));
app.get('/api/history/employee-submissions',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r');
    const result=await pool.query(`SELECT r.* FROM public.nems_store_remarks r WHERE ${scope.sql}
        ORDER BY r.created_at DESC,r.remark_id DESC LIMIT 500`,scope.args);
    res.json(result.rows);
}));
app.get('/api/assigned/tasks',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'s');
    const r=await pool.query(`SELECT a.*,COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,s.store_name,s.store_email,sp.supplier_name,
        EXISTS(SELECT 1 FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id
        AND sub.submitted_at>COALESCE((SELECT MAX(reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity')) AS submitted,
        (SELECT jsonb_agg(to_jsonb(e) ORDER BY e.submitted_at DESC) FROM public.nems_task_overdue_explanations e
            WHERE e.assignment_id=a.assignment_id) AS explanations
        FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id
        JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id WHERE ${scope.sql} ORDER BY a.due_at,a.assignment_id`,scope.args);
    res.json(r.rows);
}));
app.post('/api/store/tasks/:id/explanation',authenticate,secureRoute(async(req,res)=>{
    if(req.user.role!=='STORE')throw appError(403,'STORE access required');
    const id=validId(req.params.id),employee=requiredText(req.body.employee_name,120),explanation=requiredText(req.body.explanation,5000);
    if(!id||!employee||!explanation)throw appError(400,'Task, Employee Full Name and explanation are required');
    const row=await transaction(async c=>{
        const a=(await c.query(`SELECT a.*,COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,s.store_name,s.store_email FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id
            WHERE a.assignment_id=$1 AND s.store_name=$2 AND LOWER(s.store_email)=LOWER($3) FOR UPDATE OF a`,[id,req.user.store_name,req.user.email])).rows[0];
        if(!a)throw appError(404,'Task not found');
        if(a.status!=='ACTIVE'||!a.due_at||new Date(a.due_at).getTime()>=Date.now())throw appError(409,'Task is not overdue');
        const submitted=await c.query(`SELECT 1 FROM public.nems_monitoring_submissions WHERE assignment_id=$1 AND submitted_at>
            COALESCE((SELECT MAX(reopened_at) FROM public.nems_task_reopen_history WHERE assignment_id=$1),'-infinity')`,[id]);
        if(submitted.rowCount)throw appError(409,'Current task cycle is already submitted');
        const saved=(await c.query(`INSERT INTO public.nems_task_overdue_explanations(assignment_id,store_name,store_email,employee_name,explanation)
            VALUES($1,$2,$3,$4,$5) RETURNING *`,[id,a.store_name,a.store_email,employee,explanation])).rows[0];
        for(const mail of await managersForStore(c,a.store_id)) await notify(c,mail,req.user.email,'OVERDUE_EXPLANATION','Overdue task explanation',`${a.store_name}: ${explanation}`,'TASK',id);
        return saved;
    });res.status(201).json(row);
}));

// Scoped conversations preserve the existing one-conversation-per-store model.
app.get('/api/messages/stores',authenticate,secureRoute(async(req,res)=>res.json(await accessibleStores(pool,req.user))));
// Direct recipients are active users authorized for the same store. No new schema is required.
async function messageContacts(client,storeId,senderEmail) {
    return (await client.query(`SELECT DISTINCT u.email,u.full_name,u.role FROM public.users u
        WHERE u.status='ACTIVE' AND LOWER(u.email)<>LOWER($2::text) AND (
            u.role IN ('ADMIN','HEAD') OR
            (u.role='AS' AND EXISTS(SELECT 1 FROM public.as_store_assignments a WHERE a.store_id=$1 AND LOWER(a.as_email)=LOWER(u.email))) OR
            (u.role='AOM' AND EXISTS(SELECT 1 FROM public.aom_store_assignments a WHERE a.store_id=$1 AND LOWER(a.aom_email)=LOWER(u.email))) OR
            (u.role='STORE' AND EXISTS(SELECT 1 FROM public.stores s WHERE s.store_id=$1 AND LOWER(s.store_email)=LOWER(u.email))))
        ORDER BY u.role,u.full_name,u.email`,[storeId,senderEmail])).rows;
}
// Roles of other users are visible only to ADMIN; authorization still uses real roles.
function messageRoleView(user,row,emailField='email') {
    const view={...row};
    if(user.role!=='ADMIN' && cleanEmail(row[emailField])!==cleanEmail(user.email)){
        delete view.role;
        delete view.sender_role;
    }
    return view;
}
app.get('/api/messages/contacts/:storeId',authenticate,secureRoute(async(req,res)=>{
    const store=await requireStore(pool,req.user,req.params.storeId);
    const contacts=await messageContacts(pool,store.store_id,req.user.email);
    res.json(contacts.map(row=>messageRoleView(req.user,row)).sort((a,b)=>String(a.full_name||a.email).localeCompare(String(b.full_name||b.email))));
}));
app.get('/api/messages/:storeId',authenticate,secureRoute(async(req,res)=>{
    await requireStore(pool,req.user,req.params.storeId);
    const r=await pool.query(`SELECT m.*,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('email',n.recipient_email,'read_at',n.read_at) ORDER BY n.recipient_email)
            FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id),'[]'::jsonb) AS recipients
        FROM public.nems_messages m JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id
        WHERE c.store_id=$1 AND (
            $3::boolean OR LOWER(m.sender_email)=LOWER($2::text) OR
            EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND LOWER(n.recipient_email)=LOWER($2::text)) OR
            NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND n.title LIKE 'NEMS direct message · %'))
        ORDER BY m.created_at DESC,m.message_id DESC LIMIT 500`,[req.params.storeId,req.user.email,['ADMIN','HEAD'].includes(req.user.role)]);res.json(r.rows.map(row=>messageRoleView(req.user,row,'sender_email')));
}));
app.post('/api/messages',authenticate,secureRoute(async(req,res)=>{
    const text=requiredText(req.body.message,5000);if(!text)throw appError(400,'Message required (maximum 5000 characters)');
    const result=await transaction(async c=>{
        const allowed=await accessibleStores(c,req.user);
        const ids=req.body.all===true?allowed.map(s=>String(s.store_id)):[...new Set((Array.isArray(req.body.store_ids)?req.body.store_ids:[]).map(String))];
        if(!ids.length||ids.length>1000||ids.some(id=>!allowed.some(s=>String(s.store_id)===id)))throw appError(403,'Select only authorized stores');
        const direct=Object.hasOwn(req.body,'recipient_emails');
        let directRecipients=[];
        if(direct){
            if(ids.length!==1||!Array.isArray(req.body.recipient_emails))throw appError(400,'Choose one store before selecting people');
            directRecipients=[...new Set(req.body.recipient_emails.map(cleanEmail))];
            if(!directRecipients.length||directRecipients.length>50)throw appError(400,'Select 1–50 recipients');
            const contacts=await messageContacts(c,ids[0],req.user.email);
            if(directRecipients.some(mail=>!contacts.some(u=>cleanEmail(u.email)===mail)))throw appError(403,'Select only active authorized recipients for this store');
        }
        let count=0;
        for(const id of ids){
            const store=allowed.find(s=>String(s.store_id)===id);
            const conv=(await c.query(`INSERT INTO public.nems_conversations(store_id) VALUES($1) ON CONFLICT(store_id)
                DO UPDATE SET updated_at=NOW() RETURNING conversation_id`,[id])).rows[0];
            const m=(await c.query(`INSERT INTO public.nems_messages(conversation_id,sender_email,sender_role,message_type,message_text)
                VALUES($1,$2,$3,$4,$5) RETURNING message_id`,[conv.conversation_id,req.user.email,req.user.role,ids.length>1?'ANNOUNCEMENT':'DIRECT',text])).rows[0];
            const recipients=direct?directRecipients:(req.user.role==='STORE'?await managersForStore(c,id):[store.store_email]);
            for(const mail of [...new Set(recipients.filter(Boolean).map(cleanEmail))].filter(mail=>mail!==cleanEmail(req.user.email)))
                await notify(c,mail,req.user.email,'MESSAGE',`${direct?'NEMS direct message':'NEMS message'} · ${store.store_name}`,text,'MESSAGE',m.message_id,false);
            count++;
        }return {stores:count,email_delivery:'In-app only; no email requested'};
    });res.status(201).json(result);
}));
app.post('/api/messages/:storeId/read',authenticate,secureRoute(async(req,res)=>{
    await transaction(async c=>{
        await requireStore(c,req.user,req.params.storeId);
        await c.query(`UPDATE public.nems_notifications n SET read_at=COALESCE(n.read_at,NOW())
            WHERE LOWER(n.recipient_email)=LOWER($1) AND n.reference_type='MESSAGE' AND EXISTS(
            SELECT 1 FROM public.nems_messages m JOIN public.nems_conversations cv ON cv.conversation_id=m.conversation_id
            WHERE m.message_id=n.reference_id AND cv.store_id=$2)`,[req.user.email,req.params.storeId]);
        if(req.user.role==='STORE')await c.query(`UPDATE public.nems_messages m SET read_at=COALESCE(m.read_at,NOW())
            FROM public.nems_conversations cv WHERE cv.conversation_id=m.conversation_id AND cv.store_id=$1 AND m.sender_role<>'STORE' AND (
                EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND LOWER(n.recipient_email)=LOWER($2::text)) OR
                NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND n.title LIKE 'NEMS direct message · %'))`,[req.params.storeId,req.user.email]);
    });res.json({message:'Marked read for your account'});
}));
// Notifications remain visible only while the recipient retains access to the source store.
const notificationAccess=`(
    (n.reference_type='TASK' AND EXISTS(SELECT 1 FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id WHERE a.assignment_id=n.reference_id AND SCOPE)) OR
    (n.reference_type='REPORT' AND EXISTS(SELECT 1 FROM public.nems_expired_status_reports s WHERE s.report_id=n.reference_id AND SCOPE)) OR
    (n.reference_type='MESSAGE' AND EXISTS(SELECT 1 FROM public.nems_messages m JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id JOIN public.stores s ON s.store_id=c.store_id WHERE m.message_id=n.reference_id AND SCOPE))
)`;
function notificationScope(user) {
    const s=storeScope(user,'s');return {sql:notificationAccess.replaceAll('SCOPE',s.sql),args:s.args};
}
app.get('/api/notifications',authenticate,secureRoute(async(req,res)=>{
    const scope=notificationScope(req.user),args=[...scope.args,req.user.email];
    res.json((await pool.query(`SELECT n.* FROM public.nems_notifications n WHERE ${scope.sql}
        AND LOWER(n.recipient_email)=LOWER($${args.length}) ORDER BY n.created_at DESC,n.notification_id DESC LIMIT 500`,args)).rows);
}));
app.post('/api/notifications/:id/read',authenticate,secureRoute(async(req,res)=>{
    const scope=notificationScope(req.user),args=[...scope.args,req.user.email,validId(req.params.id)];
    const r=await pool.query(`UPDATE public.nems_notifications n SET read_at=COALESCE(read_at,NOW()) WHERE ${scope.sql}
        AND LOWER(n.recipient_email)=LOWER($${args.length-1}) AND n.notification_id=$${args.length} RETURNING notification_id`,args);
    if(!r.rowCount)throw appError(404,'Notification not found');res.json({message:'Marked read'});
}));

function stockDates(row,source) {
    const entries=[];
    for(let i=1;i<=3;i++)if(row['expiration_'+i])entries.push({date:dateKey(row['expiration_'+i]),qty:Number(row['qty_'+i]||0)});
    for(const e of row.extra_expirations||[]){const date=dateKey(e.date||e.expiration_date);if(date)entries.push({date,qty:Number(e.qty??e.quantity??0)});}
    return entries;
}
async function writeRestoredDates(c,row,entries,actor,source) {
    if(entries.length>100)throw appError(409,'Restoration would exceed 100 expiry entries. Resolve active entries first.');
    const d=i=>entries[i]?.date??null,q=i=>entries[i]?.qty??null;
    if(source==='monitoring')await c.query(`UPDATE public.monitoring SET expiration_1=$2,qty_1=$3,expiration_2=$4,qty_2=$5,expiration_3=$6,qty_3=$7,
        extra_expirations=$8::jsonb,updated_at=NOW(),updated_by=$9 WHERE monitoring_id=$1`,[row.monitoring_id,d(0),q(0),d(1),q(1),d(2),q(2),JSON.stringify(entries.slice(3).map(x=>({expiration_date:x.date,quantity:x.qty}))),actor]);
    else await c.query(`UPDATE public.nems_task_product_progress SET expiration_1=$3,qty_1=$4,expiration_2=$5,qty_2=$6,expiration_3=$7,qty_3=$8,
        extra_expirations=$9::jsonb,no_stock=FALSE,saved_at=NOW(),saved_by=$10 WHERE assignment_id=$1 AND product_id=$2`,[row.assignment_id,row.product_id,d(0),q(0),d(1),q(1),d(2),q(2),JSON.stringify(entries.slice(3)),actor]);
}
async function archiveEntry(c,entry,actor,reason,reportId=null) {
    await lockProduct(c,entry.store_email,entry.product_id);
    const current=(await c.query(`SELECT * FROM (${combinedMonitoringEntries}) m WHERE LOWER(m.store_email)=LOWER($1)
        AND m.product_id=$2 AND m.expiration_date=$3::date`,[entry.store_email,entry.product_id,dateKey(entry.expiration_date)])).rows;
    if(!current.length)throw appError(409,'Stock is already archived or no longer active');
    const qty=current.reduce((n,r)=>n+Number(r.quantity),0);
    if(qty!==Number(entry.quantity))throw appError(409,'Stock quantity changed. Refresh and submit a new report.');
    const product=(await c.query('SELECT * FROM public.products WHERE product_id=$1',[entry.product_id])).rows[0];
    const original=(await c.query('SELECT * FROM public.monitoring WHERE LOWER(store_email)=LOWER($1) AND product_id=$2',[entry.store_email,entry.product_id])).rows[0]||null;
    const taskRows=(await c.query(`SELECT pr.* FROM public.nems_task_product_progress pr JOIN public.nems_task_assignments a ON a.assignment_id=pr.assignment_id
        JOIN public.stores s ON s.store_id=a.store_id WHERE LOWER(s.store_email)=LOWER($1) AND pr.product_id=$2`,[entry.store_email,entry.product_id])).rows;
    const remarks=(await c.query(`SELECT * FROM public.nems_store_remarks WHERE LOWER(store_email)=LOWER($1) AND product_id=$2 ORDER BY remark_id`,[entry.store_email,entry.product_id])).rows;
    const snap={expiration_date:dateKey(entry.expiration_date),quantity:qty,monitoring:original,task_progress:taskRows,employee_history:remarks,active_entries:current};
    const archived=(await c.query(`INSERT INTO public.nems_expired_archive(original_monitoring_id,store_name,store_email,product_id,product_snapshot,monitoring_snapshot,archive_reason,source_report_id,archived_by)
        VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9) RETURNING *`,[entry.monitoring_id||null,entry.store_name,entry.store_email,entry.product_id,JSON.stringify(product),JSON.stringify(snap),reason,reportId,actor])).rows[0];
    if(reason==='DISPOSE')await c.query(`INSERT INTO public.nems_expired_disposal_history(monitoring_id,store_name,store_email,product_id,sku,product_name,supplier,expiration_date,quantity_disposed,disposed_by)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[entry.monitoring_id||null,entry.store_name,entry.store_email,entry.product_id,product.sku,product.product_name,product.supplier_name,dateKey(entry.expiration_date),qty,actor]);
    return archived;
}
async function archiveLegacyMonitoring(req,res) {
    return secureRoute(async(req,res)=>{
        const id=validId(req.body.monitoring_id),pid=validId(req.body.product_id),date=dateKey(req.body.expiration_date);
        if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||expiryDays(date)>=0)throw appError(400,'Valid expired date required');
        const result=await transaction(async c=>{
            let email=cleanEmail(req.body.store_email),productId=pid;
            if(id){const m=(await c.query('SELECT * FROM public.monitoring WHERE monitoring_id=$1',[id])).rows[0];
                if(!m)throw appError(404,'Monitoring not found');email=m.store_email;productId=m.product_id;}
            if(!email||!productId)throw appError(400,'Store/product required');
            await lockProduct(c,email,productId);
            const rows=(await c.query(`SELECT * FROM (${combinedMonitoringEntries}) m WHERE LOWER(m.store_email)=LOWER($1) AND m.product_id=$2 AND m.expiration_date=$3::date`,[email,productId,date])).rows;
            if(!rows.length)throw appError(404,'Active expired entry not found');
            return archiveEntry(c,{...rows[0],quantity:rows.reduce((n,r)=>n+Number(r.quantity),0)},req.user.email,'ADMIN ARCHIVE');
        });res.json({message:'Permanently archived; original stock and history preserved',archive_id:result.archive_id});
    })(req,res);
}
app.get('/api/expired/reports',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r');res.json((await pool.query(`SELECT r.*,p.product_name,p.sku FROM public.nems_expired_status_reports r
        LEFT JOIN public.products p ON p.product_id=r.product_id WHERE ${scope.sql} ORDER BY r.reported_at DESC,r.report_id DESC LIMIT 1000`,scope.args)).rows);
}));
app.post('/api/expired/reports',authenticate,secureRoute(async(req,res)=>{
    if(req.user.role!=='STORE')throw appError(403,'STORE reports the action first');
    const {employee,remarks}=employeeFields(req.body),id=validId(req.body.product_id),date=dateKey(req.body.expiration_date),status=req.body.product_status;
    if(!id||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(expiryDays(date))||expiryDays(date)>=0||!['DISPOSE','TRANSFER TO DC','ON STORE'].includes(status))throw appError(400,'Select a valid expired product and action');
    if(status==='ON STORE'&&req.body.on_store_explanation_confirmed!==true)throw appError(400,'Confirm that Store Remarks explain why the expired product remains ON STORE');
    const saved=await transaction(async c=>{
        await lockProduct(c,req.user.email,id);
        const rows=(await c.query(`SELECT * FROM (${combinedMonitoringEntries}) m WHERE LOWER(m.store_email)=LOWER($1) AND m.store_name=$2 AND m.product_id=$3 AND m.expiration_date=$4::date`,[req.user.email,req.user.store_name,id,date])).rows;
        if(!rows.length)throw appError(404,'Active expired stock not found');
        const existing=await c.query(`SELECT 1 FROM public.nems_expired_status_reports WHERE LOWER(store_email)=LOWER($1) AND product_id=$2 AND expiration_date=$3::date AND validation_status='PENDING'`,[req.user.email,id,date]);
        if(existing.rowCount)throw appError(409,'An AS review is already pending for this entry');
        const qty=rows.reduce((n,r)=>n+Number(r.quantity),0);
        if(Number(req.body.quantity)!==qty)throw appError(409,'Stock changed. Refresh before reporting. Reports cover the full displayed expired quantity.');
        const r=(await c.query(`INSERT INTO public.nems_expired_status_reports(monitoring_id,store_name,store_email,product_id,expiration_date,quantity,product_status,employee_name,store_remarks,reported_by)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[rows[0].monitoring_id,req.user.store_name,req.user.email,id,date,qty,status,employee,remarks,req.user.email])).rows[0];
        const managers=await c.query(`SELECT a.as_email FROM public.as_store_assignments a JOIN public.stores s ON s.store_id=a.store_id
            JOIN public.users u ON LOWER(u.email)=LOWER(a.as_email) AND u.status='ACTIVE' AND u.role='AS' WHERE LOWER(s.store_email)=LOWER($1)`,[req.user.email]);
        for(const manager of managers.rows)await notify(c,manager.as_email,req.user.email,'EXPIRED_REPORT','Expired report awaiting AS review',`${req.user.store_name}: ${status}. ${remarks}`,'REPORT',r.report_id);
        return r;
    });res.status(201).json(saved);
}));
app.post('/api/expired/reports/:id/validate',authenticate,secureRoute(async(req,res)=>{
    if(req.user.role!=='AS')throw appError(403,'Only the assigned AS may validate a STORE report');
    const id=validId(req.params.id),decision=req.body.decision,remarks=requiredText(req.body.remarks,2000);
    if(!id||!['APPROVED','REJECTED'].includes(decision)||!remarks)throw appError(400,'APPROVED or REJECTED and validation remarks are required');
    const result=await transaction(async c=>{
        const r=(await c.query('SELECT * FROM public.nems_expired_status_reports WHERE report_id=$1 FOR UPDATE',[id])).rows[0];
        if(!r)throw appError(404,'Report not found');
        const scope=storeScope(req.user,'r');
        const auth=await c.query(`SELECT 1 FROM public.nems_expired_status_reports r WHERE r.report_id=$${scope.args.length+1} AND ${scope.sql}`,[...scope.args,id]);
        if(!auth.rowCount)throw appError(403,'Report is outside your assigned stores');
        if(r.validation_status!=='PENDING')throw appError(409,'Report was already validated');
        if(decision==='APPROVED'&&r.product_status!=='ON STORE')await archiveEntry(c,r,req.user.email,r.product_status,id);
        const updated=(await c.query(`UPDATE public.nems_expired_status_reports SET validation_status=$2,validated_by=$3,validated_at=NOW(),validation_remarks=$4 WHERE report_id=$1 RETURNING *`,[id,decision,req.user.email,remarks])).rows[0];
        await notify(c,r.store_email,req.user.email,'VALIDATION','Expired report '+decision,`${r.product_status}: ${remarks}`,'REPORT',id);
        return updated;
    });res.json(result);
}));
app.get('/api/archive',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r');res.json((await pool.query(`SELECT r.* FROM public.nems_expired_archive r WHERE ${scope.sql} ORDER BY r.archived_at DESC,r.archive_id DESC LIMIT 1000`,scope.args)).rows);
}));
app.post('/api/archive/:id/restore',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const id=validId(req.params.id),remarks=requiredText(req.body.remarks,2000);if(!id||!remarks)throw appError(400,'Archive ID and restoration remarks required');
    const saved=await transaction(async c=>{
        const ar=(await c.query('SELECT * FROM public.nems_expired_archive WHERE archive_id=$1 FOR UPDATE',[id])).rows[0];
        if(!ar)throw appError(404,'Archive not found');if(ar.restored_at)throw appError(409,'Already restored');
        await lockProduct(c,ar.store_email,ar.product_id);
        // Original rows are retained. Verify the archived date/quantity still exists; never overwrite newer stock.
        const underlying=(await c.query(`SELECT * FROM (${rawCombinedMonitoringEntries}) m WHERE LOWER(m.store_email)=LOWER($1) AND m.product_id=$2 AND m.expiration_date=$3::date`,[ar.store_email,ar.product_id,ar.monitoring_snapshot.expiration_date])).rows;
        const qty=underlying.reduce((n,r)=>n+Number(r.quantity),0);
        const expectedQty=Number(ar.monitoring_snapshot.quantity);
        if(qty!==expectedQty){
            if(qty!==0)throw appError(409,'This expiration date now has a different quantity. Restore blocked to avoid overwriting newer stock.');
            const snapshot=ar.monitoring_snapshot;
            const m=(await c.query('SELECT * FROM public.monitoring WHERE LOWER(store_email)=LOWER($1) AND product_id=$2 FOR UPDATE',[ar.store_email,ar.product_id])).rows[0];
            if(m){
                const entries=stockDates(m,'monitoring');
                entries.push({date:snapshot.expiration_date,qty:expectedQty});
                await writeRestoredDates(c,m,entries,req.user.email,'monitoring');
            }else if(snapshot.monitoring){
                const old=snapshot.monitoring;
                await c.query(`INSERT INTO public.monitoring(store_email,store_name,product_id,sku,product_name,supplier,store_barcode,srp,expiration_1,qty_1,updated_by)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[ar.store_email,ar.store_name,ar.product_id,old.sku,old.product_name,old.supplier,old.store_barcode,old.srp,snapshot.expiration_date,expectedQty,req.user.email]);
            }else{
                const source=snapshot.task_progress?.sort((a,b)=>String(b.saved_at).localeCompare(String(a.saved_at)))[0];
                if(!source)throw appError(409,'Archived task source unavailable');
                const task=(await c.query('SELECT * FROM public.nems_task_product_progress WHERE assignment_id=$1 AND product_id=$2 FOR UPDATE',[source.assignment_id,ar.product_id])).rows[0];
                if(!task)throw appError(409,'Original task source unavailable; no history was changed');
                const entries=task.no_stock?[]:stockDates(task,'task');entries.push({date:snapshot.expiration_date,qty:expectedQty});
                await writeRestoredDates(c,task,entries,req.user.email,'task');
            }
        }
        const r=(await c.query(`UPDATE public.nems_expired_archive SET restored_at=NOW(),restored_by=$2,restore_remarks=$3 WHERE archive_id=$1 RETURNING *`,[id,req.user.email,remarks])).rows[0];
        if(ar.source_report_id)await notify(c,ar.store_email,req.user.email,'RESTORED','Archived stock restored',remarks,'REPORT',ar.source_report_id);
        return r;
    });res.json(saved);
}));

// Durable, deduplicated overdue notifications. Reopened task cycles use their new deadline.
let overdueBusy=false,overdueLastRun=0;
async function scanOverdueTasks() {
    if(overdueBusy||Date.now()-overdueLastRun<60000)return;overdueBusy=true;overdueLastRun=Date.now();
    try{await transaction(async c=>{
        const acquired=await c.query("SELECT pg_try_advisory_xact_lock(hashtextextended('nems-overdue-worker',0)) AS acquired");
        if(!acquired.rows[0]?.acquired)return;
        // Set-based work avoids a query and task-row lock for every overdue assignment.
        const eligible=`SELECT DISTINCT a.assignment_id,s.store_name,s.store_email,sp.supplier_name,
            COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,LOWER(u.email) AS recipient_email
            FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id
            JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id
            CROSS JOIN LATERAL(SELECT s.store_email AS email UNION SELECT x.as_email FROM public.as_store_assignments x WHERE x.store_id=s.store_id) recipient
            JOIN public.users u ON LOWER(u.email)=LOWER(recipient.email) AND u.status='ACTIVE' AND u.role IN ('STORE','AS')
            WHERE a.status='ACTIVE' AND s.status='ACTIVE' AND COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila'))<NOW()
            AND NOT EXISTS(SELECT 1 FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id
                AND sub.submitted_at>COALESCE((SELECT MAX(reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity'::timestamptz))`;
        await c.query(`WITH eligible AS (${eligible}), prepared AS(SELECT e.*,
            'Task #'||e.assignment_id||' for '||e.store_name||' is unsubmitted after '||to_char(e.due_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')||'. Employee Full Name and an overdue explanation are required. This is not a negligence determination.' AS message FROM eligible e)
            INSERT INTO public.nems_notifications(recipient_email,sender_email,notification_type,title,message,reference_type,reference_id)
            SELECT e.recipient_email,NULL,'OVERDUE','Overdue task — explanation required',e.message,'TASK',e.assignment_id FROM prepared e
            WHERE NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE LOWER(n.recipient_email)=e.recipient_email AND n.reference_type='TASK' AND n.reference_id=e.assignment_id AND n.notification_type='OVERDUE' AND n.message=e.message)`);
        const hour=Number(new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Manila',hour:'2-digit',hourCycle:'h23'}).format(new Date()));
        if(hour>=8){
            const subject='NEMS overdue task summary · '+businessDate();
            const summaries=(await c.query(`SELECT e.recipient_email,jsonb_agg(jsonb_build_object('assignment_id',e.assignment_id,'store_name',e.store_name,'supplier_name',e.supplier_name,'due_at',e.due_at) ORDER BY e.store_name,e.assignment_id) AS tasks FROM (${eligible}) e WHERE NOT EXISTS(SELECT 1 FROM public.nems_email_notifications q WHERE LOWER(q.recipient_email)=e.recipient_email AND (q.subject LIKE 'NEMS overdue task summary · %' OR q.subject='Overdue task — explanation required') AND POSITION(('Task #'||e.assignment_id::text||' ') IN q.message)>0) AND NOT EXISTS(SELECT 1 FROM public.nems_email_notifications q WHERE LOWER(q.recipient_email)=e.recipient_email AND q.subject=$1) GROUP BY e.recipient_email`,[subject])).rows;
            if(summaries.length)await c.query(`INSERT INTO public.nems_email_notifications(recipient_email,subject,message) SELECT x.recipient_email,$2,x.message FROM jsonb_to_recordset($1::jsonb) AS x(recipient_email text,message text) WHERE NOT EXISTS(SELECT 1 FROM public.nems_email_notifications q WHERE LOWER(q.recipient_email)=x.recipient_email AND q.subject=$2)`,[JSON.stringify(summaries.map(row=>({recipient_email:row.recipient_email,message:overdueSummaryText(row.tasks)}))),subject]);
        }
    });}catch(e){console.error('[NEMS overdue worker]',e.code||e.message);}finally{overdueBusy=false;}
}
function overdueSummaryText(tasks) {
    const lines=tasks.map((a,i)=>`${i+1}. Task #${a.assignment_id} | Store: ${a.store_name}${a.supplier_name?' | Supplier: '+a.supplier_name:''} | Deadline: ${new Date(a.due_at).toLocaleString('en-GB',{timeZone:'Asia/Manila'})} (Philippine time)`);
    return `You have ${tasks.length} overdue task(s).\n\n${lines.join('\n')}\n\nOpen NEMS to complete the tasks and provide any required explanations. Responses stay inside NEMS.\nhttps://nems-app.onrender.com/`;
}
async function currentOverdueEmailTasks(user) {
    if(!['STORE','AS'].includes(user.role))return [];
    const scope=storeScope(user,'s');
    return (await pool.query(`SELECT a.*,s.store_name,sp.supplier_name,COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at
        FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id
        WHERE ${scope.sql} AND s.status='ACTIVE' AND a.status='ACTIVE'
        AND COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila'))<NOW()
        AND NOT EXISTS(SELECT 1 FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id
            AND sub.submitted_at>COALESCE((SELECT MAX(reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity'))
        ORDER BY s.store_name,a.assignment_id`,scope.args)).rows;
}
require('./nems-task-controls')({app,pool,authenticate,adminOnly,secureRoute,transaction,taskTrackerSQL,scalePageQuery,notify,accessibleStores});
const taskBatchEmails=require('./nems-task-review').register({app,pool,authenticate,adminOnly,secureRoute,accessibleStores});
const meetingReports=require('./nems-reports').registerReports({app,pool,authenticate,adminOnly,secureRoute,transaction,accessibleStores,combinedMonitoringEntries,XLSX});
// Brevo API acceptance is NOT delivery. SENT is recorded only for a verified delivery webhook.
let emailBusy=false;
async function processEmailQueue() {
    if(emailBusy||!process.env.BREVO_API_KEY||!process.env.BREVO_SENDER_EMAIL)return;
    emailBusy=true;
    try{
        for(let i=0;i<20;i++){
            const row=await transaction(async c=>{
                const r=(await c.query(`SELECT *,created_at::text AS created_at_exact FROM public.nems_email_notifications WHERE delivery_status='PENDING' AND error_message IS NULL
                    ORDER BY email_id FOR UPDATE SKIP LOCKED LIMIT 1`)).rows[0];
                if(!r)return null;
                await c.query(`UPDATE public.nems_email_notifications SET error_message=$2 WHERE email_id=$1`,[r.email_id,JSON.stringify({state:'SENDING',at:new Date().toISOString()})]);return r;
            });if(!row)break;
            try{
                // Never send chat by email, including chat queued by older deployments.
                if(/^NEMS (?:direct )?message(?:\s|[·:—-]|$)/i.test(String(row.subject||'')) || ['Overdue task explanation','Archived stock restored','Overdue task — explanation required'].includes(row.subject)){
                    await pool.query(`UPDATE public.nems_email_notifications SET delivery_status='FAILED',error_message=$2 WHERE email_id=$1 AND delivery_status='PENDING'`,
                        [row.email_id,JSON.stringify({state:'IN_APP_ONLY',reason:'Individual email suppressed; notification remains in NEMS'})]);
                    continue;
                }
                const recipient=(await pool.query(`SELECT email,role,store_name FROM public.users WHERE LOWER(email)=LOWER($1) AND status='ACTIVE'`,[row.recipient_email])).rows[0];
                if(!recipient)throw new Error('Recipient no longer has an active NEMS account');
                let meetingAttachment;
                if(String(row.subject).startsWith('NEMS new task assignments · ')){
                    row.message=await taskBatchEmails.prepareEmail(row,recipient);
                    await pool.query('UPDATE public.nems_email_notifications SET message=$2 WHERE email_id=$1',[row.email_id,row.message]);
                }else if(/^NEMS (monthly|yearly) meeting report · /.test(String(row.subject))){
                    const meeting=await meetingReports.prepareEmail(row,recipient);
                    row.message=meeting.message;meetingAttachment=meeting.attachment;
                    await pool.query('UPDATE public.nems_email_notifications SET message=$2 WHERE email_id=$1',[row.email_id,row.message]);
                }else if(String(row.subject).startsWith('NEMS overdue task summary · ')){
                    // Keep only tasks originally queued here; never add all old overdue tasks again.
                    const queuedIds=new Set([...String(row.message||'').matchAll(/Task #(\d+) \|/g)].map(m=>m[1]));
                    const earlier=(await pool.query(`SELECT message FROM public.nems_email_notifications
                        WHERE LOWER(recipient_email)=LOWER($1) AND email_id<$2
                          AND subject LIKE 'NEMS overdue task summary · %' AND delivery_status<>'FAILED'`,[row.recipient_email,row.email_id])).rows;
                    const notified=new Set(earlier.flatMap(q=>[...String(q.message||'').matchAll(/Task #(\d+) \|/g)].map(m=>m[1])));
                    const tasks=(await currentOverdueEmailTasks(recipient)).filter(t=>queuedIds.has(String(t.assignment_id))&&!notified.has(String(t.assignment_id)));
                    if(!tasks.length)throw new Error('No new authorized overdue tasks remain; duplicate reminder suppressed');
                    row.message=overdueSummaryText(tasks);
                    await pool.query('UPDATE public.nems_email_notifications SET message=$2 WHERE email_id=$1',[row.email_id,row.message]);
                }else{
                const scope=notificationScope(recipient);
                const access=await pool.query(`SELECT 1 FROM public.nems_notifications n WHERE ${scope.sql}
                    AND LOWER(n.recipient_email)=LOWER($${scope.args.length+1}) AND n.title=$${scope.args.length+2}
                    AND n.message=$${scope.args.length+3} AND n.created_at=$${scope.args.length+4}::timestamptz LIMIT 1`,
                    [...scope.args,row.recipient_email,row.subject,row.message,row.created_at_exact]);
                if(!access.rowCount)throw new Error('Recipient no longer has access to this notification');
                }
                const response=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',signal:AbortSignal.timeout(20000),headers:{'api-key':process.env.BREVO_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({sender:{email:process.env.BREVO_SENDER_EMAIL,name:process.env.BREVO_SENDER_NAME||'CARD INDOGROSIR NEMS'},to:[{email:row.recipient_email}],subject:row.subject,textContent:row.message,...(meetingAttachment?{attachment:meetingAttachment}:{}),tags:['nems-'+row.email_id]})});
                const data=await response.json().catch(()=>({}));
                if(!response.ok||!data.messageId)throw new Error('Brevo acceptance not confirmed: '+response.status);
                await pool.query(`UPDATE public.nems_email_notifications SET error_message=$2 WHERE email_id=$1 AND delivery_status='PENDING'`,[row.email_id,JSON.stringify({state:'ACCEPTED_DELIVERY_UNCONFIRMED',messageId:data.messageId})]);
            }catch(e){await pool.query(`UPDATE public.nems_email_notifications SET delivery_status='FAILED',error_message=$2 WHERE email_id=$1 AND delivery_status<>'SENT'`,[row.email_id,JSON.stringify({state:'FAILED',error:String(e.message).slice(0,1000)})]);}
        }
    }catch(e){console.error('[NEMS email worker]',e.code||e.message);}finally{emailBusy=false;}
}
app.post('/api/email/brevo-webhook',secureRoute(async(req,res)=>{
    const crypto=require('crypto'),expected=process.env.BREVO_WEBHOOK_TOKEN||'',actual=req.get('x-nems-webhook-token')||'';
    if(!expected||Buffer.byteLength(actual)!==Buffer.byteLength(expected)||!crypto.timingSafeEqual(Buffer.from(actual),Buffer.from(expected)))throw appError(401,'Invalid webhook credentials');
    const event=req.body.event,messageId=req.body['message-id']||req.body.messageId;
    const tags=Array.isArray(req.body.tags)?req.body.tags:[];
    if(typeof req.body.tag==='string')tags.push(...req.body.tag.split(/[ ,]+/));
    const tag=tags.find(x=>/^nems-\d+$/.test(String(x)));
    if(!messageId&&!tag)throw appError(400,'Provider message ID or NEMS tag required');
    if(['delivered','hard_bounce','blocked','invalid','error'].includes(event)){
        await pool.query(`UPDATE public.nems_email_notifications SET delivery_status=$3,sent_at=CASE WHEN $3='SENT' THEN COALESCE(sent_at,NOW()) ELSE sent_at END,
            error_message=$4 WHERE (POSITION(('"messageId":' || to_json($1::text)::text) IN error_message)>0 OR email_id=$2) AND delivery_status<>'SENT'`,[messageId||'',tag?tag.slice(5):null,event==='delivered'?'SENT':'FAILED',JSON.stringify({event,messageId,provider_delivery_confirmed:event==='delivered'})]);
    }res.json({received:true});
}));
app.get('/api/admin/email-status',authenticate,adminOnly,secureRoute(async(req,res)=>{
    res.json((await pool.query('SELECT * FROM public.nems_email_notifications ORDER BY email_id DESC LIMIT 200')).rows);
}));
let lastRequestCleanup=0;
async function cleanupRequestReceipts(){if(Date.now()-lastRequestCleanup<3600000)return;lastRequestCleanup=Date.now();try{await pool.query(`DELETE FROM public.nems_request_keys WHERE (owner_email,request_key) IN (SELECT owner_email,request_key FROM public.nems_request_keys WHERE state='COMPLETE' AND completed_at<NOW()-INTERVAL '30 days' LIMIT 1000)`);}catch(e){console.error('[NEMS receipt cleanup]',e.code||e.message);}}
const maintenanceTimer=setInterval(()=>{void scanOverdueTasks();void processEmailQueue();void cleanupRequestReceipts();void meetingReports.tick();},60000);
maintenanceTimer.unref();
setImmediate(()=>void meetingReports.tick());

// Separate Products/Suppliers imports: preview first, then an owner-bound one-use confirmation.
const importPreviews=new Map();
const IMPORT_FIELDS={PRODUCTS:['sku','product_name','master_barcode','master_srp','supplier_name','condition','remarks','category','status','shelf_life','landed_cost','store_task_visible'],SUPPLIERS:['supplier_name','status']};
const IMPORT_ALIASES={'product id':'product_id','supplier id':'supplier_id','product name':'product_name','short description':'product_name','description':'product_name','barcode':'master_barcode','master barcode':'master_barcode','srp':'master_srp','retail price':'master_srp','master srp':'master_srp','supplier':'supplier_name','supplier name':'supplier_name','landed cost':'landed_cost','shelf life':'shelf_life','store task visible':'store_task_visible'};
const normalizeImportHeader=v=>{const h=String(v).trim().toLowerCase().replaceAll('_',' ').replace(/\s+/g,' ');return IMPORT_ALIASES[h]||h.replaceAll(' ','_');};
function canonicalImportValue(field,value) {
    if(['master_srp','landed_cost'].includes(field)){
        if(value===null||value===undefined||value==='')return null;
        const s=String(value).trim();if(!/^\d+(\.\d{1,2})?$/.test(s)||Number(s)>9999999999.99)throw appError(400,`Invalid ${field}; use a nonnegative amount with at most two decimal places`);
        return Number(s).toFixed(2);
    }
    if(field==='store_task_visible'){
        if(typeof value==='boolean')return value;
        if(['TRUE','1','YES'].includes(String(value).toUpperCase()))return true;
        if(['FALSE','0','NO'].includes(String(value).toUpperCase()))return false;
        throw appError(400,'store_task_visible must be TRUE or FALSE');
    }
    const s=String(value??'').trim();
    const max={sku:100,product_name:255,master_barcode:100,supplier_name:255,condition:100,category:100,status:50,shelf_life:5000,remarks:10000}[field]||255;
    if(s.length>max)throw appError(400,`${field} exceeds ${max} characters`);
    if(['sku','product_name','supplier_name','status'].includes(field)&&!s)throw appError(400,`${field} is required`);
    if(field==='status'&&!['ACTIVE','INACTIVE'].includes(s.toUpperCase()))throw appError(400,'Status must be ACTIVE or INACTIVE');
    return field==='status'?s.toUpperCase():s||null;
}
function importProductIdentity(row) {
    return [row.sku,row.supplier_name,row.product_name].map(v=>String(v??'').trim().toLowerCase()).join('\u0000');
}
function importScientificBarcode(value) {
    return typeof value==='string' && /^[+-]?\d+(?:\.\d+)?[eE][+-]?\d+$/.test(value.trim());
}
function importRoundAmount(value) {
    const text=String(value).trim();
    if(!/^\d+\.\d{3,}$/.test(text))return value;
    const [whole,fraction]=text.split('.');
    let cents=BigInt(whole)*100n+BigInt(fraction.slice(0,2));
    if(Number(fraction[2])>=5)cents++;
    return (cents/100n).toString()+'.'+(cents%100n).toString().padStart(2,'0');
}
function importFingerprint(rows) {return require('crypto').createHash('sha256').update(JSON.stringify(rows)).digest('hex');}
app.post('/api/admin/import/preview',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const type=req.body.import_type,fields=IMPORT_FIELDS[type];
    if(!fields)throw appError(400,'Choose PRODUCTS or SUPPLIERS');
    const filename=requiredText(req.body.filename,255),base64=req.body.file_base64;
    if(!filename||typeof base64!=='string'||base64.length>5600000||!/^[-\w .()]+\.(xlsx|csv)$/i.test(filename))throw appError(400,'Supply an XLSX or CSV file up to 4 MB');
    const buffer=Buffer.from(base64,'base64');if(!buffer.length||buffer.length>4*1024*1024)throw appError(400,'Invalid file size');
    let workbook;try{workbook=XLSX.read(buffer,{type:'buffer',cellDates:false,raw:true,sheetRows:5002});}catch(e){throw appError(400,'Could not read this workbook');}
    if(workbook.SheetNames.length!==1)throw appError(400,'Import one worksheet at a time. Keep only the Products or Suppliers sheet in this file.');
    const cells=XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]],{header:1,defval:null,raw:true,blankrows:false});
    if(cells.length<2||cells.length>5001)throw appError(400,'Import 1–5000 data rows per file');
    const idField=type==='PRODUCTS'?'product_id':'supplier_id',table=type==='PRODUCTS'?'products':'suppliers';
    const headers=cells[0].map(normalizeImportHeader);
    if(new Set(headers).size!==headers.length)throw appError(400,'Duplicate column headers');
    const unknown=headers.filter(h=>!fields.includes(h)&&h!==idField);if(unknown.length)throw appError(400,'Unsupported columns: '+unknown.join(', '));
    const source=await pool.query(`SELECT * FROM public.${table} ORDER BY ${idField}`);
    const supplierRows=(await pool.query('SELECT * FROM public.suppliers ORDER BY supplier_id')).rows;
    const barcodes=(await pool.query('SELECT product_id,barcode FROM public.nems_product_barcodes ORDER BY barcode_id')).rows;
    const getKey=r=>type==='PRODUCTS'?`${String(r.sku).trim().toLowerCase()}\u0000${String(r.supplier_name).trim().toLowerCase()}`:String(r.supplier_name).trim().toLowerCase();
    const changes=[],seen=new Set(),seenIds=new Set(),conflicts=[],errors=[];
    const resolutions=req.body.resolutions||{};
    if(typeof resolutions!=='object'||Array.isArray(resolutions))throw appError(400,'Invalid row selections');
    for(let i=1;i<cells.length;i++){
        const supplied=Object.fromEntries(headers.map((h,j)=>[h,cells[i][j]]));
        try{
        for(const f of ['sku','master_barcode'])if(supplied[f]!==null&&supplied[f]!==undefined&&typeof supplied[f]!=='string')
            throw appError(400,`Row ${i+1}: ${f} must be stored as text in Excel to preserve leading zeroes`);
        const warnings=[];
        const scientificBarcode=type==='PRODUCTS'&&importScientificBarcode(supplied.master_barcode);
        const values={};
        for(const f of fields)if(Object.hasOwn(supplied,f)){
            if(f==='master_barcode'&&scientificBarcode)continue;
            let value=supplied[f];
            // Existing products retain their registered supplier even if this cell is blank.
            if(type==='PRODUCTS'&&f==='supplier_name'&&!String(value??'').trim())continue;
            if(['master_srp','landed_cost'].includes(f)&&value!==null&&value!==''){
                const rounded=importRoundAmount(value);
                if(String(rounded)!==String(value))warnings.push(`${f}: ${value} rounded to ${rounded} for the database's two-decimal amount field`);
                value=rounded;
            }
            values[f]=canonicalImportValue(f,value);
        }
        let current=null;
        if(supplied[idField]!==null&&supplied[idField]!==undefined&&supplied[idField]!==''){
            const id=validId(supplied[idField]);if(!id)throw appError(400,`Row ${i+1}: Invalid ${idField}`);
            current=source.rows.find(r=>Number(r[idField])===id);if(!current)throw appError(400,`Row ${i+1}: ${idField} does not exist. Leave ID blank for a new record.`);
        }else if(type==='PRODUCTS'){
            if(!values.sku)throw appError(400,`Row ${i+1}: SKU is required`);
            const norm=v=>String(v||'').trim().toLowerCase();
            const skuMatches=source.rows.filter(r=>norm(r.sku)===norm(values.sku));
            const barcode=scientificBarcode?'':String(values.master_barcode||'').trim();
            const exact=barcode?skuMatches.filter(r=>String(r.master_barcode||'').trim()===barcode||barcodes.some(b=>Number(b.product_id)===Number(r.product_id)&&String(b.barcode).trim()===barcode)):[];
            const named=skuMatches.filter(r=>norm(r.product_name)===norm(values.product_name)&&(!values.supplier_name||norm(r.supplier_name)===norm(values.supplier_name)));
            let candidates=exact.length?exact:named.length?named:skuMatches;
            const selection=resolutions[String(i+1)];
            if(selection!==undefined){
                if(selection==='NEW'){
                    if(!barcode||exact.length)throw appError(409,`Row ${i+1}: A new pack needs a unique exact barcode`);
                    warnings.push('New product/pack explicitly selected in preview.');
                }else{
                    const id=validId(selection);current=candidates.find(r=>Number(r.product_id)===id);
                    if(!current)throw appError(409,`Row ${i+1}: Invalid or stale product selection. Generate a fresh preview.`);
                    warnings.push(`Existing product #${current.product_id} explicitly selected in preview.`);
                }
            }else if(exact.length===1)current=exact[0];
            else if(!barcode&&!exact.length&&named.length===1)current=named[0];
            else if(candidates.length){
                conflicts.push({row:i+1,sku:values.sku,product_name:values.product_name,barcode:supplied.master_barcode,
                    allow_new:!!barcode&&!exact.length,
                    candidates:candidates.map(r=>({product_id:r.product_id,product_name:r.product_name,supplier_name:r.supplier_name,master_barcode:r.master_barcode,landed_cost:r.landed_cost}))});
                continue;
            }
        }else{
            if(!values.supplier_name)throw appError(400,`Row ${i+1}: Supplier name is required`);
            const matches=source.rows.filter(r=>getKey(r)===getKey(values));
            if(matches.length>1)throw appError(409,`Row ${i+1}: Multiple suppliers match. Supply the stable Supplier ID.`);
            current=matches[0]||null;
        }
        if(type==='PRODUCTS'&&current){
            if(Object.hasOwn(values,'supplier_name')&&values.supplier_name!==current.supplier_name)warnings.push(`Supplier preserved: ${current.supplier_name}. Uploaded supplier was ${values.supplier_name||'blank'}.`);
            values.supplier_name=current.supplier_name;
            // A registered alternative barcode identifies the product but must not replace its master barcode.
            if(values.master_barcode&&values.master_barcode!==current.master_barcode&&barcodes.some(b=>Number(b.product_id)===Number(current.product_id)&&b.barcode===values.master_barcode)){
                warnings.push('Registered alternative barcode matched; existing master barcode preserved.');
                delete values.master_barcode;
            }
        }
        if(current&&seenIds.has(String(current[idField])))throw appError(400,`Row ${i+1}: The same record appears twice`);
        const final={...(current||{status:'ACTIVE',master_srp:'0.00',store_task_visible:true}),...values};
        if(!final.supplier_name)throw appError(400,`Row ${i+1}: Supplier is required for a new product. Enter its exact registered supplier name.`);
        if(type==='PRODUCTS'&&(!final.sku||!final.product_name))throw appError(400,`Row ${i+1}: SKU and Product Name are required`);
        const key=type==='PRODUCTS'?importProductIdentity(final)+'\u0000'+String(final.master_barcode||'').trim():getKey(final);
        if(seen.has(key)){
            const existingIdentityRetained=type==='PRODUCTS'&&current&&importProductIdentity(current)+'\u0000'+String(current.master_barcode||'').trim()===key
                &&changes.filter(ch=>importProductIdentity(ch.after)+'\u0000'+String(ch.after.master_barcode||'').trim()===key).every(ch=>ch.before&&importProductIdentity(ch.before)+'\u0000'+String(ch.before.master_barcode||'').trim()===key);
            if(!existingIdentityRetained)throw appError(409,`Row ${i+1}: Duplicate product/pack identity in this import`);
        }
        const identityOf=r=>type==='PRODUCTS'?importProductIdentity(r)+'\u0000'+String(r.master_barcode||'').trim():getKey(r);
        const collision=source.rows.find(r=>identityOf(r)===key&&(!current||String(r[idField])!==String(current[idField])));
        // Existing duplicate identities may be maintained only through an explicit, stable ID.
        // Creating or moving another record into an already-used identity is blocked.
        if(collision&&(!current||identityOf(current)!==key))throw appError(409,`Row ${i+1}: This exact product/pack identity already belongs to another record.`);
        if(scientificBarcode){
            if(!current)throw appError(400,`Row ${i+1}: New product has a scientific-notation barcode. Supply all original barcode digits as text.`);
            warnings.push(`Barcode ${supplied.master_barcode} skipped: scientific notation cannot establish the original digits. Existing master_barcode preserved (${current.master_barcode||'blank'}).`);
        }
        if(type==='PRODUCTS'){
            if(!current&&!supplierRows.some(s=>s.supplier_name===final.supplier_name))throw appError(400,`Row ${i+1}: Supplier "${final.supplier_name}" is not registered. Add it in Suppliers, or use its exact registered name.`);
            if(!current&&!final.master_barcode)throw appError(400,`Row ${i+1}: An exact barcode is required for a new product`);
            if(final.master_barcode&&(!current||canonicalImportValue('master_barcode',current.master_barcode)!==final.master_barcode)){
                const barcode=String(final.master_barcode).trim();
                if(source.rows.some(r=>String(r.master_barcode||'').trim()===barcode&&(!current||r.product_id!==current.product_id))||barcodes.some(b=>b.barcode===barcode&&(!current||b.product_id!==current.product_id))||changes.some(ch=>ch.after.master_barcode===barcode&&(!current||ch.id!==current.product_id)))throw appError(409,`Row ${i+1}: Barcode belongs to another product`);
            }
        }
        const changed=current?fields.filter(f=>Object.hasOwn(values,f)&&canonicalImportValue(f,current[f])!==values[f]):Object.keys(values);
        const action=!current?'NEW':changed.length?'CHANGED':'UNCHANGED';
        if(current)seenIds.add(String(current[idField]));
        seen.add(key);
        changes.push({row:i+1,id:current?.[idField]||null,action,fields:current?changed:Object.keys(values),warnings,before:current,after:final});
        }catch(error){
            // Validation is read-only. Report every affected row; never issue a commit token for partial data.
            if(![400,409].includes(error.status)&&![400,409].includes(error.statusCode))throw error;
            errors.push({row:i+1,sku:String(supplied.sku??''),product_name:String(supplied.product_name??''),supplier_name:String(supplied.supplier_name??''),message:error.message});
        }
    }
    if(conflicts.length||errors.length)return res.json({requires_resolution:true,conflicts,errors,total_rows:cells.length-1,valid_rows:changes.length,
        counts:{new:changes.filter(x=>x.action==='NEW').length,changed:changes.filter(x=>x.action==='CHANGED').length,unchanged:changes.filter(x=>x.action==='UNCHANGED').length}});
    for(const [key,p] of importPreviews)if(p.expires<Date.now())importPreviews.delete(key);
    if(importPreviews.size>=20)throw appError(429,'Too many pending previews. Confirm an existing preview or wait 15 minutes.');
    const token=require('crypto').randomBytes(32).toString('hex');
    const preview={type,filename,changes,owner:req.user.email,expires:Date.now()+15*60*1000,fingerprint:importFingerprint(source.rows),supplierFingerprint:importFingerprint(supplierRows),barcodeFingerprint:importFingerprint(barcodes)};
    importPreviews.set(token,preview);
    res.json({preview_token:token,expires_at:new Date(preview.expires).toISOString(),counts:{new:changes.filter(x=>x.action==='NEW').length,changed:changes.filter(x=>x.action==='CHANGED').length,unchanged:changes.filter(x=>x.action==='UNCHANGED').length},changes});
}));
app.post('/api/admin/import/confirm',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const token=req.body.preview_token,p=importPreviews.get(token);
    if(!p||p.expires<Date.now()||p.owner!==req.user.email)throw appError(409,'Preview expired or unavailable. Generate a fresh preview.');
    if(req.body.confirm!==true)throw appError(400,'Explicit confirmation required');
    // Consume before awaiting, preventing two confirmations on this process.
    importPreviews.delete(token);
    const result=await transaction(async c=>{
        // Same lock order across Products and Suppliers imports; blocks concurrent master edits.
        await c.query('LOCK TABLE public.suppliers,public.products,public.nems_product_barcodes IN SHARE ROW EXCLUSIVE MODE');
        const table=p.type==='PRODUCTS'?'products':'suppliers',idField=p.type==='PRODUCTS'?'product_id':'supplier_id';
        const rows=(await c.query(`SELECT * FROM public.${table} ORDER BY ${idField}`)).rows;
        const suppliers=(await c.query('SELECT * FROM public.suppliers ORDER BY supplier_id')).rows;
        const barcodes=(await c.query('SELECT product_id,barcode FROM public.nems_product_barcodes ORDER BY barcode_id')).rows;
        if(importFingerprint(rows)!==p.fingerprint||importFingerprint(suppliers)!==p.supplierFingerprint||importFingerprint(barcodes)!==p.barcodeFingerprint)throw appError(409,'Master data changed after preview. Generate and review a fresh preview.');
        let added=0,updated=0,unchanged=0;
        for(const ch of p.changes){
            if(ch.action==='UNCHANGED'){unchanged++;continue;}
            const fields=ch.fields.filter(f=>IMPORT_FIELDS[p.type].includes(f));
            const args=fields.map(f=>ch.after[f]);
            if(ch.action==='NEW'){
                const r=await c.query(`INSERT INTO public.${table}(${fields.map(f=>'"'+f+'"').join(',')}) VALUES(${args.map((_,i)=>'$'+(i+1)).join(',')}) RETURNING ${idField}`,args);
                ch.id=r.rows[0][idField];added++;
            }else{
                await c.query(`UPDATE public.${table} SET ${fields.map((f,i)=>'"'+f+'"=$'+(i+1)).join(',')} WHERE ${idField}=$${args.length+1}`,[...args,ch.id]);updated++;
            }
        }
        const audit=(await c.query(`INSERT INTO public.nems_import_history(import_type,imported_by,filename,added_count,updated_count,unchanged_count,changes)
            VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) RETURNING import_id`,[p.type,req.user.email,p.filename,added,updated,unchanged,JSON.stringify(p.changes)])).rows[0];
        return {added,updated,unchanged,import_id:audit.import_id};
    });res.json(result);
}));
app.get('/api/admin/import/history',authenticate,adminOnly,secureRoute(async(req,res)=>{
    res.json((await pool.query(`SELECT import_id,import_type,imported_by,filename,added_count,updated_count,unchanged_count,confirmed_at
        FROM public.nems_import_history ORDER BY import_id DESC LIMIT 200`)).rows);
}));

// Bounded list endpoints. Authorization stays in SQL before paging or aggregation.
function expiryBounds(){const today=businessDate(),d=new Date(today+'T00:00:00Z'),six=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+6,1));six.setUTCDate(Math.min(d.getUTCDate(),new Date(Date.UTC(six.getUTCFullYear(),six.getUTCMonth()+1,0)).getUTCDate()));return [today,six.toISOString().slice(0,10)];}
function expiryCaseSQL(column,today,six){return `CASE WHEN ${column}<${today} THEN 'EXPIRED' WHEN ${column}<=${today}+30 THEN 'RED' WHEN ${column}<=${today}+60 THEN 'BLUE' WHEN ${column}<=${today}+90 THEN 'GREEN' WHEN ${column}<=${six} THEN 'ORANGE' ELSE 'LATER' END`;}
function scopedMonitoringSQL(user){
    const ms=storeScope(user,'m'),ss=storeScope(user,'s');
    return combinedMonitoringEntries.replaceAll('FROM public.monitoring m',`FROM (SELECT * FROM public.monitoring m WHERE ${ms.sql}) m`)
        .replaceAll('JOIN public.stores s ON s.store_id = a.store_id',`JOIN (SELECT * FROM public.stores s WHERE ${ss.sql}) s ON s.store_id = a.store_id`);
}
function monitoringFilters(user,query){
    const scope=storeScope(user),args=[...scope.args],clauses=[scope.sql];
    const add=(value,sql)=>{args.push(value);clauses.push(sql('$'+args.length));};
    const category=String(query.category||'').toUpperCase(),search=String(query.search||'').trim().slice(0,100);
    if(category){if(!['EXPIRED','RED','BLUE','GREEN','ORANGE','LATER'].includes(category))throw appError(400,'Invalid expiry category');
        const today=businessDate(),d=new Date(today+'T00:00:00Z');const six=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+6,1));six.setUTCDate(Math.min(d.getUTCDate(),new Date(Date.UTC(six.getUTCFullYear(),six.getUTCMonth()+1,0)).getUTCDate()));
        let t;if(category!=='LATER'){args.push(today);t='$'+args.length+'::date';}
        let end;if(category==='ORANGE'||category==='LATER'){args.push(six.toISOString().slice(0,10));end='$'+args.length+'::date';}
        clauses.push(({EXPIRED:`m.expiration_date<${t}`,RED:`m.expiration_date BETWEEN ${t} AND ${t}+30`,BLUE:`m.expiration_date BETWEEN ${t}+31 AND ${t}+60`,GREEN:`m.expiration_date BETWEEN ${t}+61 AND ${t}+90`,ORANGE:`m.expiration_date>${t}+90 AND m.expiration_date<=${end}`,LATER:`m.expiration_date>${end}`})[category]);}
    if(search)add(search,p=>`POSITION(LOWER(${p}) IN LOWER(CONCAT_WS(' ',m.store_name,m.sku,m.product_name,m.supplier)))>0`);
    return {args,where:clauses.join(' AND ')};
}
app.get('/api/scale/monitoring',authenticate,secureRoute(async(req,res)=>{
    const filters=monitoringFilters(req.user,req.query);
    const data=await scalePageQuery(pool,req.query,`SELECT m.* FROM (${scopedMonitoringSQL(req.user)}) m WHERE ${filters.where}`,filters.args,'m.expiration_date,m.store_name,m.product_id,m.slot,m.monitoring_id NULLS LAST');
    data.records=(await enrichMonitoring(pool,data.records)).map(r=>({...r,action_remarks:req.user.role==='ADMIN'?r.action_remarks:undefined,category:expiryCategory(r.expiration_date)}));res.json(data);
}));
app.get('/api/scale/expired-stock',authenticate,secureRoute(async(req,res)=>{
    if(req.user.role!=='STORE')throw appError(403,'STORE access required');
    const filters=monitoringFilters(req.user,{category:'EXPIRED',search:req.query.search});
    res.json(await scalePageQuery(pool,req.query,`SELECT m.product_id,m.product_name,m.expiration_date,SUM(m.quantity)::int AS quantity FROM (${scopedMonitoringSQL(req.user)}) m WHERE ${filters.where} GROUP BY m.product_id,m.product_name,m.expiration_date`,filters.args,'m.product_name,m.product_id,m.expiration_date'));
}));
app.get('/api/scale/export-options',authenticate,secureRoute(async(req,res)=>{
    // Supplier metadata is small. Do not download stock rows to populate checkboxes.
    res.json((await pool.query("SELECT supplier_name FROM public.suppliers ORDER BY supplier_name")).rows);
}));
function taskTrackerSQL(user,query){
    const scope=storeScope(user,'s'),args=[...scope.args],conditions=[scope.sql];
    const add=(v,sql)=>{if(v){args.push(v);conditions.push(sql('$'+args.length));}};
    add(validId(query.store),p=>`s.store_id=${p}`);add(validId(query.supplier),p=>`a.supplier_id=${p}`);
    for(const role of ['as','aom'])add(requiredText(query[role],255),p=>`EXISTS(SELECT 1 FROM public.${role}_store_assignments z WHERE z.store_id=s.store_id AND LOWER(z.${role}_email)=LOWER(${p}))`);
    const date=value=>/^\d{4}-\d{2}-\d{2}$/.test(String(value||''))?value:null;
    add(date(query.from),p=>`COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila'))>=(${p}::date::timestamp AT TIME ZONE 'Asia/Manila')`);
    add(date(query.to),p=>`COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila'))<((${p}::date+1)::timestamp AT TIME ZONE 'Asia/Manila')`);
    add(requiredText(query.search,100),p=>`POSITION(LOWER(${p}) IN LOWER(CONCAT_WS(' ',s.store_name,sp.supplier_name,a.assignment_id::text)))>0`);
    const sql=`SELECT a.assignment_id,a.store_id,s.store_name,s.store_email,sp.supplier_name,a.supplier_id,a.expiry_scope,a.status,a.assigned_at,a.assigned_by,a.due_date,
        (SELECT COUNT(*)::int FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id) AS submission_count,
        COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,
        CASE WHEN a.status='CANCELLED' THEN 'CANCELLED'
          WHEN EXISTS(SELECT 1 FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id AND sub.submitted_at>COALESCE((SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity'::timestamptz)) THEN 'SUBMITTED'
          WHEN a.status<>'ACTIVE' THEN 'CLOSED'
          WHEN COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila'))<NOW() THEN 'OVERDUE' ELSE 'PENDING' END AS display_status
        FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id WHERE ${conditions.join(' AND ')}`;
    return {sql,args};
}
app.get('/api/scale/task-tracker/options',authenticate,secureRoute(async(req,res)=>{
    const stores=await accessibleStores(pool,req.user),ids=stores.map(s=>s.store_id);
    const staff=(await pool.query(`SELECT DISTINCT u.email,u.full_name,u.role FROM public.users u WHERE u.status='ACTIVE' AND (
        (u.role='AS' AND EXISTS(SELECT 1 FROM public.as_store_assignments z WHERE LOWER(z.as_email)=LOWER(u.email) AND z.store_id=ANY($1::int[]))) OR
        (u.role='AOM' AND EXISTS(SELECT 1 FROM public.aom_store_assignments z WHERE LOWER(z.aom_email)=LOWER(u.email) AND z.store_id=ANY($1::int[])))) ORDER BY u.full_name,u.email`,[ids])).rows;
    const scope=storeScope(req.user,'s');const suppliers=(await pool.query(`SELECT DISTINCT sp.supplier_id,sp.supplier_name FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id WHERE ${scope.sql} ORDER BY sp.supplier_name`,scope.args)).rows;
    res.json({stores,suppliers,as:staff.filter(u=>u.role==='AS').map(({email,full_name})=>({email,full_name})),aom:staff.filter(u=>u.role==='AOM').map(({email,full_name})=>({email,full_name}))});
}));
app.get('/api/scale/task-tracker',authenticate,secureRoute(async(req,res)=>{
    const {sql,args}=taskTrackerSQL(req.user,req.query),status=String(req.query.status||'');
    if(status&&!['SUBMITTED','PENDING','OVERDUE','CANCELLED','CLOSED'].includes(status))throw appError(400,'Invalid task status');
    const summary=(await pool.query(`SELECT COUNT(*)::int AS assignments,COUNT(DISTINCT store_id)::int AS stores,
        COUNT(*) FILTER(WHERE display_status='SUBMITTED')::int AS submitted,COUNT(*) FILTER(WHERE display_status='PENDING')::int AS pending,
        COUNT(*) FILTER(WHERE display_status='OVERDUE')::int AS overdue,COUNT(*) FILTER(WHERE display_status IN ('CANCELLED','CLOSED'))::int AS closed FROM (${sql}) t`,args)).rows[0];
    const values=[...args];if(status)values.push(status);
    const page=await scalePageQuery(pool,req.query,`SELECT * FROM (${sql}) t${status?' WHERE t.display_status=$'+values.length:''}`,values,"CASE WHEN t.display_status IN ('PENDING','OVERDUE') THEN 0 WHEN t.display_status='SUBMITTED' THEN 1 ELSE 2 END,t.assigned_at DESC NULLS LAST,t.assignment_id DESC");res.json({...page,summary});
}));
app.get('/api/scale/notifications/count',authenticate,secureRoute(async(req,res)=>{
    const scope=notificationScope(req.user),args=[...scope.args,req.user.email];
    const r=await pool.query(`SELECT COUNT(*)::int AS unread FROM public.nems_notifications n WHERE n.read_at IS NULL AND ${scope.sql} AND LOWER(n.recipient_email)=LOWER($${args.length})`,args);res.json(r.rows[0]);
}));
// Literal, bounded search is applied inside the authorized query before pagination.
function nemsRecordSearch(query,args,fields){
    const term=String(query.search||'').trim().slice(0,100);
    if(!term)return '';
    args.push(term);return ` AND POSITION(LOWER($${args.length}::text) IN LOWER(CONCAT_WS(' ',${fields})))>0`;
}
app.get('/api/scale/email-status',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const args=[],search=nemsRecordSearch(req.query,args,'e.recipient_email,e.subject,e.delivery_status,e.error_message,e.sent_at::text');
    res.json(await scalePageQuery(pool,req.query,`SELECT e.* FROM public.nems_email_notifications e WHERE TRUE${search}`,args,'e.email_id DESC'));
}));
app.get('/api/scale/notifications',authenticate,secureRoute(async(req,res)=>{
    const scope=notificationScope(req.user),args=[...scope.args,req.user.email],recipientPosition=args.length,search=nemsRecordSearch(req.query,args,'n.title,n.message,n.created_at::text');res.json(await scalePageQuery(pool,req.query,`SELECT n.* FROM public.nems_notifications n WHERE ${scope.sql} AND LOWER(n.recipient_email)=LOWER($${recipientPosition})${search}`,args,'n.created_at DESC,n.notification_id DESC'));
}));
app.get('/api/scale/employee-history',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r'),args=[...scope.args],search=nemsRecordSearch(req.query,args,'r.store_name,r.employee_name,r.remarks,r.account_email,r.source,r.product_id::text,r.created_at::text');res.json(await scalePageQuery(pool,req.query,`SELECT r.* FROM public.nems_store_remarks r WHERE ${scope.sql}${search}`,args,'r.created_at DESC,r.remark_id DESC'));
}));
app.get('/api/scale/reports',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r'),args=[...scope.args],search=nemsRecordSearch(req.query,args,'r.store_name,p.product_name,p.sku,r.employee_name,r.store_remarks,r.validation_status,r.validation_remarks,r.product_status');res.json(await scalePageQuery(pool,req.query,`SELECT r.*,p.product_name,p.sku FROM public.nems_expired_status_reports r LEFT JOIN public.products p ON p.product_id=r.product_id WHERE ${scope.sql}${search}`,args,'r.reported_at DESC,r.report_id DESC'));
}));
app.get('/api/scale/archive',authenticate,secureRoute(async(req,res)=>{
    const scope=storeScope(req.user,'r'),args=[...scope.args],search=nemsRecordSearch(req.query,args,"r.store_name,r.product_snapshot->>'product_name',r.product_snapshot->>'sku',r.archive_reason,r.archived_at::text");res.json(await scalePageQuery(pool,req.query,`SELECT r.* FROM public.nems_expired_archive r WHERE ${scope.sql}${search}`,args,'r.archived_at DESC,r.archive_id DESC'));
}));
app.get('/api/scale/task-followup',authenticate,secureRoute(async(req,res)=>{
    const {sql,args}=taskTrackerSQL(req.user,req.query);res.json(await scalePageQuery(pool,req.query,`SELECT t.*,t.display_status='SUBMITTED' AS submitted,
      COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.submitted_at DESC) FROM (SELECT * FROM public.nems_task_overdue_explanations e WHERE e.assignment_id=t.assignment_id ORDER BY e.submitted_at DESC LIMIT 5) e),'[]'::jsonb) AS explanations FROM (${sql}) t`,args,"CASE WHEN t.display_status IN ('PENDING','OVERDUE') THEN 0 WHEN t.display_status='SUBMITTED' THEN 1 ELSE 2 END,t.assigned_at DESC NULLS LAST,t.assignment_id DESC"));
}));
app.get('/api/scale/messages/:storeId',authenticate,secureRoute(async(req,res)=>{
    await requireStore(pool,req.user,req.params.storeId);
    const args=[req.params.storeId,req.user.email,['ADMIN','HEAD'].includes(req.user.role)];
    const search=nemsRecordSearch(req.query,args,'m.sender_email,m.message_text,m.created_at::text');
    const data=await scalePageQuery(pool,req.query,`SELECT m.*,COALESCE((SELECT jsonb_agg(jsonb_build_object('email',n.recipient_email,'read_at',n.read_at) ORDER BY n.recipient_email) FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id),'[]'::jsonb) AS recipients FROM public.nems_messages m JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id WHERE c.store_id=$1 AND ($3::boolean OR LOWER(m.sender_email)=LOWER($2::text) OR EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND LOWER(n.recipient_email)=LOWER($2::text)) OR NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND n.title LIKE 'NEMS direct message · %'))${search}`,args,'m.created_at DESC,m.message_id DESC');
    if(req.user.role!=='ADMIN')data.records=data.records.map(({sender_role,...row})=>row);
    const version=require('crypto').createHash('sha256').update(JSON.stringify(data)).digest('hex');
    if(req.query.version===version)return res.json({unchanged:true,version});
    res.json({...data,version});
}));
app.post('/api/scale/messages/:storeId/read',authenticate,secureRoute(async(req,res)=>{
    const ids=Array.isArray(req.body.message_ids)?req.body.message_ids.map(validId):[];
    if(!ids.length||ids.length>100||ids.some(id=>!id))throw appError(400,'Select 1–100 visible messages');
    await requireStore(pool,req.user,req.params.storeId);
    const when=new Date().toISOString();
    await pool.query(`UPDATE public.nems_notifications n SET read_at=COALESCE(n.read_at,$4::timestamptz) WHERE LOWER(n.recipient_email)=LOWER($1) AND n.reference_type='MESSAGE' AND n.reference_id=ANY($3::bigint[]) AND EXISTS(SELECT 1 FROM public.nems_messages m JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id WHERE m.message_id=n.reference_id AND c.store_id=$2)`,[req.user.email,req.params.storeId,ids,when]);
    res.json({read_at:when});
}));
app.get('/api/help',authenticate,(req,res)=>{
    const value=String(process.env.NEMS_HELP_VIDEO_URL||'').trim();
    let video_url=null;try{const url=new URL(value);if(url.protocol==='https:')video_url=url.href;}catch(_){}
    res.json({video_url});
});
app.get('/api/admin/system-status',authenticate,adminOnly,secureRoute(async(req,res)=>{
    const ready=await pool.query("SELECT to_regclass('public.nems_request_keys') IS NOT NULL AS save_protection_ready");
    res.json({version:'nems-scale-2026-11',save_protection_ready:ready.rows[0].save_protection_ready,database_pool:{total:pool.totalCount,idle:pool.idleCount,waiting:pool.waitingCount,max:pool.options.max},export_jobs:scaleServices.stats()});
}));
function exportScopeKey(stores){return stores.map(s=>String(s.store_id)+':'+cleanEmail(s.store_email)).sort().join(',');}
app.get('/api/exports/:id',authenticate,secureRoute(async(req,res)=>{
    const j=scaleServices.getJob(req.user,req.params.id);res.json({job_id:j.id,state:j.state,error:j.error||null});
}));
app.get('/api/exports/:id/download',authenticate,secureRoute(async(req,res)=>{
    const j=scaleServices.getJob(req.user,req.params.id);
    if(j.state!=='READY')throw appError(409,'Export is not ready');
    if(exportScopeKey(await accessibleStores(pool,req.user))!==j.scope)throw appError(409,'Store access changed. Generate a fresh export.');
    res.set({'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="NEMS_Monitoring.xlsx"','Cache-Control':'no-store'});res.send(j.buffer);
}));

app.use((error,req,res,next)=>{
    if(error.type==='entity.too.large')return sendError(res,413,'Request exceeds the 6 MB limit');
    if(error instanceof SyntaxError&&error.status===400)return sendError(res,400,'Invalid JSON request');
    console.error('[NEMS request]',error.code||error.message);return sendError(res,500,'Request failed');
});
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
