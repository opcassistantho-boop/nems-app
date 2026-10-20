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
    });
}
 
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
        v.slot
 
    FROM public.monitoring m
 
    JOIN public.products p
      ON p.product_id = m.product_id
 
    CROSS JOIN LATERAL (
        VALUES
            (m.expiration_1, m.qty_1, 1),
            (m.expiration_2, m.qty_2, 2),
            (m.expiration_3, m.qty_3, 3)
    ) AS v(
        expiration_date,
        quantity,
        slot
    )
 
    WHERE v.expiration_date IS NOT NULL
      AND v.quantity > 0
`;
 
// ==========================================
// EXPIRATION CATEGORY
// ==========================================
 
function expiryCategory(date) {
    const today = new Date();
 
    today.setUTCHours(0, 0, 0, 0);
 
    const days = Math.floor(
        (
            new Date(date).getTime() -
            today.getTime()
        ) / 86400000
    );
 
    if (days < 0) return 'EXPIRED';
    if (days <= 30) return 'RED';
    if (days <= 60) return 'BLUE';
    if (days <= 90) return 'GREEN';
 
    return 'LATER';
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
 
        const dates = [
            req.body.exp1,
            req.body.exp2,
            req.body.exp3
        ];
 
        const quantities = [
            req.body.qty1,
            req.body.qty2,
            req.body.qty3
        ];
 
        let hasValue = false;
 
        for (let i = 0; i < 3; i++) {
            const date = dates[i];
            const qty = quantities[i];
 
            if (
                (date == null || date === '') &&
                (qty == null || qty === '')
            ) {
                dates[i] = null;
                quantities[i] = null;
                continue;
            }
 
            if (
                typeof date !== 'string' ||
                !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
                Number.isNaN(
                    Date.parse(date + 'T00:00:00Z')
                )
            ) {
                return sendError(
                    res,
                    400,
                    `Invalid expiration date ${i + 1}`
                );
            }
 
            const number = Number(qty);
 
            if (
                !Number.isInteger(number) ||
                number < 0 ||
                number > 500
            ) {
                return sendError(
                    res,
                    400,
                    `Quantity ${i + 1} must be 0–500 pieces`
                );
            }
 
            quantities[i] = number;
            hasValue = true;
        }
 
        if (!hasValue) {
            return sendError(
                res,
                400,
                'Enter at least one expiration date and quantity'
            );
        }
 
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
 
        try {
            const storeResult = await pool.query(
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
 
            const productResult = await pool.query(
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
 
            const { rows } = await pool.query(
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
                    updated_at,
                    updated_by
                )
                VALUES
                (
                    $1, $2, $3, $4, $5,
                    $6, $7, $8, $9, $10,
                    $11, $12, $13, $14,
                    NOW(), $15
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
                    user.email
                ]
            );
 
            res.json({
                message: 'Monitoring saved',
                monitoring_id: rows[0].monitoring_id
            });
 
        } catch (error) {
            databaseError(
                res,
                error,
                'Unable to save monitoring'
            );
        }
    }
);
 
// ==========================================
// EXPORT MONITORING TO EXCEL
// ==========================================
 
app.get(
    '/api/export/monitoring',
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
                    store_name,
                    expiration_date
                LIMIT 50000
                `,
                scope.args
            );
 
            const records = rows.map(record => ({
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
                'Updated By': record.updated_by
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
