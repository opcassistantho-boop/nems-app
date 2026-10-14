'use strict';

const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const XLSX = require('xlsx');

const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// DATABASE CONNECTION
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL_DISABLE === 'true'
        ? false
        : { rejectUnauthorized: false },
    max: 10
});

// SUPABASE AUTHENTICATION
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

const sendError = (res, status, message) => {
    return res.status(status).json({
        error: message
    });
};

const cleanEmail = email => {
    return String(email || '')
        .trim()
        .toLowerCase();
};

const VALID_ROLES = [
    'STORE',
    'AS',
    'AOM',
    'HEAD',
    'ADMIN'
];

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
            !result.access_token
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

        console.error('Authentication error:', error);

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

    if (days < 0) {
        return 'EXPIRED';
    }

    if (days <= 30) {
        return 'RED';
    }

    if (days <= 60) {
        return 'BLUE';
    }

    if (days <= 90) {
        return 'GREEN';
    }

    return 'LATER';
}

// ==========================================
// CURRENT USER
// ==========================================

app.get('/api/me', authenticate, (req, res) => {

    res.json(req.user);

});

// ==========================================
// GET SUPPLIERS
// ==========================================

app.get('/api/suppliers', authenticate, async (req, res) => {

    try {

        const { rows } = await pool.query(
            `
            SELECT supplier_name
            FROM public.suppliers
            WHERE status = 'ACTIVE'
            ORDER BY supplier_name
            `
        );

        res.json(rows);

    } catch (error) {

        console.error(error);

        sendError(
            res,
            500,
            'Could not load suppliers'
        );
    }
});

// ==========================================
// SEARCH PRODUCTS
// ==========================================

app.get('/api/products', authenticate, async (req, res) => {

    const supplier = String(
        req.query.supplier || ''
    );

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
            [
                supplier,
                search
            ]
        );

        res.json(rows);

    } catch (error) {

        console.error(error);

        sendError(
            res,
            500,
            'Could not load products'
        );
    }
});

// ==========================================
// GET ACCESSIBLE STORES
// ==========================================

app.get('/api/stores', authenticate, async (req, res) => {

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

        query += `
            ORDER BY s.store_name
        `;

        const { rows } = await pool.query(
            query,
            args
        );

        res.json(rows);

    } catch (error) {

        console.error(error);

        sendError(
            res,
            500,
            'Could not load stores'
        );
    }
});

// ==========================================
// GET MONITORING RECORDS
// ==========================================

app.get('/api/monitoring', authenticate, async (req, res) => {

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

        console.error(error);

        sendError(
            res,
            500,
            'Could not load monitoring'
        );
    }
});

// ==========================================
// DASHBOARD SUMMARY
// ==========================================

app.get('/api/dashboard', authenticate, async (req, res) => {

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

        console.error(error);

        sendError(
            res,
            500,
            'Could not load dashboard'
        );
    }
});

// ==========================================
// SAVE STORE MONITORING
// ==========================================

app.post('/api/store/monitoring', authenticate, async (req, res) => {

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

        // VERIFY STORE OWNERSHIP
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

        // GET PRODUCT
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

        // SAVE MONITORING
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

        console.error(error);

        sendError(
            res,
            500,
            'Unable to save monitoring'
        );
    }
});

// ==========================================
// EXPORT MONITORING TO EXCEL
// ==========================================

app.get('/api/export/monitoring', authenticate, async (req, res) => {

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

        console.error(error);

        sendError(
            res,
            500,
            'Export failed'
        );
    }
});

// ==========================================
// DISABLE OUTDATED MASTERLIST IMPORT
// ==========================================

app.post(
    '/api/admin/import-excel',
    authenticate,
    (req, res) => {

        return sendError(
            res,
            403,
            'Master import disabled until safe product_id-based import is implemented'
        );
    }
);

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
