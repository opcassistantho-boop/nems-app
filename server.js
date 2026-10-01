const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const xlsx = require('xlsx');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const upload = multer({ storage: multer.memoryStorage() });
const JWT_SECRET = process.env.JWT_SECRET || "nems_secure_secret_key_2026";

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// LOGIN
app.post('/api/login', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const lowerEmail = email.toLowerCase().trim();
    const validDomains = ['@cardindogrosir.com', '@cardmri.com'];
    if (!validDomains.some(d => lowerEmail.endsWith(d))) {
        return res.status(403).json({ error: "Domain unauthorized. Must use @cardindogrosir.com or @cardmri.com" });
    }

    try {
        const { rows } = await pool.query("SELECT * FROM users WHERE LOWER(email) = $1 AND status = 'ACTIVE'", [lowerEmail]);
        if (rows.length === 0) {
            return res.status(403).json({ error: "User account not active or not registered in USERS list" });
        }
        const user = rows[0];
        const token = jwt.sign({ email: user.email, role: user.role, store_name: user.store_name }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// AUTH MIDDLEWARE
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access token required" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid session token" });
    }
};

// GET SUPPLIERS
app.get('/api/suppliers', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM suppliers WHERE status = 'ACTIVE' ORDER BY supplier_name");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET PRODUCTS BY SUPPLIER
app.get('/api/products', authenticateToken, async (req, res) => {
    const { supplier } = req.query;
    try {
        let query = "SELECT * FROM products WHERE status = 'ACTIVE'";
        let values = [];
        if (supplier) {
            query += " AND supplier_name = $1";
            values.push(supplier);
        }
        query += " ORDER BY product_name";
        const { rows } = await pool.query(query, values);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SAVE MONITORING RECORD
app.post('/api/store/monitoring', authenticateToken, async (req, res) => {
    const { product_id, store_barcode, srp, exp1, qty1, exp2, qty2, exp3, qty3 } = req.body;
    const store_email = req.user.email;
    const store_name = req.user.store_name;

    try {
        const prodRes = await pool.query("SELECT * FROM products WHERE product_id = $1", [product_id]);
        if (prodRes.rows.length === 0) return res.status(404).json({ error: "Product not found" });
        const prod = prodRes.rows[0];

        const query = `
            INSERT INTO monitoring 
            (store_email, store_name, product_id, sku, product_name, supplier, store_barcode, srp, 
             expiration_1, qty_1, expiration_2, qty_2, expiration_3, qty_3, updated_at, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW(), $15)
            ON CONFLICT (store_email, product_id) DO UPDATE SET
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
            RETURNING *;
        `;

        const values = [
            store_email, store_name, product_id, prod.sku, prod.product_name, prod.supplier_name,
            store_barcode || prod.master_barcode, srp || prod.master_srp,
            exp1, qty1, exp2 || null, qty2 || null, exp3 || null, qty3 || null,
            store_email
        ];

        const { rows } = await pool.query(query, values);
        res.json({ message: "Record saved successfully", data: rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// MASTER DATA EXCEL IMPORT
app.post('/api/admin/import-excel', authenticateToken, upload.single('file'), async (req, res) => {
    if (req.user.role !== 'ADMIN') return res.status(403).json({ error: "Admin access required" });
    if (!req.file) return res.status(400).json({ error: "No Excel file uploaded" });

    try {
        const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
        
        // USERS SHEET
        if (workbook.Sheets['USERS']) {
            const usersData = xlsx.utils.sheet_to_json(workbook.Sheets['USERS']);
            for (let u of usersData) {
                if (u.EMAIL && u.STORE_NAME) {
                    await pool.query(`
                        INSERT INTO users (email, store_name, role, status)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (email) DO UPDATE SET store_name = EXCLUDED.store_name, role = EXCLUDED.role, status = EXCLUDED.status
                    `, [String(u.EMAIL).trim().toLowerCase(), String(u.STORE_NAME).trim(), String(u.ROLE || 'STORE').trim(), String(u.STATUS || 'ACTIVE').trim()]);
                }
            }
        }

        // SUPPLIERS SHEET
        if (workbook.Sheets['SUPPLIERS']) {
            const suppliersData = xlsx.utils.sheet_to_json(workbook.Sheets['SUPPLIERS']);
            for (let s of suppliersData) {
                if (s.SUPPLIER_NAME) {
                    await pool.query(`
                        INSERT INTO suppliers (supplier_name, status)
                        VALUES ($1, $2)
                        ON CONFLICT (supplier_name) DO UPDATE SET status = EXCLUDED.status
                    `, [String(s.SUPPLIER_NAME).trim(), String(s.STATUS || 'ACTIVE').trim()]);
                }
            }
        }

        // PRODUCTS SHEET
        if (workbook.Sheets['PRODUCTS']) {
            const productsData = xlsx.utils.sheet_to_json(workbook.Sheets['PRODUCTS']);
            for (let p of productsData) {
                if (p.SKU && p.SUPPLIER) {
                    await pool.query(`
                        INSERT INTO products (sku, product_name, master_barcode, master_srp, supplier_name, condition, remarks, category, status)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        ON CONFLICT (sku, supplier_name) DO UPDATE SET
                            product_name = EXCLUDED.product_name,
                            master_barcode = EXCLUDED.master_barcode,
                            master_srp = EXCLUDED.master_srp,
                            condition = EXCLUDED.condition,
                            remarks = EXCLUDED.remarks,
                            category = EXCLUDED.category,
                            status = EXCLUDED.status
                    `, [
                        String(p.SKU).trim(), String(p.PRODUCT_NAME || '').trim(), String(p.MASTER_BARCODE || '').trim(),
                        parseFloat(p.MASTER_SRP) || 0, String(p.SUPPLIER).trim(), String(p.CONDITION || '').trim(),
                        String(p.REMARKS || '').trim(), String(p.CATEGORY || '').trim(), String(p.STATUS || 'ACTIVE').trim()
                    ]);
                }
            }
        }

        res.json({ message: "Master Excel Data imported successfully!" });
    } catch (err) {
        res.status(500).json({ error: "Import error: " + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
