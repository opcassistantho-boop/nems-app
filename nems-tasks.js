 
'use strict';
 
module.exports = function registerTaskRoutes({
    app,
    pool,
    authenticate,
    adminOnly
}) {
    if (!app || !pool || !authenticate || !adminOnly) {
        throw new Error('Missing NEMS task module dependencies');
    }
 
    const fail = (res, status, message) => {
        return res.status(status).json({ error: message });
    };
 
    const positiveId = value => {
        const n = Number(value);
        return Number.isSafeInteger(n) && n > 0 ? n : null;
    };
 
    const cleanText = value => String(value || '').trim();
 
    const getStoreName = req => {
        return cleanText(req.user?.store_name);
    };
 
    const getEmail = req => {
        return cleanText(req.user?.email).toLowerCase();
    };
 
    const getRole = req => {
        return cleanText(req.user?.role).toUpperCase();
    };
 
    const validScope = value => {
        const scope = cleanText(value || 'BOTH').toUpperCase();
        return ['EXPIRED', 'NEAR', 'BOTH'].includes(scope)
            ? scope
            : null;
    };
 
    const parseDueAt = value => {
        if (value === undefined || value === null || value === '') {
            return null;
        }
 
        const date = new Date(value);
 
        if (Number.isNaN(date.getTime())) {
            return undefined;
        }
 
        return date.toISOString();
    };
 
    function handleError(res, error, message) {
        console.error('[NEMS TASKS]', error);
 
        if (error.code === '23505') {
            return fail(
                res,
                409,
                'This supplier is already assigned to this store'
            );
        }
 
        if (error.code === '23503') {
            return fail(
                res,
                400,
                'The selected store or supplier does not exist'
            );
        }
 
        return fail(res, 500, message);
    }
 
    // ==========================================
    // ADMIN: STORES AVAILABLE FOR ASSIGNMENT
    // ==========================================
 
    app.get(
        '/api/admin/task-stores',
        authenticate,
        adminOnly,
        async (req, res) => {
            try {
                const result = await pool.query(`
                    SELECT store_id, store_name
                    FROM public.stores
                    ORDER BY store_name ASC
                `);
 
                return res.json(result.rows);
            } catch (error) {
                return handleError(
                    res,
                    error,
                    'Could not load stores'
                );
            }
        }
    );
 
    // ==========================================
    // ADMIN: CREATE TASK ASSIGNMENTS
    // ==========================================
 
    app.post(
        '/api/admin/tasks',
        authenticate,
        adminOnly,
        async (req, res) => {
            const body = req.body || {};
 
            const supplierId = positiveId(body.supplier_id);
 
            const rawStoreIds = Array.isArray(body.store_ids)
                ? body.store_ids
                : body.store_id !== undefined
                    ? [body.store_id]
                    : [];
 
            const storeIds = [
                ...new Set(rawStoreIds.map(positiveId))
            ];
 
            const scope = validScope(body.expiry_scope);
            const dueAt = parseDueAt(body.due_at);
 
            if (!supplierId) {
                return fail(res, 400, 'Select a valid supplier');
            }
 
            if (
                !storeIds.length ||
                storeIds.some(id => id === null)
            ) {
                return fail(res, 400, 'Select valid stores');
            }
 
            if (!scope) {
                return fail(res, 400, 'Invalid expiry scope');
            }
 
            if (dueAt === undefined || !dueAt || new Date(dueAt).getTime() <= Date.now()) {
                return fail(res, 400, 'A future deadline is required');
            }
 
            const assignedBy = getEmail(req);
 
            if (!assignedBy) {
                return fail(res, 401, 'User email unavailable');
            }
 
            let client;
 
            try {
                client = await pool.connect();
 
                await client.query('BEGIN');
 
                const supplierCheck = await client.query(
                    `
                    SELECT supplier_id
                    FROM public.suppliers
                    WHERE supplier_id = $1
                    `,
                    [supplierId]
                );
 
                if (!supplierCheck.rowCount) {
                    await client.query('ROLLBACK');
                    return fail(res, 404, 'Supplier not found');
                }
 
                const storeCheck = await client.query(
                    `
                    SELECT store_id
                    FROM public.stores
                    WHERE store_id = ANY($1::bigint[])
                    `,
                    [storeIds]
                );
 
                if (storeCheck.rowCount !== storeIds.length) {
                    await client.query('ROLLBACK');
                    return fail(
                        res,
                        404,
                        'One or more stores were not found'
                    );
                }
 
                const existing = await client.query(
                    `
                    SELECT store_id
                    FROM public.nems_task_assignments
                    WHERE supplier_id = $1
                      AND store_id = ANY($2::bigint[])
                    `,
                    [supplierId, storeIds]
                );
 
                if (existing.rowCount) {
                    await client.query('ROLLBACK');
 
                    return res.status(409).json({
                        error:
                            'One or more selected stores already have an assignment for this supplier. Existing assignments were not changed.',
                        conflicting_store_ids:
                            existing.rows.map(row => row.store_id)
                    });
                }
 
                const created = [];
 
                for (const storeId of storeIds) {
                    const result = await client.query(
                        `
                        INSERT INTO public.nems_task_assignments (
                            store_id,
                            supplier_id,
                            assigned_by,
                            expiry_scope,
                            due_at,
                            due_date,
                            status
                        )
                        VALUES (
                            $1, $2, $3, $4, $5,
                            $5::timestamptz::date,
                            'ACTIVE'
                        )
                        RETURNING *
                        `,
                        [
                            storeId,
                            supplierId,
                            assignedBy,
                            scope,
                            dueAt
                        ]
                    );
 
                    created.push(result.rows[0]);
                }
 
                await client.query('COMMIT');
 
                return res.status(201).json({
                    message: 'Task assignments created',
                    count: created.length,
                    tasks: created
                });
            } catch (error) {
                if (client) {
                    try {
                        await client.query('ROLLBACK');
                    } catch (_) {
                        // Preserve original error.
                    }
                }
 
                return handleError(
                    res,
                    error,
                    'Could not create task assignments'
                );
            } finally {
                if (client) {
                    client.release();
                }
            }
        }
    );
 
    // ==========================================
    // ADMIN: VIEW ALL TASK ASSIGNMENTS
    // ==========================================
 
    app.get(
        '/api/admin/tasks',
        authenticate,
        adminOnly,
        async (req, res) => {
            try {
                const result = await pool.query(`
                    SELECT
                        a.assignment_id,
                        a.store_id,
                        s.store_name,
                        a.supplier_id,
                        sp.supplier_name,
                        a.assigned_by,
                        a.assigned_at,
                        a.expiry_scope,
                        a.due_at,
                        a.due_date,
                        a.status,
                        COUNT(sub.submission_id)::integer
                            AS submission_count,
                        MAX(sub.submitted_at)
                            AS last_submitted_at,
                        CASE
                            WHEN a.status = 'CANCELLED'
                                THEN 'CANCELLED'
                            WHEN MAX(sub.submitted_at) > COALESCE(
                                 (SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h
                                  WHERE h.assignment_id = a.assignment_id), '-infinity'::timestamptz)
                                THEN 'SUBMITTED'
                            WHEN a.due_at IS NOT NULL
                                AND a.due_at < NOW()
                                THEN 'OVERDUE'
                            ELSE 'PENDING'
                        END AS display_status
                    FROM public.nems_task_assignments a
                    JOIN public.stores s
                        ON s.store_id = a.store_id
                    JOIN public.suppliers sp
                        ON sp.supplier_id = a.supplier_id
                    LEFT JOIN public.nems_monitoring_submissions sub
                        ON sub.assignment_id = a.assignment_id
                    GROUP BY
                        a.assignment_id,
                        s.store_name,
                        sp.supplier_name
                    ORDER BY a.assigned_at DESC,
                             a.assignment_id DESC
                `);
 
                return res.json(result.rows);
            } catch (error) {
                return handleError(
                    res,
                    error,
                    'Could not load task assignments'
                );
            }
        }
    );
 
    // ==========================================
    // STORE: VIEW OWN TASKS
    // ==========================================
 
    app.get(
        '/api/store/tasks',
        authenticate,
        async (req, res) => {
            if (getRole(req) !== 'STORE') {
                return fail(res, 403, 'STORE access required');
            }
 
            const storeName = getStoreName(req);
 
            if (!storeName) {
                return fail(
                    res,
                    403,
                    'Your account has no assigned store'
                );
            }
 
            try {
                const result = await pool.query(
                    `
                    SELECT
                        a.assignment_id,
                        a.store_id,
                        s.store_name,
                        a.supplier_id,
                        sp.supplier_name,
                        a.assigned_at,
                        a.expiry_scope,
                        a.due_at,
                        a.due_date,
                        a.status,
                        COUNT(sub.submission_id)::integer
                            AS submission_count,
                        CASE
                            WHEN a.status = 'CANCELLED'
                                THEN 'CANCELLED'
                            WHEN MAX(sub.submitted_at) > COALESCE(
                                 (SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h
                                  WHERE h.assignment_id = a.assignment_id), '-infinity'::timestamptz)
                                THEN 'SUBMITTED'
                            WHEN a.due_at IS NOT NULL
                                AND a.due_at < NOW()
                                THEN 'OVERDUE'
                            ELSE 'PENDING'
                        END AS display_status
                    FROM public.nems_task_assignments a
                    JOIN public.stores s
                        ON s.store_id = a.store_id
                    JOIN public.suppliers sp
                        ON sp.supplier_id = a.supplier_id
                    LEFT JOIN public.nems_monitoring_submissions sub
                        ON sub.assignment_id = a.assignment_id
                    WHERE LOWER(TRIM(s.store_name))
                        = LOWER(TRIM($1))
                    GROUP BY
                        a.assignment_id,
                        s.store_name,
                        sp.supplier_name
                    ORDER BY a.assigned_at DESC,
                             a.assignment_id DESC
                    `,
                    [storeName]
                );
 
                return res.json(result.rows);
            } catch (error) {
                return handleError(
                    res,
                    error,
                    'Could not load your tasks'
                );
            }
        }
    );
 
    // ==========================================
    // STORE: SUBMIT COMPLETED TASK
    // ==========================================
 
    app.post(
        '/api/store/tasks/:id/submit',
        authenticate,
        async (req, res) => {
            if (getRole(req) !== 'STORE') {
                return fail(res, 403, 'STORE access required');
            }
 
            const assignmentId = positiveId(req.params.id);
            const storeName = getStoreName(req);
            const submittedBy = getEmail(req);
 
            if (!assignmentId) {
                return fail(res, 400, 'Invalid task ID');
            }
 
            if (!storeName || !submittedBy) {
                return fail(
                    res,
                    403,
                    'Your store account is incomplete'
                );
            }
 
            const remarks = cleanText(req.body?.remarks);
 
            if (remarks.length > 2000) {
                return fail(
                    res,
                    400,
                    'Remarks must not exceed 2000 characters'
                );
            }
 
            let client;
 
            try {
                client = await pool.connect();
 
                await client.query('BEGIN');
 
                const assignment = await client.query(
                    `
                    SELECT a.assignment_id, a.status, a.due_at
                    FROM public.nems_task_assignments a
                    JOIN public.stores s
                        ON s.store_id = a.store_id
                    WHERE a.assignment_id = $1
                      AND LOWER(TRIM(s.store_name))
                          = LOWER(TRIM($2))
                    FOR UPDATE OF a
                    `,
                    [assignmentId, storeName]
                );
 
                if (!assignment.rowCount) {
                    await client.query('ROLLBACK');
                    return fail(res, 404, 'Task not found');
                }
 
                if (assignment.rows[0].status !== 'ACTIVE') {
                    await client.query('ROLLBACK');
                    return fail(
                        res,
                        409,
                        'This task is not active'
                    );
                }
 
                if (assignment.rows[0].due_at &&
                    new Date(assignment.rows[0].due_at).getTime() <= Date.now()) {
                    await client.query('ROLLBACK');
                    return fail(res, 409, 'Task deadline has passed. Contact ADMIN.');
                }
 
                const prior = await client.query(
                    `
                    SELECT sub.submission_id
                    FROM public.nems_monitoring_submissions sub
                    WHERE sub.assignment_id = $1
                      AND sub.submitted_at > COALESCE(
                          (SELECT MAX(reopened_at)
                           FROM public.nems_task_reopen_history
                           WHERE assignment_id = $1),
                          '-infinity'::timestamptz)
                    LIMIT 1
                    `,
                    [assignmentId]
                );
 
                if (prior.rowCount) {
                    await client.query('ROLLBACK');
                    return fail(
                        res,
                        409,
                        'This task was already submitted'
                    );
                }
 
                const completeness = await client.query(`
                    SELECT COUNT(*)::int AS total,
                           COUNT(pr.product_id) FILTER (WHERE pr.expiration_1 IS NOT NULL OR pr.expiration_2 IS NOT NULL OR pr.expiration_3 IS NOT NULL OR jsonb_array_length(COALESCE(pr.extra_expirations, '[]'::jsonb)) > 0)::int AS encoded
                    FROM public.products p
                    JOIN public.suppliers sp
                      ON LOWER(TRIM(p.supplier_name)) = LOWER(TRIM(sp.supplier_name))
                    JOIN public.nems_task_assignments a
                      ON a.supplier_id = sp.supplier_id
                    LEFT JOIN public.nems_task_product_progress pr
                      ON pr.assignment_id = a.assignment_id
                     AND pr.product_id = p.product_id
                    WHERE a.assignment_id = $1 AND p.status = 'ACTIVE'
                      AND p.store_task_visible = TRUE
                `, [assignmentId]);
                const counts = completeness.rows[0];
                if (!counts.total || counts.encoded !== counts.total) {
                    await client.query('ROLLBACK');
                    return fail(res, 409,
                        `Encode all active supplier products before submitting (${counts.encoded}/${counts.total}).`);
                }
 
                const result = await client.query(
                    `
                    INSERT INTO public.nems_monitoring_submissions (
                        assignment_id,
                        submitted_by,
                        remarks
                    )
                    VALUES ($1, $2, $3)
                    RETURNING *
                    `,
                    [
                        assignmentId,
                        submittedBy,
                        remarks || null
                    ]
                );
 
                await client.query(`
                    INSERT INTO public.nems_task_submission_items (
                        submission_id, product_id, sku, product_name, supplier_name,
                        expiration_1, qty_1, expiration_2, qty_2, expiration_3, qty_3, extra_expirations)
                    SELECT $1, p.product_id, p.sku, p.product_name, p.supplier_name,
                           pr.expiration_1, pr.qty_1, pr.expiration_2, pr.qty_2,
                           pr.expiration_3, pr.qty_3, COALESCE(pr.extra_expirations, '[]'::jsonb)
                    FROM public.nems_task_product_progress pr
                    JOIN public.products p ON p.product_id = pr.product_id
                    WHERE pr.assignment_id = $2 AND p.status = 'ACTIVE'
                      AND p.store_task_visible = TRUE
                `, [result.rows[0].submission_id, assignmentId]);
 
                await client.query('COMMIT');
 
                return res.status(201).json({
                    message: 'Task submitted successfully',
                    submission: result.rows[0]
                });
            } catch (error) {
                if (client) {
                    try {
                        await client.query('ROLLBACK');
                    } catch (_) {
                        // Preserve original error.
                    }
                }
 
                return handleError(
                    res,
                    error,
                    'Could not submit task'
                );
            } finally {
                if (client) {
                    client.release();
                }
            }
        }
    );
 
    // STORE: Load every active supplier product with task-specific saved progress.
    app.get('/api/store/tasks/:id/products', authenticate, async (req, res) => {
        if (getRole(req) !== 'STORE') return fail(res, 403, 'STORE access required');
        const id = positiveId(req.params.id);
        if (!id) return fail(res, 400, 'Invalid task ID');
        try {
            const task = await pool.query(`
                SELECT a.assignment_id, a.status, a.due_at, sp.supplier_name,
                       EXISTS (
                         SELECT 1 FROM public.nems_monitoring_submissions sub
                         WHERE sub.assignment_id = a.assignment_id
                           AND sub.submitted_at > COALESCE(
                             (SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h
                              WHERE h.assignment_id = a.assignment_id), '-infinity'::timestamptz)
                       ) AS submitted
                FROM public.nems_task_assignments a
                JOIN public.stores s ON s.store_id = a.store_id
                JOIN public.suppliers sp ON sp.supplier_id = a.supplier_id
                WHERE a.assignment_id = $1
                  AND LOWER(TRIM(s.store_name)) = LOWER(TRIM($2))
            `, [id, getStoreName(req)]);
            if (!task.rowCount) return fail(res, 404, 'Task not found');
            const a = task.rows[0];
            const locked = a.status !== 'ACTIVE' || a.submitted ||
                (a.due_at && new Date(a.due_at).getTime() <= Date.now());
            const products = await pool.query(`
                SELECT p.product_id, p.sku, p.product_name, p.supplier_name,
                       pr.expiration_1, pr.qty_1, pr.expiration_2, pr.qty_2,
                       pr.expiration_3, pr.qty_3, COALESCE(pr.extra_expirations, '[]'::jsonb) AS extra_expirations, pr.saved_at,
                       (pr.product_id IS NOT NULL) AS encoded
                FROM public.products p
                LEFT JOIN public.nems_task_product_progress pr
                  ON pr.product_id = p.product_id AND pr.assignment_id = $1
                WHERE p.status = 'ACTIVE'
                  AND p.store_task_visible = TRUE
                  AND LOWER(TRIM(p.supplier_name)) = LOWER(TRIM($2))
                ORDER BY p.product_name, p.product_id
            `, [id, a.supplier_name]);
            return res.json({task: a, locked: Boolean(locked), products: products.rows});
        } catch (error) { return handleError(res, error, 'Could not load task products'); }
    });
 
    // STORE: Save one product; lock and ownership checks are enforced server-side.
    app.put('/api/store/tasks/:id/products/:productId', authenticate, async (req, res) => {
        if (getRole(req) !== 'STORE') return fail(res, 403, 'STORE access required');
        const id = positiveId(req.params.id);
        const productId = positiveId(req.params.productId);
        if (!id || !productId) return fail(res, 400, 'Invalid task or product ID');
        const b = req.body || {};
        const dates = [], quantities = [];
        for (let i = 1; i <= 3; i++) {
            const d = b[`expiration_${i}`] || null;
            const q = b[`qty_${i}`] === '' || b[`qty_${i}`] == null ? null : Number(b[`qty_${i}`]);
            if (d !== null && (!/^\d{4}-\d{2}-\d{2}$/.test(d) ||
                Number.isNaN(Date.parse(d)) || new Date(d).toISOString().slice(0,10) !== d))
                return fail(res, 400, `Invalid expiration date ${i}`);
            if (q !== null && (!Number.isInteger(q) || q < 0 || q > 500))
                return fail(res, 400, `Invalid quantity ${i} (0–500)`);
            if ((d === null) !== (q === null))
                return fail(res, 400, `Expiration date and quantity ${i} must be entered together`);
            dates.push(d); quantities.push(q);
        }
        const extras = Array.isArray(b.extra_expirations) ? b.extra_expirations : [];
        if (extras.length > 97) return fail(res, 400, 'Maximum 100 expiration dates per product');
        for (let i = 0; i < extras.length; i++) {
            const item = extras[i];
            const d = item?.date;
            const q = Number(item?.qty);
            if (typeof d !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d) ||
                Number.isNaN(Date.parse(d)) || new Date(d).toISOString().slice(0,10) !== d ||
                !Number.isInteger(q) || q < 0 || q > 500 || item?.qty === '') {
                return fail(res, 400, `Invalid additional expiration row ${i + 4}`);
            }
        }
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const task = await client.query(`
                SELECT a.assignment_id, a.status, a.due_at, sp.supplier_name
                FROM public.nems_task_assignments a
                JOIN public.stores s ON s.store_id = a.store_id
                JOIN public.suppliers sp ON sp.supplier_id = a.supplier_id
                WHERE a.assignment_id = $1
                  AND LOWER(TRIM(s.store_name)) = LOWER(TRIM($2))
                FOR UPDATE OF a
            `, [id, getStoreName(req)]);
            if (!task.rowCount) { await client.query('ROLLBACK'); return fail(res, 404, 'Task not found'); }
            const a = task.rows[0];
            if (a.status !== 'ACTIVE' ||
                (a.due_at && new Date(a.due_at).getTime() <= Date.now())) {
                await client.query('ROLLBACK'); return fail(res, 409, 'Task is locked or overdue');
            }
            const submitted = await client.query(`
                SELECT 1 FROM public.nems_monitoring_submissions sub
                WHERE sub.assignment_id = $1
                  AND sub.submitted_at > COALESCE(
                    (SELECT MAX(reopened_at) FROM public.nems_task_reopen_history
                     WHERE assignment_id = $1), '-infinity'::timestamptz)
                LIMIT 1
            `, [id]);
            if (submitted.rowCount) {
                await client.query('ROLLBACK'); return fail(res, 409, 'Task already submitted');
            }
            const product = await client.query(`
                SELECT product_id FROM public.products
                WHERE product_id = $1 AND status = 'ACTIVE'
                  AND store_task_visible = TRUE
                  AND LOWER(TRIM(supplier_name)) = LOWER(TRIM($2))
            `, [productId, a.supplier_name]);
            if (!product.rowCount) {
                await client.query('ROLLBACK'); return fail(res, 404, 'Product not in assigned supplier');
            }
            const saved = await client.query(`
                INSERT INTO public.nems_task_product_progress
                (assignment_id, product_id, expiration_1, qty_1,
                 expiration_2, qty_2, expiration_3, qty_3, saved_by, extra_expirations)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
                ON CONFLICT (assignment_id, product_id) DO UPDATE SET
                  expiration_1=EXCLUDED.expiration_1, qty_1=EXCLUDED.qty_1,
                  expiration_2=EXCLUDED.expiration_2, qty_2=EXCLUDED.qty_2,
                  expiration_3=EXCLUDED.expiration_3, qty_3=EXCLUDED.qty_3,
                  saved_by=EXCLUDED.saved_by, extra_expirations=EXCLUDED.extra_expirations, saved_at=NOW()
                RETURNING *
            `, [id, productId, dates[0], quantities[0], dates[1], quantities[1],
                dates[2], quantities[2], getEmail(req), JSON.stringify(extras)]);
            await client.query('COMMIT');
            return res.json(saved.rows[0]);
        } catch (error) {
            if (client) await client.query('ROLLBACK').catch(() => {});
            return handleError(res, error, 'Could not save task product');
        } finally { if (client) client.release(); }
    });
 
    // ADMIN: Edit an OPEN assignment only; never change submitted/overdue cycles.
    app.patch('/api/admin/tasks/:id', authenticate, adminOnly, async (req, res) => {
        const id = positiveId(req.params.id);
        const scope = validScope(req.body?.expiry_scope);
        const rawDeadline = req.body?.due_at;
        const dueAt = rawDeadline === null || rawDeadline === '' ? null : parseDueAt(rawDeadline);
        if (!id || !scope || (rawDeadline !== null && rawDeadline !== '' && !dueAt)) {
            return fail(res, 400, 'Invalid task ID, expiry scope or deadline');
        }
        if (dueAt && new Date(dueAt).getTime() <= Date.now()) {
            return fail(res, 400, 'Deadline must be in the future');
        }
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const result = await client.query(`
                SELECT assignment_id, status, due_at FROM public.nems_task_assignments
                WHERE assignment_id=$1 FOR UPDATE
            `, [id]);
            if (!result.rowCount) {
                await client.query('ROLLBACK');
                return fail(res, 404, 'Assignment not found');
            }
            const task = result.rows[0];
            if (task.status !== 'ACTIVE' ||
                (task.due_at && new Date(task.due_at).getTime() <= Date.now())) {
                await client.query('ROLLBACK');
                return fail(res, 409, 'Closed or overdue task: use Reopen instead');
            }
            const latest = await client.query(`
                SELECT
                    (SELECT MAX(submitted_at) FROM public.nems_monitoring_submissions
                     WHERE assignment_id=$1) AS last_submission,
                    (SELECT MAX(reopened_at) FROM public.nems_task_reopen_history
                     WHERE assignment_id=$1) AS last_reopen
            `, [id]);
            const {last_submission, last_reopen} = latest.rows[0];
            if (last_submission && (!last_reopen || new Date(last_submission) > new Date(last_reopen))) {
                await client.query('ROLLBACK');
                return fail(res, 409, 'Submitted task: use Reopen instead');
            }
            const updated = await client.query(`
                UPDATE public.nems_task_assignments
                SET expiry_scope=$2, due_at=$3, due_date=$3::timestamptz::date
                WHERE assignment_id=$1
                RETURNING assignment_id, expiry_scope, due_at
            `, [id, scope, dueAt]);
            await client.query('COMMIT');
            return res.json({message:'Task updated', task:updated.rows[0]});
        } catch (error) {
            if (client) await client.query('ROLLBACK').catch(() => {});
            return handleError(res, error, 'Could not update assignment');
        } finally {
            if (client) client.release();
        }
    });
 
    // ADMIN: Reopen a task, preserving all previous submission snapshots.
    app.post('/api/admin/tasks/:id/reopen', authenticate, adminOnly, async (req, res) => {
        const id = positiveId(req.params.id);
        const newDueAt = parseDueAt(req.body?.due_at);
        if (!id || !newDueAt || new Date(newDueAt).getTime() <= Date.now())
            return fail(res, 400, 'A future deadline is required');
        const reason = cleanText(req.body?.reason).slice(0, 2000);
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const found = await client.query(`
                SELECT assignment_id, status, due_at
                FROM public.nems_task_assignments WHERE assignment_id = $1 FOR UPDATE
            `, [id]);
            if (!found.rowCount) { await client.query('ROLLBACK'); return fail(res, 404, 'Task not found'); }
            if (found.rows[0].status === 'CANCELLED') {
                await client.query('ROLLBACK'); return fail(res, 409, 'Cancelled task cannot be reopened');
            }
            const wasSubmitted = await client.query(`
                SELECT 1 FROM public.nems_monitoring_submissions
                WHERE assignment_id = $1 LIMIT 1
            `, [id]);
            const isExpired = found.rows[0].due_at &&
                new Date(found.rows[0].due_at).getTime() <= Date.now();
            if (!wasSubmitted.rowCount && !isExpired) {
                await client.query('ROLLBACK');
                return fail(res, 409, 'Task is still open; use deadline management instead');
            }
            await client.query(`
                INSERT INTO public.nems_task_reopen_history
                (assignment_id, reopened_by, previous_due_at, new_due_at, reason)
                VALUES ($1,$2,$3,$4,$5)
            `, [id, getEmail(req), found.rows[0].due_at, newDueAt, reason || null]);
            await client.query(`
                UPDATE public.nems_task_assignments
                SET due_at=$2, due_date=$2::timestamptz::date
                WHERE assignment_id=$1
            `, [id, newDueAt]);
            await client.query('COMMIT');
            return res.json({message:'Task reopened', assignment_id:id, due_at:newDueAt});
        } catch (error) {
            if (client) await client.query('ROLLBACK').catch(() => {});
            return handleError(res, error, 'Could not reopen task');
        } finally { if (client) client.release(); }
    });
 
    // ADMIN: Review visible and hidden products for an assigned supplier.
    app.get('/api/admin/task-products', authenticate, adminOnly, async (req, res) => {
        const supplierId = positiveId(req.query.supplier_id);
        if (!supplierId) return fail(res, 400, 'Invalid supplier ID');
        try {
            const supplier = await pool.query(
                'SELECT supplier_id, supplier_name FROM public.suppliers WHERE supplier_id = $1',
                [supplierId]);
            if (!supplier.rowCount) return fail(res, 404, 'Supplier not found');
            const products = await pool.query(`
                SELECT product_id, sku, product_name, supplier_name,
                       store_task_visible,
                       (product_name ~* '(^|[^[:alnum:]])(CS|CASE|BOX)([^[:alnum:]]|$)') AS possible_case
                FROM public.products
                WHERE status = 'ACTIVE'
                  AND LOWER(TRIM(supplier_name)) = LOWER(TRIM($1))
                ORDER BY product_name, product_id
            `, [supplier.rows[0].supplier_name]);
            return res.json({supplier: supplier.rows[0], products: products.rows});
        } catch (error) { return handleError(res, error, 'Could not load product visibility'); }
    });
 
    // ADMIN: Set visibility for selected products. Never delete product records.
    app.patch('/api/admin/task-products/visibility', authenticate, adminOnly, async (req, res) => {
        const supplierId = positiveId(req.body?.supplier_id);
        const ids = req.body?.product_ids;
        const visible = req.body?.visible;
        if (!supplierId || !Array.isArray(ids) || !ids.length || ids.length > 3000 ||
            ids.some(id => !positiveId(id)) || typeof visible !== 'boolean') {
            return fail(res, 400, 'Valid supplier, product IDs, and visibility are required');
        }
        const uniqueIds = [...new Set(ids.map(Number))];
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const supplier = await client.query(
                'SELECT supplier_name FROM public.suppliers WHERE supplier_id = $1', [supplierId]);
            if (!supplier.rowCount) {
                await client.query('ROLLBACK');
                return fail(res, 404, 'Supplier not found');
            }
            const result = await client.query(`
                UPDATE public.products SET store_task_visible = $1
                WHERE product_id = ANY($2::integer[])
                  AND status = 'ACTIVE'
                  AND LOWER(TRIM(supplier_name)) = LOWER(TRIM($3))
                RETURNING product_id
            `, [visible, uniqueIds, supplier.rows[0].supplier_name]);
            if (result.rowCount !== uniqueIds.length) {
                await client.query('ROLLBACK');
                return fail(res, 409, 'Some products do not belong to this active supplier');
            }
            await client.query('COMMIT');
            return res.json({updated: result.rowCount, visible});
        } catch (error) {
            if (client) await client.query('ROLLBACK').catch(() => {});
            return handleError(res, error, 'Could not update product visibility');
        } finally { if (client) client.release(); }
    });
 
};
 
