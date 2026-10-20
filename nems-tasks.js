
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

            if (dueAt === undefined) {
                return fail(res, 400, 'Invalid deadline');
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
                            WHEN COUNT(sub.submission_id) > 0
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
                            WHEN COUNT(sub.submission_id) > 0
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
                    SELECT a.assignment_id, a.status
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

                const prior = await client.query(
                    `
                    SELECT submission_id
                    FROM public.nems_monitoring_submissions
                    WHERE assignment_id = $1
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
};

