'use strict';
const taskReview=require('./nems-task-review');
const {randomUUID}=require('crypto');
 
// One in-app alert per store for this creation batch, committed with the tasks.
async function queueTaskAssignmentAlerts(client,created,actor){
    if(!created.length)return 0;
    const ids=created.map(a=>a.assignment_id);
    const result=await client.query(`
        WITH batches AS (
            SELECT s.store_id,LOWER(s.store_email) AS recipient,MIN(a.assignment_id) AS reference_id,
                COUNT(*)::integer AS task_count,
                'Store: '||s.store_name||E'\nNew monitoring tasks:\n'||
                string_agg(sp.supplier_name||' · '||a.expiry_scope||' · Deadline: '||
                    to_char(a.due_at AT TIME ZONE 'Asia/Manila','Mon DD, YYYY HH12:MI AM')||' (Philippine time)',E'\n' ORDER BY sp.supplier_name,a.assignment_id)||
                E'\nOpen My Tasks to review and encode. Save each product, then submit the completed task.' AS message
            FROM public.nems_task_assignments a
            JOIN public.stores s ON s.store_id=a.store_id
            JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id
            WHERE a.assignment_id=ANY($1::bigint[]) AND NULLIF(TRIM(s.store_email),'') IS NOT NULL
            GROUP BY s.store_id,s.store_email,s.store_name
        )
        INSERT INTO public.nems_notifications(recipient_email,sender_email,notification_type,title,message,reference_type,reference_id)
        SELECT b.recipient,$2,'TASK_ASSIGNED','New tasks assigned ('||b.task_count||')',b.message,'TASK',b.reference_id
        FROM batches b
        WHERE NOT EXISTS(SELECT 1 FROM public.nems_notifications n
            WHERE LOWER(n.recipient_email)=b.recipient AND n.reference_type='TASK'
              AND n.reference_id=b.reference_id AND n.notification_type='TASK_ASSIGNED')
        RETURNING notification_id`,[ids,actor]);
    return result.rowCount;
}

// Offline drafts belong to the downloaded reopen cycle, never a later reopen.
async function offlineCycleMatches(client,assignmentId,body){
    if(!Object.hasOwn(body||{},'offline_task_cycle'))return true;
    const r=await client.query(`SELECT COALESCE(MAX(reopened_at)::text,'INITIAL') AS task_cycle FROM public.nems_task_reopen_history WHERE assignment_id=$1`,[assignmentId]);
    return typeof body.offline_task_cycle==='string'&&body.offline_task_cycle===r.rows[0].task_cycle;
}

module.exports = function registerTaskRoutes({
    app,
    pool,
    authenticate,
    adminOnly, getMonitoringStock, storeScope, lockProduct, assertDatesNotArchived, businessDate, scanOverdueTasks
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
        if(error.status)return fail(res,error.status,error.message);
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
 
            const supplierIds=[...new Set((Array.isArray(body.supplier_ids)?body.supplier_ids:[body.supplier_id]).map(positiveId))];
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
 
            if (!supplierIds.length || supplierIds.some(id=>id===null)) {
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
                    WHERE supplier_id = ANY($1::bigint[])
                    `,
                    [supplierIds]
                );
 
                if (supplierCheck.rowCount !== supplierIds.length) {
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
 
                // Serialize task creation so concurrent admins cannot create duplicate pairs.
                await client.query("SELECT pg_advisory_xact_lock(hashtextextended('nems-task-create',0))");
                const visibilityReview=await taskReview.applyReview(client, body.product_review, supplierIds);
                const assignmentBatch=randomUUID();
                const result=await client.query(`
                    INSERT INTO public.nems_task_assignments
                    (store_id,supplier_id,assigned_by,expiry_scope,due_at,due_date,status,assignment_batch)
                    SELECT st.store_id,sp.supplier_id,$3,$4,$5::timestamptz,$5::timestamptz::date,'ACTIVE',$6::uuid
                    FROM unnest($1::bigint[]) AS st(store_id)
                    CROSS JOIN unnest($2::bigint[]) AS sp(supplier_id)
                    WHERE NOT EXISTS (SELECT 1 FROM public.nems_task_assignments a
                        WHERE a.store_id=st.store_id AND a.supplier_id=sp.supplier_id AND a.assignment_batch=$6::uuid)
                    RETURNING *`,[storeIds,supplierIds,assignedBy,scope,dueAt,assignmentBatch]);
                const created=result.rows;
                const skipped=storeIds.length*supplierIds.length-created.length;
                const emailBatch=await taskReview.queueBatch(client,created,assignedBy,body.product_review);
                const popupNotifications=await queueTaskAssignmentAlerts(client,created,assignedBy);

                await client.query('COMMIT');
 
                return res.status(201).json({
                    message: `${created.length} new-round task assignments created; ${skipped} duplicates within this round skipped. ${emailBatch.emails} combined store email(s) queued. ${visibilityReview.reviewed} product choices saved (${visibilityReview.hidden} hidden).`,
                    popup_notifications:popupNotifications,
                    visibility_review:visibilityReview,
                    email_batch:emailBatch,
                    assignment_batch:assignmentBatch,
                    skipped,
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
                        COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,
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
                            WHEN COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) < NOW()
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
                // Display status is computed by deadline; maintenance handles reminder scans.
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
                        COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,
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
                            WHEN COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) < NOW()
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
                        = LOWER(TRIM($1)) AND LOWER(s.store_email)=LOWER($2)
                    GROUP BY
                        a.assignment_id,
                        s.store_name,
                        sp.supplier_name
                    ORDER BY a.assigned_at DESC,
                             a.assignment_id DESC
                    `,
                    [storeName,getEmail(req)]
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
            const employeeName = cleanText(req.body?.employee_name);
            if (!employeeName || employeeName.length>120 || !remarks) return fail(res,400,'Employee Full Name and completion remarks are required');
 
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
                    SELECT a.assignment_id, a.status, COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at, EXISTS (SELECT 1 FROM public.nems_monitoring_submissions sub
                    WHERE sub.assignment_id=a.assignment_id
                      AND sub.submitted_at > COALESCE(
                        (SELECT MAX(rh.reopened_at) FROM public.nems_task_reopen_history rh
                         WHERE rh.assignment_id=a.assignment_id), '-infinity'::timestamptz)) AS submitted
                    FROM public.nems_task_assignments a
                    JOIN public.stores s
                        ON s.store_id = a.store_id
                    WHERE a.assignment_id = $1
                      AND LOWER(TRIM(s.store_name))
                          = LOWER(TRIM($2))
                      AND LOWER(s.store_email)=LOWER($3)
                    FOR UPDATE OF a
                    `,
                    [assignmentId, storeName, submittedBy]
                );
 
                if (!assignment.rowCount) {
                    await client.query('ROLLBACK');
                    return fail(res, 404, 'Task not found');
                }
 
                if(!await offlineCycleMatches(client,assignmentId,req.body)){
                    await client.query('ROLLBACK');return fail(res,409,'Offline draft belongs to an earlier task cycle. Download and review the reopened task.');
                }
                if(Object.hasOwn(req.body||{},'offline_product_revisions')){
                    const expected=req.body.offline_product_revisions;
                    if(!Array.isArray(expected)||expected.length>10000){await client.query('ROLLBACK');return fail(res,400,'Invalid offline task revisions');}
                    const actual=(await client.query(`SELECT p.product_id,pr.xmin::text AS revision FROM public.products p
                        JOIN public.suppliers sp ON LOWER(TRIM(sp.supplier_name))=LOWER(TRIM(p.supplier_name))
                        JOIN public.nems_task_assignments a ON a.supplier_id=sp.supplier_id AND a.assignment_id=$1
                        LEFT JOIN public.nems_task_product_progress pr ON pr.assignment_id=a.assignment_id AND pr.product_id=p.product_id
                        WHERE p.status='ACTIVE' AND p.store_task_visible=TRUE ORDER BY p.product_id`,[assignmentId])).rows;
                    const canonical=rows=>JSON.stringify(rows.map(r=>[Number(r.product_id),r.revision??null]).sort((a,b)=>a[0]-b[0]));
                    if(canonical(expected)!==canonical(actual)){await client.query('ROLLBACK');return fail(res,409,'Task products changed since the offline download or sync. Review them online before submitting.');}
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
 
                const completeness = await client.query(`
                    SELECT COUNT(*)::int AS total,
                           COUNT(pr.product_id) FILTER (WHERE pr.no_stock = TRUE OR pr.expiration_1 IS NOT NULL OR pr.expiration_2 IS NOT NULL OR pr.expiration_3 IS NOT NULL OR jsonb_array_length(COALESCE(pr.extra_expirations, '[]'::jsonb)) > 0)::int AS encoded
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
                        remarks,
                        submitted_at
                    )
                    VALUES ($1, $2, $3, clock_timestamp())
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
                        expiration_1, qty_1, expiration_2, qty_2, expiration_3, qty_3, extra_expirations, no_stock)
                    SELECT $1, p.product_id, p.sku, p.product_name, p.supplier_name,
                           pr.expiration_1, pr.qty_1, pr.expiration_2, pr.qty_2,
                           pr.expiration_3, pr.qty_3, COALESCE(pr.extra_expirations, '[]'::jsonb), pr.no_stock
                    FROM public.nems_task_product_progress pr
                    JOIN public.products p ON p.product_id = pr.product_id
                    WHERE pr.assignment_id = $2 AND p.status = 'ACTIVE'
                      AND p.store_task_visible = TRUE
                `, [result.rows[0].submission_id, assignmentId]);
 
                await client.query(`INSERT INTO public.nems_store_remarks
                    (store_name,store_email,product_id,assignment_id,employee_name,remarks,source,account_email,details)
                    SELECT $1,$2,i.product_id,$3,$4,$5,'MY_TASKS',$2,
                           jsonb_build_object('submission_id',$6::bigint,'submission_item',to_jsonb(i),'event','TASK_SUBMIT')
                    FROM public.nems_task_submission_items i WHERE i.submission_id=$6`,
                    [storeName,submittedBy,assignmentId,employeeName,remarks,result.rows[0].submission_id]);
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
                SELECT a.assignment_id, a.status, a.expiry_scope,
                       (SELECT COALESCE(MAX(reopened_at)::text,'INITIAL') FROM public.nems_task_reopen_history rh WHERE rh.assignment_id=a.assignment_id) AS task_cycle, COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at, sp.supplier_name,
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
                  AND LOWER(TRIM(s.store_name)) = LOWER(TRIM($2)) AND LOWER(s.store_email)=LOWER($3)
            `, [id, getStoreName(req), getEmail(req)]);
            if (!task.rowCount) return fail(res, 404, 'Task not found');
            const a = task.rows[0];
            const locked = a.status !== 'ACTIVE' ||
                (a.due_at && new Date(a.due_at).getTime() <= Date.now());
            const products = await pool.query(`
                SELECT p.product_id, p.sku, p.product_name, p.master_barcode, p.supplier_name,
                       pr.expiration_1, pr.qty_1, pr.expiration_2, pr.qty_2,
                       pr.expiration_3, pr.qty_3, COALESCE(pr.extra_expirations, '[]'::jsonb) AS extra_expirations, COALESCE(pr.no_stock, FALSE) AS no_stock, pr.saved_at, pr.xmin::text AS revision,
                       (pr.product_id IS NOT NULL) AS encoded
                FROM public.products p
                LEFT JOIN public.nems_task_product_progress pr
                  ON pr.product_id = p.product_id AND pr.assignment_id = $1
                WHERE p.status = 'ACTIVE'
                  AND p.store_task_visible = TRUE
                  AND LOWER(TRIM(p.supplier_name)) = LOWER(TRIM($2))
                ORDER BY p.product_name, p.product_id
            `, [id, a.supplier_name]);
            // Existing stock is a draft for confirmation, never automatic task completion.
            const monitoringRows=getMonitoringStock?await getMonitoringStock(req.user,a.supplier_name):[];
            const today=businessDate(),nearEnd=new Date(today+'T00:00:00Z');nearEnd.setUTCDate(nearEnd.getUTCDate()+90);
            const end=nearEnd.toISOString().slice(0,10);
            const byProduct=new Map();
            for(const row of monitoringRows){
                // Never prefill a locked task with stock encoded after its deadline.
                if(locked && (a.submitted || (String(row.excluded_task_ids||'').split(',').map(x=>x.trim()).includes(String(a.assignment_id)))||a.status!=='ACTIVE'||!a.due_at||!row.updated_at||new Date(row.updated_at).getTime()>=new Date(a.due_at).getTime()))continue;
                const date=row.expiration_date instanceof Date?row.expiration_date.toISOString().slice(0,10):String(row.expiration_date).slice(0,10);
                const qty=Number(row.quantity);
                const inScope=a.expiry_scope==='EXPIRED'?date<today:a.expiry_scope==='NEAR'?date>=today&&date<=end:date<=end;
                if(!inScope||!Number.isInteger(qty)||qty<=0)continue;
                const id=Number(row.product_id);if(!byProduct.has(id))byProduct.set(id,[]);
                byProduct.get(id).push({date,qty});
            }
            const mergedProducts=products.rows.map(product=>{
                if(product.encoded)return product;
                const values=byProduct.get(Number(product.product_id));if(!values?.length)return product;
                const draft={...product,monitoring_available:true};
                for(let i=1;i<=3;i++){draft[`expiration_${i}`]=values[i-1]?.date||null;draft[`qty_${i}`]=values[i-1]?.qty??null;}
                draft.extra_expirations=values.slice(3);return draft;
            });
            return res.json({task: a, locked: Boolean(locked), products: mergedProducts});
        } catch (error) { return handleError(res, error, 'Could not load task products'); }
    });
 
    // STORE: Save one product; lock and ownership checks are enforced server-side.
    app.put('/api/store/tasks/:id/products/:productId', authenticate, async (req, res) => {
        if (getRole(req) !== 'STORE') return fail(res, 403, 'STORE access required');
        const id = positiveId(req.params.id);
        const productId = positiveId(req.params.productId);
        if (!id || !productId) return fail(res, 400, 'Invalid task or product ID');
        const b = req.body || {};
        const employeeName = typeof b.employee_name === 'string' ? b.employee_name.trim() : '';
        const storeRemarks = typeof b.store_remarks === 'string' ? b.store_remarks.trim() : '';
        if (!employeeName || employeeName.length > 120 || !storeRemarks || storeRemarks.length > 2000)
            return fail(res, 400, 'Employee full name and Store Remarks are required');
        if (b.no_stock !== undefined && typeof b.no_stock !== 'boolean')
            return fail(res, 400, 'Invalid NO STOCK value');
        const noStock = b.no_stock === true;
        const dates = [], quantities = [];
        for (let i = 1; i <= 3; i++) {
            const d = b[`expiration_${i}`] || null;
            const q = b[`qty_${i}`] === '' || b[`qty_${i}`] == null ? null : Number(b[`qty_${i}`]);
            if (d !== null && (!/^\d{4}-\d{2}-\d{2}$/.test(d) ||
                Number.isNaN(Date.parse(d)) || new Date(d).toISOString().slice(0,10) !== d))
                return fail(res, 400, `Invalid expiration date ${i}`);
            if (q !== null && (!Number.isInteger(q) || q < 0))
                return fail(res, 400, `Invalid quantity ${i} (nonnegative whole number)`);
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
                !Number.isInteger(q) || q < 0 || item?.qty === '') {
                return fail(res, 400, `Invalid additional expiration row ${i + 4}`);
            }
        }
        if (!noStock && !dates.some(Boolean) && !extras.length) return fail(res,400,'Enter an expiration date and quantity or select NO STOCK');
        let client;
        try {
            client = await pool.connect();
            await client.query('BEGIN');
            const task = await client.query(`
                SELECT a.assignment_id, a.status, COALESCE(a.due_at, ((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at, sp.supplier_name, EXISTS (SELECT 1 FROM public.nems_monitoring_submissions sub
                    WHERE sub.assignment_id=a.assignment_id
                      AND sub.submitted_at > COALESCE(
                        (SELECT MAX(rh.reopened_at) FROM public.nems_task_reopen_history rh
                         WHERE rh.assignment_id=a.assignment_id), '-infinity'::timestamptz)) AS submitted
                FROM public.nems_task_assignments a
                JOIN public.stores s ON s.store_id = a.store_id
                JOIN public.suppliers sp ON sp.supplier_id = a.supplier_id
                WHERE a.assignment_id = $1
                  AND LOWER(TRIM(s.store_name)) = LOWER(TRIM($2)) AND LOWER(s.store_email)=LOWER($3)
                FOR UPDATE OF a
            `, [id, getStoreName(req), getEmail(req)]);
            if (!task.rowCount) { await client.query('ROLLBACK'); return fail(res, 404, 'Task not found'); }
            const a = task.rows[0];
            if(!await offlineCycleMatches(client,id,b)){
                await client.query('ROLLBACK');return fail(res,409,'Offline draft belongs to an earlier task cycle. Download and review the reopened task.');
            }
            if (a.status !== 'ACTIVE' ||
                (a.due_at && new Date(a.due_at).getTime() <= Date.now())) {
                await client.query('ROLLBACK'); return fail(res, 409, 'Task is closed or past its deadline. Ask ADMIN to reopen this task. Store Encoding is still available.');
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
            await lockProduct(client, getEmail(req), productId);
            const previous = await client.query(`SELECT pr.*, xmin::text AS revision FROM public.nems_task_product_progress pr
                WHERE assignment_id=$1 AND product_id=$2 FOR UPDATE`, [id, productId]);
            if (!Object.hasOwn(b, 'expected_revision') || (b.expected_revision ?? null) !== (previous.rows[0]?.revision ?? null)) {
                await client.query('ROLLBACK');
                return fail(res,409,'Another session changed this product. Reload the task before saving. Your draft has not been saved.');
            }
            if (!noStock) await assertDatesNotArchived(client,getEmail(req),productId,[...dates.filter(Boolean),...extras.map(x=>x.date)]);
            const saved = noStock ? await client.query(`
                INSERT INTO public.nems_task_product_progress
                    (assignment_id, product_id, no_stock, saved_by)
                VALUES ($1, $2, TRUE, $3)
                ON CONFLICT (assignment_id, product_id) DO UPDATE SET
                    no_stock=TRUE, saved_by=EXCLUDED.saved_by, saved_at=NOW()
                RETURNING *, xmin::text AS revision
            `, [id, productId, getEmail(req)]) : await client.query(`
                INSERT INTO public.nems_task_product_progress
                (assignment_id, product_id, expiration_1, qty_1,
                 expiration_2, qty_2, expiration_3, qty_3, saved_by, extra_expirations, no_stock)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,FALSE)
                ON CONFLICT (assignment_id, product_id) DO UPDATE SET
                  expiration_1=EXCLUDED.expiration_1, qty_1=EXCLUDED.qty_1,
                  expiration_2=EXCLUDED.expiration_2, qty_2=EXCLUDED.qty_2,
                  expiration_3=EXCLUDED.expiration_3, qty_3=EXCLUDED.qty_3,
                  saved_by=EXCLUDED.saved_by, extra_expirations=EXCLUDED.extra_expirations, no_stock=FALSE, saved_at=NOW()
                RETURNING *, xmin::text AS revision
            `, [id, productId, dates[0], quantities[0], dates[1], quantities[1],
                dates[2], quantities[2], getEmail(req), JSON.stringify(extras)]);
            await client.query(`INSERT INTO public.nems_store_remarks
                (store_name, store_email, product_id, assignment_id, employee_name, remarks, source, account_email, details)
                VALUES ($1,$2,$3,$4,$5,$6,'MY_TASKS',$7,$8::jsonb)`,
                [getStoreName(req),getEmail(req),productId,id,employeeName,storeRemarks,getEmail(req),
                 JSON.stringify({before:previous.rows[0]||null,revision:saved.rows[0].revision,no_stock:noStock,expiration_1:dates[0],qty_1:quantities[0],expiration_2:dates[1],qty_2:quantities[1],expiration_3:dates[2],qty_3:quantities[2],extra_expirations:extras})]);
            // Before the deadline, edits to a submitted task create a new immutable
            // submission revision. Previous submissions/items remain unchanged.
            let submissionUpdated=false;
            if(a.submitted){
                const revision=(await client.query(`INSERT INTO public.nems_monitoring_submissions(assignment_id,submitted_by,remarks,submitted_at)
                    VALUES($1,$2,$3,clock_timestamp()) RETURNING submission_id`,[id,getEmail(req),('Updated after submission: '+storeRemarks).slice(0,2000)])).rows[0];
                await client.query(`INSERT INTO public.nems_task_submission_items(submission_id,product_id,sku,product_name,supplier_name,
                    expiration_1,qty_1,expiration_2,qty_2,expiration_3,qty_3,extra_expirations,no_stock)
                    SELECT $1,p.product_id,p.sku,p.product_name,p.supplier_name,
                        pr.expiration_1,pr.qty_1,pr.expiration_2,pr.qty_2,pr.expiration_3,pr.qty_3,COALESCE(pr.extra_expirations,'[]'::jsonb),pr.no_stock
                    FROM public.nems_task_product_progress pr JOIN public.products p ON p.product_id=pr.product_id
                    WHERE pr.assignment_id=$2 AND p.status='ACTIVE' AND p.store_task_visible=TRUE`,[revision.submission_id,id]);
                await client.query(`INSERT INTO public.nems_store_remarks(store_name,store_email,product_id,assignment_id,employee_name,remarks,source,account_email,details)
                    VALUES($1,$2,$3,$4,$5,$6,'MY_TASKS',$2,$7::jsonb)`,[getStoreName(req),getEmail(req),productId,id,employeeName,storeRemarks,
                        JSON.stringify({event:'TASK_SUBMISSION_EDIT',submission_id:revision.submission_id})]);
                submissionUpdated=true;
            }
            await client.query('COMMIT');
            return res.json({...saved.rows[0],submission_updated:submissionUpdated});
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
                SELECT product_id, sku, product_name, supplier_name, master_barcode, landed_cost,
                       store_task_visible,
                       (product_name ~* '(^|[^[:alnum:]])(CS|CASE|BOX)([^[:alnum:]]|$)') AS possible_case
                FROM public.products
                WHERE status = 'ACTIVE'
                  AND LOWER(TRIM(supplier_name)) = LOWER(TRIM($1))
                ORDER BY product_name, product_id
            `, [supplier.rows[0].supplier_name]);
            const flags=new Map(taskReview.analyze(products.rows,[supplierId]).products.map(p=>[Number(p.product_id),p]));
            return res.json({supplier: supplier.rows[0], products: products.rows.map(p=>({...p,possible_case:taskReview.possiblePack(p.product_name),duplicate_group:flags.get(Number(p.product_id))?.duplicate_group||null}))});
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
            if(visible){
                const rows=await client.query(`SELECT product_id,sku,product_name,supplier_name,master_barcode,store_task_visible FROM public.products WHERE status='ACTIVE' AND LOWER(TRIM(supplier_name))=LOWER(TRIM($1)) ORDER BY product_id FOR UPDATE`,[supplier.rows[0].supplier_name]);
                const flagged=taskReview.analyze(rows.rows,[supplierId]).products;
                const affected=new Set(flagged.filter(p=>uniqueIds.includes(Number(p.product_id))&&p.duplicate_group).map(p=>p.duplicate_group));
                const counts=new Map();for(const p of flagged)if(affected.has(p.duplicate_group)&&(p.store_task_visible||uniqueIds.includes(Number(p.product_id))))counts.set(p.duplicate_group,(counts.get(p.duplicate_group)||0)+1);
                if([...counts.values()].some(n=>n>1)){await client.query('ROLLBACK');return fail(res,409,'Another exact duplicate is already visible. Hide it first, then unhide the record to keep.');}
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
 
