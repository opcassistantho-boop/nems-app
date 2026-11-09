'use strict';
// No new npm packages. xlsx is already a NEMS dependency.
const crypto=require('crypto');
const {Worker,isMainThread,parentPort,workerData}=require('worker_threads');
if(!isMainThread && workerData?.nemsExport){
    void (async()=>{
        const XLSX=require('xlsx'),book=XLSX.utils.book_new();
        const sheets=workerData.databaseExport?await buildDatabaseExport():workerData.sheets;
        for(const sheet of sheets)XLSX.utils.book_append_sheet(book,XLSX.utils.json_to_sheet(sheet.rows.length?sheet.rows:[{Message:'No records'}]),sheet.name);
        const data=XLSX.write(book,{type:'buffer',bookType:'xlsx'});
        const bytes=Uint8Array.from(data);parentPort.postMessage(bytes,[bytes.buffer]);
    })().catch(error=>{throw error;});
async function buildDatabaseExport(){
    const {Pool}=require('pg');
    const exportPool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL_DISABLE==='true'?false:{rejectUnauthorized:false},max:1,connectionTimeoutMillis:10000,idleTimeoutMillis:1000,statement_timeout:30000,application_name:'nems-export-worker'});
    let pool;
    const storeScope=(user,alias='m')=>workerData.scopes[alias];
    const scopedMonitoringSQL=()=>workerData.monitoringSQL;
function businessDate() {
    return new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Manila',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
}
function dateKey(v) { return v instanceof Date ? v.toISOString().slice(0,10) : String(v || '').slice(0,10); }
function expiryDays(v) { return Math.round((Date.parse(dateKey(v)+'T00:00:00Z')-Date.parse(businessDate()+'T00:00:00Z'))/86400000); }
function appError(status,message) { const e=new Error(message); e.status=status; return e; }
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
 
function expiryBounds(){const today=businessDate(),d=new Date(today+'T00:00:00Z'),six=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+6,1));six.setUTCDate(Math.min(d.getUTCDate(),new Date(Date.UTC(six.getUTCFullYear(),six.getUTCMonth()+1,0)).getUTCDate()));return [today,six.toISOString().slice(0,10)];}
function expiryCaseSQL(column,today,six){return `CASE WHEN ${column}<${today} THEN 'EXPIRED' WHEN ${column}<=${today}+30 THEN 'RED' WHEN ${column}<=${today}+60 THEN 'BLUE' WHEN ${column}<=${today}+90 THEN 'GREEN' WHEN ${column}<=${six} THEN 'ORANGE' ELSE 'LATER' END`;}
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
    return rows.map((r,i)=>({...r,...map.get(i),days_remaining:expiryDays(r.expiration_date),days_overdue:Math.max(0,-expiryDays(r.expiration_date))}));
}

async function buildMonitoringExport(req){
            const scope = storeScope(req.user);
            const allowedCategories = new Set(['EXPIRED', 'RED', 'BLUE', 'GREEN', 'ORANGE', 'LATER']);
            const rawCategories = req.query.category == null ? [] :
                (Array.isArray(req.query.category) ? req.query.category : [req.query.category]);
            const categories = [...new Set(rawCategories.map(value => String(value).trim().toUpperCase()))];
            if (categories.length > 6 || categories.some(value => !allowedCategories.has(value))) {
                throw appError(400,'Invalid monitoring category');
            }
            const rawSuppliers = req.query.supplier == null ? [] :
                (Array.isArray(req.query.supplier) ? req.query.supplier : [req.query.supplier]);
            if (rawSuppliers.length > 500 || rawSuppliers.some(name => typeof name !== 'string' || !name.trim() || name.length > 255)) {
                throw appError(400,'Invalid supplier selection');
            }
            const suppliers = [...new Set(rawSuppliers.map(name => name.trim()))];
            const supplierCondition = suppliers.length ?
                ` AND m.supplier = ANY($${scope.args.length + 1}::text[])` : '';
            const queryArgs = suppliers.length ? [...scope.args, suppliers] : scope.args;
            const exportArgs=[...queryArgs];let categoryCondition='';
            if(categories.length){const bounds=expiryBounds();exportArgs.push(...bounds,categories);const n=exportArgs.length;
                categoryCondition=` AND (${expiryCaseSQL('m.expiration_date','$'+(n-2)+'::date','$'+(n-1)+'::date')})=ANY($${n}::text[])`;}

 
            const { rows } = await pool.query(
                `
                SELECT *
                FROM (${scopedMonitoringSQL(req.user)}) m
                WHERE ${scope.sql}${supplierCondition}${categoryCondition}
                ORDER BY
                    store_name,
                    expiration_date
                LIMIT 50001
                `,
                exportArgs
            );
 
            if(rows.length>50000)throw appError(400,'Export exceeds 50,000 stock rows. Select fewer suppliers before exporting.');
            const enrichedRows = await enrichMonitoring(pool, rows);
            const filteredRows = categories.length ? enrichedRows.filter(record => categories.includes(expiryCategory(record.expiration_date))) : enrichedRows;
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
                'Product Status': record.product_status || 'ACTIVE',
                'Employee Full Name': record.employee_name || '',
                'Store Remarks': record.store_remarks || '',
                'AS Validation': record.validation_status || '',
                'Validated By': record.validated_by || '',
                'Validation Remarks': record.validation_remarks || '',
                'Validated At': record.validated_at || '',
                'Days Remaining': expiryDays(record.expiration_date),
                'Days Overdue': Math.max(0, -expiryDays(record.expiration_date)),
                ...(req.user.role === 'ADMIN' ? {'ACTION / REMARKS': record.action_remarks || ''} : {})
            }));
 
            const archiveScope=storeScope(req.user,'ar');
            const archiveArgs=[...archiveScope.args];let archiveConditions='';
            if(suppliers.length){archiveArgs.push(suppliers);archiveConditions+=` AND ar.product_snapshot->>'supplier_name'=ANY($${archiveArgs.length}::text[])`;}
            if(categories.length){archiveArgs.push(...expiryBounds(),categories);const n=archiveArgs.length;archiveConditions+=` AND (${expiryCaseSQL("(ar.monitoring_snapshot->>'expiration_date')::date",'$'+(n-2)+'::date','$'+(n-1)+'::date')})=ANY($${n}::text[])`;}
            const archiveRows=(await pool.query(`SELECT ar.*,r.employee_name,r.store_remarks,r.validation_status,r.validated_by,r.validated_at,r.validation_remarks
                FROM public.nems_expired_archive ar LEFT JOIN public.nems_expired_status_reports r ON r.report_id=ar.source_report_id
                WHERE ${archiveScope.sql}${archiveConditions} ORDER BY ar.archived_at DESC LIMIT 50001`,archiveArgs)).rows;
            if(archiveRows.length>50000)throw appError(400,'Export exceeds 50,000 archive rows. Contact ADMIN for a separate archive export.');
            const archiveExport=archiveRows.filter(r=>(!suppliers.length||suppliers.includes(r.product_snapshot.supplier_name))&&(!categories.length||categories.includes(expiryCategory(r.monitoring_snapshot.expiration_date)))).map(r=>({
                Store:r.store_name,Supplier:r.product_snapshot.supplier_name,SKU:r.product_snapshot.sku,Product:r.product_snapshot.product_name,
                Barcode:r.product_snapshot.master_barcode,'Retail Price':r.product_snapshot.master_srp,
                'Expiration Date':r.monitoring_snapshot.expiration_date,'Quantity (Pieces)':r.monitoring_snapshot.quantity,
                Category:expiryCategory(r.monitoring_snapshot.expiration_date),'Updated By':r.archived_by,
                'Product Status':r.archive_reason,'Archive Status':r.restored_at?'RESTORED':'ARCHIVED',
                'Employee Full Name':r.employee_name||r.monitoring_snapshot.employee_history?.at(-1)?.employee_name||'',
                'Store Remarks':r.store_remarks||r.monitoring_snapshot.employee_history?.at(-1)?.remarks||'',
                'AS Validation':r.validation_status||'','Validated By':r.validated_by||'','Validation Remarks':r.validation_remarks||'',
                'Validated At':r.validated_at||'','Days Remaining':expiryDays(r.monitoring_snapshot.expiration_date),
                'Days Overdue':Math.max(0,-expiryDays(r.monitoring_snapshot.expiration_date)),
                'Archived At':r.archived_at,'Restored At':r.restored_at||'','Restored By':r.restored_by||'','Restoration Remarks':r.restore_remarks||''
            }));

    return [{name:'Monitoring',rows:records},{name:'Permanent Archive',rows:archiveExport}];
}


    try{pool=await exportPool.connect();await pool.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');return await buildMonitoringExport(workerData.request);}finally{if(pool){await pool.query('ROLLBACK').catch(()=>{});pool.release();}await exportPool.end();}
}
}else{
    function bounded(value,fallback,max){const n=Number(value);return Number.isSafeInteger(n)&&n>0?Math.min(n,max):fallback;}
    function pagination(query={}){const limit=bounded(query.limit,50,100),page=bounded(query.page,1,10000);return {limit,page,offset:(page-1)*limit};}
    async function pageQuery(pool,query,sql,args=[],order){
        const {page,limit,offset}=pagination(query),n=args.length;
        const r=await pool.query(`${sql} ORDER BY ${order} LIMIT $${n+1} OFFSET $${n+2}`,[...args,limit+1,offset]);
        return {records:r.rows.slice(0,limit),page,limit,has_more:r.rows.length>limit};
    }
    function createServices(pool,{scopeSignature=async user=>user.role+':'+(user.store_name||'')}={}){
        const jobs=new Map();let running=false;
        const cleanup=()=>{for(const [id,j] of jobs)if(j.expires<Date.now()&&!['RUNNING','QUEUED'].includes(j.state))jobs.delete(id);};
        async function pump(){
            if(running)return;const job=[...jobs.values()].find(j=>j.state==='QUEUED');if(!job)return;running=true;job.state='RUNNING';
            try{
                const payload=await job.build();
                const buffer=await new Promise((resolve,reject)=>{
                    const worker=new Worker(__filename,{workerData:{nemsExport:true,...(Array.isArray(payload)?{sheets:payload}:payload)},resourceLimits:{maxOldGenerationSizeMb:192}});
                    const timer=setTimeout(()=>{void worker.terminate();reject(new Error('Export timed out. Select fewer suppliers or expiry categories.'));},120000);timer.unref();
                    worker.once('message',data=>{clearTimeout(timer);resolve(Buffer.from(data));});worker.once('error',e=>{clearTimeout(timer);reject(e.code==='ERR_WORKER_OUT_OF_MEMORY'?new Error('Export is too large for this instance. Select fewer suppliers or categories.'):e);});worker.once('exit',()=>{clearTimeout(timer);reject(new Error('Export worker stopped. Select fewer records and try again.'));});
                });
                cleanup();const stored=[...jobs.values()].reduce((n,j)=>n+(j.buffer?.length||0),0);
                if(buffer.length>32*1024*1024||stored+buffer.length>64*1024*1024)throw new Error('Export storage is busy. Try a smaller export or retry later.');
                job.buffer=buffer;job.state='READY';
            }catch(e){job.state='FAILED';job.error=e.status?e.message:(/Export|export|Select|select/.test(e.message)?e.message:'Export could not be completed. Check server logs.');console.error('[NEMS export]',e.message);}
            finally{job.build=null;job.expires=Date.now()+10*60000;running=false;setImmediate(()=>void pump());}
        }
        function queueExport(user,scope,build){cleanup();if([...jobs.values()].some(j=>j.owner===user.email.toLowerCase()&&['QUEUED','RUNNING'].includes(j.state)))throw Object.assign(new Error('Your previous export is still running. Wait for it to finish.'),{status:409});if([...jobs.values()].filter(j=>['QUEUED','RUNNING'].includes(j.state)).length>=4)throw Object.assign(new Error('Export queue is busy. Please try again shortly.'),{status:429});
            const job={id:crypto.randomUUID(),owner:user.email.toLowerCase(),role:user.role,scope,state:'QUEUED',expires:Date.now()+10*60000,build};jobs.set(job.id,job);setImmediate(()=>void pump());return {job_id:job.id,state:job.state};}
        function getJob(user,id){cleanup();const j=jobs.get(String(id));if(!j||j.owner!==user.email.toLowerCase()||j.role!==user.role)throw Object.assign(new Error('Export expired or is unavailable. Generate it again.'),{status:404});return j;}
        const protectedWrite=req=>['POST','PUT','PATCH','DELETE'].includes(req.method)&&/^\/api\/(?:store\/monitoring$|store\/tasks\/\d+\/(?:submit|explanation|products\/\d+)$|messages$|expired\/reports(?:\/\d+\/validate)?$|archive\/\d+\/restore$|admin\/import\/confirm$|admin\/tasks(?:\/\d+(?:\/reopen)?)?$|admin\/task-groups\/\d+\/(?:reopen|cancel)$)/.test(req.path||'');
        async function idempotency(req,res,next){
            if(!protectedWrite(req))return next();
            const key=req.get('Idempotency-Key');if(!key)return next();
            if(!/^[a-zA-Z0-9-]{16,80}$/.test(key))return res.status(400).json({error:'Invalid request key'});
            const owner=req.user.email.toLowerCase(),route=req.method+' '+req.path;
            try{
                const scope=await scopeSignature(req.user);
                const hash=crypto.createHash('sha256').update(JSON.stringify([req.body||{},scope])).digest('hex');
                const claim=await pool.query(`INSERT INTO public.nems_request_keys(owner_email,request_key,route,body_hash) VALUES($1,$2,$3,$4) ON CONFLICT(owner_email,request_key) DO NOTHING RETURNING request_key`,[owner,key,route,hash]);
                if(!claim.rowCount){const row=(await pool.query('SELECT * FROM public.nems_request_keys WHERE owner_email=$1 AND request_key=$2',[owner,key])).rows[0];
                    if(!row||row.route!==route||row.body_hash!==hash)return res.status(409).json({error:'Request key belongs to another operation. Refresh the record before saving.'});
                    if(row.state==='COMPLETE')return res.status(row.status_code).json(row.response);
                    return res.status(409).json({error:'This save is processing or its result needs verification. Refresh the record before sending another save.',request_pending:true});
                }
                const json=res.json.bind(res);res.json=function(body){
                    const status=res.statusCode||200;
                    // Commit the response record before acknowledging success. A crash leaves PENDING rather than rerunning a possibly committed write.
                    return pool.query(`UPDATE public.nems_request_keys SET state='COMPLETE',status_code=$3,response=$4::jsonb,completed_at=NOW() WHERE owner_email=$1 AND request_key=$2`,[owner,key,status,JSON.stringify(body)]).then(()=>json(body)).catch(e=>{console.error('[NEMS request result]',e.code||e.message);res.status(503);return json({error:'The save result could not be confirmed. Refresh the record before retrying.',request_pending:true});});
                };
                return next();
            }catch(e){console.error('[NEMS request key]',e.code||e.message);return res.status(503).json({error:'Save protection is unavailable. Check that the NEMS scaling SQL has been installed.'});}
        }
        return {queueExport,getJob,idempotency,stats:()=>({queued:[...jobs.values()].filter(j=>j.state==='QUEUED').length,running:running?1:0,ready:[...jobs.values()].filter(j=>j.state==='READY').length})};
    }
    module.exports={pagination,pageQuery,createServices};
}
