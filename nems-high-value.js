'use strict';

const XLSX = require('xlsx');
const seed = require('./nems-high-value-seed.json');
const prefix = '/api/high-value';
function nameTerms(name) {
    return [...new Set(String(name||'').toLowerCase().match(/[a-z0-9]+/g)||[])];
}
function column(value) {
    return String(value??'').toLowerCase().replace(/[^a-z0-9]/g,'');
}
const systemImportHeaders = {
    sku:['stock','stockno','stocknumber','sku'],
    barcode:['barcode','masterbarcode'],
    description:['description','productname','itemdescription'],
    quantity:['onhandpcs','onhandpc','onhandpieces','onhand'],
    status:['status','itemstatus','productstatus','activestatus']
};
function systemImportHeader(row) {
    const headers = row.map(column);
    return Object.fromEntries(Object.entries(systemImportHeaders)
        .map(([field,choices])=>[field,headers.findIndex(header=>choices.includes(header))]));
}
function normalizedDescription(value) {
    return String(value??'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
}
const shifts = ['OPENING', 'CLOSING'];
const managers = ['AS', 'AOM'];
const editors = ['ADMIN', 'OPC', 'IC'];
const transferRoles = [...editors, ...managers];
const allStores = [...editors, 'HEAD'];
const storeQuery = `SELECT s.store_id,s.store_name,s.store_email,
    COALESCE(h.status,CASE WHEN s.status='ACTIVE' THEN 'ACTIVE' ELSE 'CLOSED' END) AS inventory_status,
    a.email AS as_email,a.full_name AS as_name,b.email AS aom_email,b.full_name AS aom_name
    FROM public.stores s LEFT JOIN public.nems_hv_stores h USING(store_id)
    LEFT JOIN LATERAL (
        SELECT u.email,u.full_name FROM public.as_store_assignments x JOIN public.users u
            ON lower(u.email)=lower(x.as_email) WHERE x.store_id=s.store_id AND u.role='AS'
            ORDER BY u.email LIMIT 1
    ) a ON true
    LEFT JOIN LATERAL (
        SELECT u.email,u.full_name FROM public.aom_store_assignments x JOIN public.users u
            ON lower(u.email)=lower(x.aom_email) WHERE x.store_id=s.store_id AND u.role='AOM'
            ORDER BY u.email LIMIT 1
    ) b ON true`;

const expectedProducts = `
    SELECT product_id FROM public.nems_hv_days WHERE inventory_date=$1 AND store_id=$2
    UNION ALL
    SELECT product_id FROM public.nems_hv_products WHERE active
    AND NOT EXISTS (SELECT 1 FROM public.nems_hv_days WHERE inventory_date=$1 AND store_id=$2)`;

module.exports = function register({app,pool,authenticate,secureRoute,transaction,appError,accessibleStores,businessDate,notify}) {
    function route(method,path,handler) {
        app[method](prefix+path,authenticate,secureRoute(async(req,res)=>{
            res.set('Cache-Control','no-store');
            await handler(req,res);
        }));
    }

    function validateId(value) {
        if (!/^\d{1,18}$/.test(String(value)) || BigInt(value) < 1n) throw appError(400,'Invalid ID');
        return String(BigInt(value));
    }

    function inventoryDate(value) {
        const parsed = new Date(value+'T00:00:00Z');
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || !Number.isFinite(+parsed) ||
            parsed.toISOString().slice(0,10)!==value || value>businessDate()) {
            throw appError(400,'Choose today or an earlier inventory date');
        }
        return value;
    }

    function requireEditor(user) {
        if (!editors.includes(user.role)) throw appError(403,'IC or OPC access required');
    }

    async function listStores(client,user) {
        if (allStores.includes(user.role)) return (await client.query(storeQuery+' ORDER BY s.store_name')).rows;
        const allowed = await accessibleStores(client,user);
        return (await client.query(storeQuery+' WHERE s.store_id=ANY($1::bigint[]) ORDER BY s.store_name',
            [allowed.map(s=>s.store_id)])).rows;
    }

    async function store(client,user,id) {
        const found = (await listStores(client,user)).find(s=>String(s.store_id)===id);
        if (!found) throw appError(403,'Store is outside your assignments');
        return found;
    }

    function recordFile(client,user,id,day,shift,action,filename,count,key=null) {
        return client.query(`INSERT INTO public.nems_hv_file_history
            (store_id,inventory_date,shift,action,filename,row_count,actor,actor_role,import_key)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,day,shift,action,filename,count,user.email,user.role,key]);
    }

    route('get','/file-history',async(req,res)=>{
        requireEditor(req.user);
        const id = validateId(req.query.store);
        const day = inventoryDate(req.query.date);
        await store(pool,req.user,id);
        const {rows} = await pool.query(`SELECT shift,action,filename,row_count,actor,actor_role,recorded_at
            FROM public.nems_hv_file_history WHERE store_id=$1 AND inventory_date=$2
            ORDER BY event_id DESC LIMIT 250`,[id,day]);
        res.json(rows);
    });

    route('get','/stores',async(req,res)=>res.json(await listStores(pool,req.user)));

    route('get','/managers',async(req,res)=>{
        requireEditor(req.user);
        res.json((await pool.query("SELECT email,full_name,role FROM public.users WHERE role IN ('AS','AOM') AND status='ACTIVE' ORDER BY full_name,email")).rows);
    });

    route('patch','/stores/:storeId',async(req,res)=>{
        requireEditor(req.user);
        const id = validateId(req.params.storeId);
        const {status,as_email,aom_email} = req.body || {};
        if (!['PIPELINE','ACTIVE','CLOSED'].includes(status)) throw appError(400,'Choose a store status');
        await transaction(async c=>{
            const locked = await c.query('SELECT store_id FROM public.stores WHERE store_id=$1 FOR UPDATE',[id]);
            if (!locked.rowCount) throw appError(404,'Store not found');
            for (const [role,table,column,mail] of [
                ['AS','as_store_assignments','as_email',as_email],
                ['AOM','aom_store_assignments','aom_email',aom_email]
            ]) {
                if (typeof mail!=='string') throw appError(400,'Select a manager or Unassigned');
                let email;
                if (mail) {
                    const result = await c.query("SELECT email FROM public.users WHERE lower(email)=lower($1) AND role=$2 AND status='ACTIVE' FOR SHARE",[mail,role]);
                    if (result.rowCount!==1) throw appError(400,'Select an active '+role);
                    email = result.rows[0].email;
                }
                await c.query(`DELETE FROM public.${table} WHERE store_id=$1`,[id]);
                if (email) await c.query(`INSERT INTO public.${table}(store_id,${column}) VALUES($1,$2)`,[id,email]);
            }
            await c.query(`INSERT INTO public.nems_hv_stores(store_id,status) VALUES($1,$2)
                ON CONFLICT(store_id) DO UPDATE SET status=excluded.status`,[id,status]);
        });
        res.json({saved:true});
    });

    route('get','/products',async(req,res)=>{
        requireEditor(req.user);
        const search = String(req.query.q||'').trim().slice(0,120);
        const products = (await pool.query(`SELECT p.product_id,p.sku,p.product_name,p.master_barcode,h.active
            FROM public.products p LEFT JOIN public.nems_hv_products h USING(product_id)
            WHERE ($1<>'' AND position(lower($1) in lower(concat_ws(' ',p.sku,p.product_name,p.master_barcode)))>0)
                OR ($1='' AND h.product_id IS NOT NULL)
            ORDER BY h.active DESC NULLS LAST,p.product_name LIMIT 250`,[search])).rows;
        const states = (await pool.query("SELECT sku,state FROM public.nems_hv_seed WHERE state<>'MATCHED' ORDER BY sku")).rows;
        res.json({products,review:states.map(row=>({...seed.find(x=>x.sku===row.sku),...row}))});
    });

    route('put','/products/:productId',async(req,res)=>{
        requireEditor(req.user);
        const id = validateId(req.params.productId);
        const {active,seed_sku} = req.body || {};
        if (typeof active!=='boolean' || (seed_sku && (!active || !seed.some(row=>row.sku===seed_sku)))) {
            throw appError(400,'Choose a product status and valid workbook row');
        }
        await transaction(async c=>{
            if (seed_sku) {
                const review = await c.query(`SELECT sku FROM public.nems_hv_seed
                    WHERE sku=$1 AND state<>'MATCHED' FOR UPDATE`,[seed_sku]);
                if (!review.rowCount) throw appError(409,'This workbook row has already been resolved. Refresh the list.');
            }
            const result = await c.query(`INSERT INTO public.nems_hv_products(product_id,active)
                SELECT product_id,$2 FROM public.products WHERE product_id=$1
                ON CONFLICT(product_id) DO UPDATE SET active=excluded.active,changed_at=now()`,[id,active]);
            if (!result.rowCount) throw appError(404,'Product not found');
            if (seed_sku) await c.query("UPDATE public.nems_hv_seed SET state='MATCHED',product_id=$2 WHERE sku=$1",[seed_sku,id]);
            if (active) await c.query(`INSERT INTO public.nems_hv_days(inventory_date,store_id,product_id)
                SELECT DISTINCT inventory_date,store_id,$2::bigint FROM public.nems_hv_days WHERE inventory_date=$1
                ON CONFLICT DO NOTHING`,[businessDate(),id]);
        });
        res.json({saved:true});
    });

    route('post','/seed',async(req,res)=>{
        requireEditor(req.user);
        await transaction(async c=>{
            const added = await c.query(`WITH source AS (
                SELECT * FROM jsonb_to_recordset($1::jsonb) AS s(sku text,barcode text,name text)
            ), matches AS (
                SELECT s.sku,COUNT(DISTINCT p.product_id) AS candidates,MIN(p.product_id) AS product_id,
                    COUNT(DISTINCT p.product_id) FILTER (
                        WHERE trim(p.sku::text)=s.sku AND s.barcode<>'' AND trim(p.master_barcode::text)=s.barcode
                    ) AS exact_candidates,
                    MIN(p.product_id) FILTER (
                        WHERE trim(p.sku::text)=s.sku AND s.barcode<>'' AND trim(p.master_barcode::text)=s.barcode
                    ) AS exact_product_id
                FROM source s LEFT JOIN public.products p ON trim(p.sku::text)=s.sku
                    OR (s.barcode<>'' AND trim(p.master_barcode::text)=s.barcode)
                GROUP BY s.sku
            ), proposed AS (
                SELECT sku,candidates,CASE WHEN exact_candidates=1 THEN exact_product_id
                    WHEN candidates=1 THEN product_id END AS picked
                FROM matches
            ), reviewed AS (
                SELECT p.sku,p.candidates,CASE WHEN NOT EXISTS (
                    SELECT 1 FROM public.nems_hv_rejections r WHERE r.sku=p.sku AND r.product_id=p.picked
                ) THEN p.picked END AS picked FROM proposed p
            ), recorded AS (
                INSERT INTO public.nems_hv_seed(sku,product_id,state)
                SELECT sku,picked,
                    CASE WHEN picked IS NOT NULL THEN 'MATCHED' WHEN candidates=0 THEN 'UNMATCHED' ELSE 'AMBIGUOUS' END
                FROM reviewed ON CONFLICT(sku) DO UPDATE SET product_id=excluded.product_id,state=excluded.state
                    WHERE public.nems_hv_seed.state<>'MATCHED' RETURNING product_id
            )
            INSERT INTO public.nems_hv_products(product_id)
            SELECT DISTINCT product_id FROM recorded WHERE product_id IS NOT NULL ON CONFLICT DO NOTHING
            RETURNING product_id`,[JSON.stringify(seed)]);
            if (added.rows.length) await c.query(`INSERT INTO public.nems_hv_days(inventory_date,store_id,product_id)
                SELECT DISTINCT d.inventory_date,d.store_id,p.product_id FROM public.nems_hv_days d
                CROSS JOIN unnest($2::bigint[]) p(product_id) WHERE d.inventory_date=$1
                ON CONFLICT DO NOTHING`,[businessDate(),added.rows.map(row=>row.product_id)]);
        });
        const states = (await pool.query('SELECT state,COUNT(*)::int AS count FROM public.nems_hv_seed GROUP BY state')).rows;
        const totals = Object.fromEntries(states.map(row=>[row.state,row.count]));
        res.json({reviewed:seed.length,matched:totals.MATCHED||0,ambiguous:totals.AMBIGUOUS||0,unmatched:totals.UNMATCHED||0});
    });

    route('get','/suggestions',async(req,res)=>{
        requireEditor(req.user);
        const source = seed.find(row=>row.sku===req.query.sku);
        if (!source) throw appError(404,'Workbook item not found');
        const terms = nameTerms(source.name);
        const {rows} = await pool.query(`SELECT p.product_id,p.sku,p.product_name,p.master_barcode,
            p.supplier_name,trim(p.sku::text)=$1 AS same_sku,
            ($2<>'' AND trim(p.master_barcode::text)=$2) AS same_barcode,
            COALESCE(h.active,false) AS active
            FROM public.products p LEFT JOIN public.nems_hv_products h USING(product_id)
            WHERE (trim(p.sku::text)=$1 OR ($2<>'' AND trim(p.master_barcode::text)=$2)
                OR lower(p.product_name) LIKE $3)
            AND NOT EXISTS (SELECT 1 FROM public.nems_hv_rejections r WHERE r.sku=$1 AND r.product_id=p.product_id)
            ORDER BY (trim(p.sku::text)=$1 OR ($2<>'' AND trim(p.master_barcode::text)=$2)) DESC,
                p.product_name,p.product_id LIMIT 250`,[source.sku,source.barcode,terms.length?'%'+terms[0]+'%':null]);
        const proposals = rows.map(row=>{
            const words = nameTerms(row.product_name);
            const score = terms.filter(word=>words.includes(word)).length / (new Set([...terms,...words]).size||1);
            return {...row,score};
        }).filter(row=>row.same_sku||row.same_barcode||row.score>=0.3)
            .sort((a,b)=>Number(b.same_barcode)-Number(a.same_barcode)||
                Number(b.same_sku)-Number(a.same_sku)||b.score-a.score);
        res.json({source,proposals:proposals.slice(0,12)});
    });

    route('post','/reject-match',async(req,res)=>{
        requireEditor(req.user);
        const sku = req.body?.sku;
        const id = validateId(req.body?.product_id);
        if (!seed.some(row=>row.sku===sku)) throw appError(404,'Workbook item not found');
        await pool.query(`INSERT INTO public.nems_hv_rejections(sku,product_id,rejected_by)
            SELECT $1,product_id,$3 FROM public.products WHERE product_id=$2
            ON CONFLICT(sku,product_id) DO NOTHING`,[sku,id,req.user.email]);
        res.json({saved:true});
    });

    route('post','/import-system',async(req,res)=>{
        if (!transferRoles.includes(req.user.role)) throw appError(403,'System-count import is unavailable for this role');
        const params = req.body || {};
        const id = validateId(params.store_id);
        const day = inventoryDate(params.date);
        if (!shifts.includes(params.shift)) throw appError(400,'Select Opening or Closing');
        const selected = await store(pool,req.user,id);
        const {rows:catalog} = await pool.query(`SELECT p.product_id,p.sku,p.master_barcode,p.product_name
            FROM (${expectedProducts}) expected JOIN public.products p USING(product_id)
            WHERE $3 OR EXISTS (SELECT 1 FROM public.nems_hv_days WHERE inventory_date=$1 AND store_id=$2)`,
            [day,id,selected.inventory_status==='ACTIVE']);
        if (!catalog.length) throw appError(409,'No high-value products are available for this store and date');
        const filename = String(params.filename||'').split(/[\\/]/).pop().trim();
        const data = params.file_base64;
        if (filename.length>255 || !/\.xlsx?$/i.test(filename) || typeof data!=='string'||data.length>4200000) {
            throw appError(400,'Choose an Excel file (.xlsx or .xls) under 3 MB');
        }
        let workbook;
        try {
            workbook = XLSX.read(Buffer.from(data,'base64'),{type:'buffer',sheetRows:5002});
        } catch {
            throw appError(400,'Could not read this Excel workbook');
        }
        const byShift = workbook.SheetNames.filter(name=>shifts.includes(name.trim().toUpperCase()));
        const sheetName = byShift.find(name=>name.trim().toUpperCase()===params.shift)||
            (!byShift.length?workbook.SheetNames[0]:null);
        if (!sheetName) throw appError(400,'This workbook does not contain a '+params.shift.toLowerCase()+' sheet');
        const sheet = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName],{header:1,raw:true,defval:null,blankrows:true});
        if (sheet.length>5000) throw appError(400,'Use a file with at most 5,000 rows');
        const header = sheet.findIndex(row=>{
            const columns = systemImportHeader(row);
            return columns.sku>=0 && columns.quantity>=0;
        });
        if (header<0) throw appError(400,'The worksheet needs Stock No. or SKU, and On-hand (Pcs)');
        const columns = systemImportHeader(sheet[header]);
        const cell = (row,key)=>row[columns[key]];
        const proposed = new Map();
        const duplicates = new Set();
        const issues = [];
        let ignored = 0, inactive = 0;
        for (const [index,row] of sheet.entries()) {
            if (index<=header) continue;
            const sku = String(cell(row,'sku')??'').trim();
            const barcode = String(cell(row,'barcode')??'').trim();
            if (!sku&&!barcode) continue;
            const status = column(cell(row,'status'));
            if (status && !['a','active'].includes(status)) { inactive++; continue; }
            const description = normalizedDescription(cell(row,'description'));
            const bySku = catalog.filter(p=>sku && String(p.sku??'').trim()===sku);
            const byBarcode = catalog.filter(p=>barcode && String(p.master_barcode??'').trim()===barcode);
            const both = bySku.filter(p=>byBarcode.includes(p));
            const matches = both.length?both:bySku.length&&byBarcode.length?[]:byBarcode.length?byBarcode:bySku;
            const sameName = description?matches.filter(p=>normalizedDescription(p.product_name)===description):[];
            const candidates = matches.length>1&&sameName.length?sameName:matches;
            if (!bySku.length&&!byBarcode.length) { ignored++; continue; }
            const raw = cell(row,'quantity');
            const quantity = typeof raw==='number'?raw:/^(?:\d+|\d{1,3}(?:,\d{3})+)$/.test(String(raw??'').trim())?
                Number(String(raw).replaceAll(',','')):NaN;
            const at = 'Row '+(index+1)+' ('+(sku||barcode)+')';
            if (candidates.length!==1) { issues.push(at+': conflicting or multiple product matches'); continue; }
            if (!Number.isInteger(quantity)||quantity<0||quantity>2147483647) {
                issues.push(at+': enter a nonnegative whole number in On-hand (Pcs)'); continue;
            }
            const product = candidates[0];
            const key = String(product.product_id);
            if (proposed.has(key)||duplicates.has(key)) {
                proposed.delete(key);
                duplicates.add(key);
                issues.push(at+': duplicate product, both quantities excluded');
                continue;
            }
            proposed.set(key,{...product,value:quantity});
        }
        const counts = [...proposed.values()];
        if (params.confirm===true) {
            if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(params.import_key||'')) {
                throw appError(400,'Preview the workbook again before saving');
            }
            const confirmed = counts.map(row=>[String(row.product_id),row.value]);
            if (JSON.stringify(confirmed)!==JSON.stringify(params.preview_counts)) {
                throw appError(409,'The product matches changed. Preview the workbook again.');
            }
            await saveCounts(req,{store_id:id,date:day,shift:params.shift,counts},{filename,key:params.import_key});
            return res.json({saved:true,row_count:counts.length});
        }
        res.json({counts,issues:issues.slice(0,30),issue_count:issues.length,ignored,inactive});
    });

    route('get','/counts',async(req,res)=>{
        const id = validateId(req.query.store);
        const day = inventoryDate(req.query.date);
        const selected = await store(pool,req.user,id);
        const showSystem = req.user.role!=='STORE';
        const result = await pool.query(`SELECT p.product_id,p.sku,p.product_name,p.master_barcode,shift.name AS shift,
            c.actual,c.counted_by,CASE WHEN $3 THEN c.system_count END AS system_count,
            CASE WHEN $3 THEN c.actual-c.system_count END AS variance,
            CASE WHEN c.actual<c.system_count THEN 'Short' WHEN c.actual>c.system_count THEN 'Over'
                WHEN c.actual=c.system_count THEN 'Matched' END AS variance_status
            FROM (${expectedProducts}) expected JOIN public.products p USING(product_id)
            CROSS JOIN (VALUES ('OPENING'),('CLOSING')) shift(name)
            LEFT JOIN public.nems_hv_counts c ON c.inventory_date=$1 AND c.store_id=$2
                AND c.product_id=p.product_id AND c.shift=shift.name
            WHERE $4 OR EXISTS (SELECT 1 FROM public.nems_hv_days WHERE inventory_date=$1 AND store_id=$2)
            ORDER BY p.product_name,p.product_id,shift.name DESC`,[day,id,showSystem,selected.inventory_status==='ACTIVE']);
        if (req.query.format==='xlsx') {
            const shift = req.query.shift;
            const template = req.query.template==='1';
            if (!shifts.includes(shift) && (shift!=='BOTH'||template)) throw appError(400,'Select a shift');
            if (req.user.role==='HEAD'||(template&&!transferRoles.includes(req.user.role))) {
                throw appError(403,'This download is unavailable for this role');
            }
            const chosenShifts = shift==='BOTH'?shifts:[shift];
            const heading = template?['Stock #','Barcode','Description','On-hand (Pcs)','Price (SRP)','Actual Cost','Total Price (SRP)']:
                ['Stock #','Barcode','Description','Counted by','Actual (Pcs)',...(showSystem?['System (Pcs)']:[]),'Variance'];
            const workbook = XLSX.utils.book_new();
            const exported = new Map();
            for (const name of chosenShifts) {
                const rows = result.rows.filter(row=>row.shift===name);
                const data = rows.map(row=>{
                    const product = [String(row.sku??''),String(row.master_barcode??''),row.product_name];
                    return template ? [...product,null,null,null,null] :
                        [...product,row.counted_by,row.actual,...(showSystem?[row.system_count]:[]),showSystem?row.variance:row.variance_status];
                });
                XLSX.utils.book_append_sheet(workbook,XLSX.utils.aoa_to_sheet([heading,...data]),name);
                exported.set(name,rows.length);
            }
            const filename = 'NEMS_'+(template?'System_Template':'Counts')+'_'+day+'_'+shift+'.xlsx';
            const buffer = XLSX.write(workbook,{type:'buffer',bookType:'xlsx'});
            await transaction(async c=>{
                for (const [name,count] of exported) {
                    await recordFile(c,req.user,id,day,name,template?'TEMPLATE':'EXPORT',filename,count);
                }
            });
            res.set({'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'Content-Disposition':'attachment; filename="'+filename+'"'});
            return res.send(buffer);
        }
        res.json({rows:result.rows,showSystem,canEdit:!showSystem||managers.includes(req.user.role),canSave:result.rowCount>0,canImport:transferRoles.includes(req.user.role),canExport:req.user.role!=='HEAD',store:selected});
    });

    async function saveCounts(req,body,imported=null) {
        const {store_id,date,shift,counts,counted_by} = body || {};
        const id = validateId(store_id);
        const day = inventoryDate(date);
        const actual = req.user.role==='STORE';
        if (!actual && !(imported?transferRoles:managers).includes(req.user.role)) throw appError(403,'Count entry is unavailable for this role');
        const leader = actual ? String(counted_by||'').trim() : null;
        if (!shifts.includes(shift) || !Array.isArray(counts) || !counts.length || counts.length>500 ||
            (actual && (!leader || leader.length>120))) throw appError(400,'Choose a shift and enter counts and the shift leader name where required');
        const values = new Map();
        for (const row of counts) {
            const product = validateId(row?.product_id);
            if (!Number.isInteger(row.value) || row.value<0 || row.value>2147483647 || values.has(product)) {
                throw appError(400,'Enter one whole, nonnegative quantity per product');
            }
            values.set(product,row.value);
        }
        await transaction(async c=>{
            await c.query('SELECT store_id FROM public.stores WHERE store_id=$1 FOR UPDATE',[id]);
            const selected = await store(c,req.user,id);
            if (imported) {
                const prior = await c.query(`SELECT 1 FROM public.nems_hv_file_history
                    WHERE import_key=$1 AND actor=$2 AND store_id=$3 AND inventory_date=$4 AND shift=$5`,
                    [imported.key,req.user.email,id,day,shift]);
                if (prior.rowCount) return;
            }
            const {rows} = await c.query(expectedProducts,[day,id]);
            const existing = await c.query('SELECT 1 FROM public.nems_hv_days WHERE inventory_date=$1 AND store_id=$2 LIMIT 1',[day,id]);
            if (!existing.rowCount && selected.inventory_status!=='ACTIVE') throw appError(409,'This store is outside the active inventory program');
            const allowed = new Set(rows.map(row=>String(row.product_id)));
            if ([...values.keys()].some(key=>!allowed.has(key))) throw appError(409,'The item list changed. Reload the counts.');
            if (!existing.rowCount) await c.query(`INSERT INTO public.nems_hv_days(inventory_date,store_id,product_id)
                SELECT $1,$2,unnest($3::bigint[])`,[day,id,[...allowed]]);
            const field = actual?'actual':'system_count';
            await c.query(`WITH incoming AS (
                SELECT * FROM jsonb_to_recordset($5::jsonb) AS x(product_id bigint,value integer)
            ), audited AS (
                INSERT INTO public.nems_hv_history(inventory_date,store_id,product_id,shift,actor,field,old_value,new_value,old_counted_by,new_counted_by)
                SELECT $1,$2,x.product_id,$3,$4,'${field}',c.${field},x.value,
                    CASE WHEN $6::text IS NOT NULL THEN c.counted_by END,$6
                FROM incoming x LEFT JOIN public.nems_hv_counts c ON c.inventory_date=$1 AND c.store_id=$2
                    AND c.product_id=x.product_id AND c.shift=$3
                WHERE c.${field} IS DISTINCT FROM x.value OR ($6 IS NOT NULL AND c.counted_by IS DISTINCT FROM $6)
                RETURNING product_id,new_value
            )
            INSERT INTO public.nems_hv_counts(inventory_date,store_id,product_id,shift,${field},counted_by)
            SELECT $1,$2,product_id,$3,new_value,$6 FROM audited
            ON CONFLICT(inventory_date,store_id,product_id,shift)
            DO UPDATE SET ${field}=excluded.${field},counted_by=COALESCE(excluded.counted_by,nems_hv_counts.counted_by)`,
            [day,id,shift,req.user.email,JSON.stringify([...values].map(([product_id,value])=>({product_id,value}))),leader]);
            if (imported) await recordFile(c,req.user,id,day,shift,'IMPORT',imported.filename,values.size,imported.key);
        });
    }

    route('put','/counts',async(req,res)=>{
        await saveCounts(req,req.body);
        res.json({saved:true});
    });

    route('get','/history',async(req,res)=>{
        const id = validateId(req.query.store);
        const day = inventoryDate(req.query.date);
        await store(pool,req.user,id);
        const result = await pool.query(`SELECT h.*,p.product_name FROM public.nems_hv_history h
            LEFT JOIN public.products p USING(product_id)
            WHERE h.inventory_date=$1 AND h.store_id=$2 AND ($3 OR h.field='actual')
            ORDER BY h.id DESC LIMIT 250`,[day,id,req.user.role!=='STORE']);
        res.json(result.rows);
    });

    async function compliance(client,day,stores,cutoff=false) {
        if (!stores.length) return [];
        const result = await client.query(`WITH expected AS (
            SELECT d.store_id,d.product_id FROM public.nems_hv_days d WHERE d.inventory_date=$1 AND d.store_id=ANY($2::bigint[])
            UNION ALL
            SELECT s.id,p.product_id FROM unnest($2::bigint[]) s(id) CROSS JOIN public.nems_hv_products p
            WHERE p.active AND NOT EXISTS (SELECT 1 FROM public.nems_hv_days d WHERE d.inventory_date=$1 AND d.store_id=s.id)
        ), done AS (
            SELECT store_id,product_id,shift,field FROM public.nems_hv_history
            WHERE inventory_date=$1 AND store_id=ANY($2::bigint[])
                AND (NOT $3 OR saved_at < (($1::date+1)::timestamp AT TIME ZONE 'Asia/Manila'))
            GROUP BY store_id,product_id,shift,field
        )
        SELECT e.store_id,COUNT(*)::int AS expected,
            COUNT(*) FILTER(WHERE done.field IS NULL AND shift.name='OPENING' AND field.name='actual')::int AS opening_actual,
            COUNT(*) FILTER(WHERE done.field IS NULL AND shift.name='OPENING' AND field.name='system_count')::int AS opening_system,
            COUNT(*) FILTER(WHERE done.field IS NULL AND shift.name='CLOSING' AND field.name='actual')::int AS closing_actual,
            COUNT(*) FILTER(WHERE done.field IS NULL AND shift.name='CLOSING' AND field.name='system_count')::int AS closing_system
        FROM expected e CROSS JOIN (VALUES ('OPENING'),('CLOSING')) shift(name)
        CROSS JOIN (VALUES ('actual'),('system_count')) field(name)
        LEFT JOIN done ON done.store_id=e.store_id AND done.product_id=e.product_id AND done.shift=shift.name AND done.field=field.name
        GROUP BY e.store_id`,[day,stores.map(s=>s.store_id),cutoff]);
        const byStore = new Map(result.rows.map(row=>[String(row.store_id),row]));
        return stores.filter(s=>byStore.has(String(s.store_id))).map(s=>({...s,...byStore.get(String(s.store_id))}));
    }

    route('get','/compliance',async(req,res)=>{
        const day = inventoryDate(req.query.date);
        const stores = (await listStores(pool,req.user)).filter(s=>s.inventory_status==='ACTIVE');
        res.json(await compliance(pool,day,stores));
    });

    async function remind() {
        await transaction(async c=>{
            const ready = await c.query("SELECT to_regclass('public.nems_hv_reminder_runs') AS table_name");
            if (!ready.rows[0].table_name) return;
            const day = (await c.query("SELECT ((now() AT TIME ZONE 'Asia/Manila')::date-1)::text AS day")).rows[0].day;
            const claimed = await c.query('INSERT INTO public.nems_hv_reminder_runs(inventory_date) VALUES($1) ON CONFLICT DO NOTHING RETURNING inventory_date',[day]);
            if (!claimed.rowCount) return;
            const stores = (await c.query(storeQuery+" WHERE COALESCE(h.status,CASE WHEN s.status='ACTIVE' THEN 'ACTIVE' ELSE 'CLOSED' END)='ACTIVE'")).rows;
            const recipients = new Map();
            const activeManagers = new Set((await c.query("SELECT lower(email) AS email FROM public.users WHERE role IN ('AS','AOM') AND status='ACTIVE'")).rows.map(r=>r.email));
            for (const row of await compliance(c,day,stores,true)) {
                const missing = [['Opening Actual',row.opening_actual],['Opening System',row.opening_system],
                    ['Closing Actual',row.closing_actual],['Closing System',row.closing_system]].filter(([,count])=>count);
                if (!missing.length) continue;
                for (const email of new Set([row.as_email,row.aom_email].filter(Boolean).map(mail=>mail.toLowerCase()))) {
                    if (!activeManagers.has(email)) continue;
                    if (!recipients.has(email)) recipients.set(email,[]);
                    recipients.get(email).push(row.store_name+' — '+missing.map(([label,n])=>label+': '+n).join(', '));
                }
            }
            for (const [email,lines] of recipients) {
                await notify(c,email,null,'OVERDUE','High-value inventory · '+day,
                    'Counts missing at midnight Philippine time.\n'+lines.join('\n'),'HIGH_VALUE',null,false);
            }
        });
    }

    return {remind,start(){
        const tick = ()=>remind().catch(error=>console.error('[High-value reminder]',error.code||error.message));
        void tick();
        setInterval(tick,30000).unref();
    }};
};
