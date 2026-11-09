'use strict';
const crypto=require('crypto');
const fault=(status,message)=>Object.assign(new Error(message),{status});
const normalize=v=>String(v||'').normalize('NFKC').trim().replace(/\s+/g,' ').toUpperCase();
const barcode=v=>normalize(v).replace(/\s+/g,'');
const possiblePack=name=>/(?:[x×]\s*\d+)|(?:^|[^a-z0-9])(?:case|cs|box|carton|ctn|pack|pk)(?=$|[^a-z])/i.test(String(name||''));
const idsOf=raw=>{
 if(!Array.isArray(raw)||!raw.length||raw.length>500)throw fault(400,'Choose 1-500 suppliers');
 const ids=[...new Set(raw.map(Number))];if(ids.some(v=>!Number.isSafeInteger(v)||v<1))throw fault(400,'Invalid supplier IDs');return ids.sort((a,b)=>a-b);
};
const key=p=>barcode(p.master_barcode)&&normalize(p.product_name)?normalize(p.supplier_name)+'|'+normalize(p.product_name)+'|'+barcode(p.master_barcode):null;
function analyze(rows,supplierIds){
 const sorted=[...rows].sort((a,b)=>Number(a.product_id)-Number(b.product_id));const groups=new Map();
 for(const p of sorted){const k=key(p);if(k){if(!groups.has(k))groups.set(k,[]);groups.get(k).push(p);}}
 const candidates=sorted.filter(p=>possiblePack(p.product_name)||(key(p)&&groups.get(key(p)).length>1)).map(p=>{
  const group=key(p)?groups.get(key(p)):[];const duplicate=group.length>1;
  const visible=group.filter(x=>x.store_task_visible===true);const keeper=visible[0];
  return {...p,possible_pack:possiblePack(p.product_name),duplicate_group:duplicate?crypto.createHash('sha256').update(key(p)).digest('hex').slice(0,24):null,
   suggested_visible:duplicate&&visible.length>1?Number(p.product_id)===Number(keeper.product_id):p.store_task_visible===true};
 });
 const token=crypto.createHash('sha256').update(JSON.stringify([supplierIds,sorted.map(p=>[p.product_id,p.supplier_id,p.product_name,p.master_barcode,p.sku,p.landed_cost,p.store_task_visible,p.revision])])).digest('hex');
 return {token,products:candidates,total_products:rows.length};
}
async function readProducts(c,ids,lock=false){
 const result=await c.query(`SELECT p.product_id,p.sku,p.product_name,p.supplier_name,p.master_barcode,p.landed_cost,p.store_task_visible,p.xmin::text AS revision,
   (SELECT MIN(sp.supplier_id) FROM public.suppliers sp WHERE sp.supplier_id=ANY($1::bigint[]) AND LOWER(TRIM(sp.supplier_name))=LOWER(TRIM(p.supplier_name))) AS supplier_id
   FROM public.products p WHERE p.status='ACTIVE' AND EXISTS(SELECT 1 FROM public.suppliers sp WHERE sp.supplier_id=ANY($1::bigint[]) AND LOWER(TRIM(sp.supplier_name))=LOWER(TRIM(p.supplier_name)))
   ORDER BY p.product_id ${lock?'FOR UPDATE OF p':''}`,[ids]);return result.rows;
}
async function applyReview(c,review,ids){
 ids=idsOf(ids);
 const rows=await readProducts(c,ids,true),expected=analyze(rows,ids);
 if(!review||review.token!==expected.token||!Array.isArray(review.decisions))throw fault(409,'Product list changed or review is missing. Open the pack/duplicate review again.');
 const decisions=new Map();for(const r of review.decisions){if(!r||!Number.isSafeInteger(Number(r.product_id))||typeof r.visible!=='boolean'||decisions.has(Number(r.product_id)))throw fault(400,'Invalid visibility choices');decisions.set(Number(r.product_id),r.visible);}
 if(decisions.size!==expected.products.length||expected.products.some(p=>!decisions.has(Number(p.product_id))))throw fault(409,'Review every suggested pack and duplicate product before creating tasks.');
 const visibleDuplicates=new Set();for(const p of expected.products){if(p.duplicate_group&&decisions.get(Number(p.product_id))){if(visibleDuplicates.has(p.duplicate_group))throw fault(400,'Keep only one visible record for each exact duplicate group.');visibleDuplicates.add(p.duplicate_group);}}
 for(const supplierId of ids){const products=rows.filter(p=>Number(p.supplier_id)===Number(supplierId));if(!products.some(p=>decisions.has(Number(p.product_id))?decisions.get(Number(p.product_id)):p.store_task_visible===true))throw fault(400,'No visible active products remain for '+(products[0]?.supplier_name||('supplier #'+supplierId))+'. Keep an item visible or remove this supplier from the assignment.');}
 if(expected.products.length)await c.query(`UPDATE public.products p SET store_task_visible=x.visible FROM jsonb_to_recordset($1::jsonb) AS x(product_id int,visible boolean) WHERE p.product_id=x.product_id AND p.store_task_visible IS DISTINCT FROM x.visible`,[JSON.stringify([...decisions].map(([product_id,visible])=>({product_id,visible})))]);
 return {reviewed:decisions.size,hidden:[...decisions.values()].filter(v=>!v).length};
}
async function queueBatch(c,created,actor,review){
 if(!created.length)return {emails:0,batch_id:null};
 const assignmentIds=created.map(a=>a.assignment_id);
 const batch=(await c.query(`INSERT INTO public.nems_task_email_batches(assigned_by,assignment_ids,product_review) VALUES($1,$2::jsonb,$3::jsonb) RETURNING batch_id`,[actor,JSON.stringify(assignmentIds),JSON.stringify(review||{})])).rows[0];
 const stores=(await c.query(`SELECT s.store_id,s.store_email,s.store_name,jsonb_agg(a.assignment_id ORDER BY a.assignment_id) AS assignment_ids
   FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id WHERE a.assignment_id=ANY($1::bigint[]) AND s.store_email IS NOT NULL GROUP BY s.store_id,s.store_email,s.store_name`,[assignmentIds])).rows;
 for(const s of stores){
  const delivery=(await c.query(`INSERT INTO public.nems_task_batch_deliveries(batch_id,store_id,recipient_email,assignment_ids,email_id)
   VALUES($1,$2,LOWER($3),$4::jsonb,nextval(pg_get_serial_sequence('public.nems_email_notifications','email_id'))) ON CONFLICT(batch_id,store_id) DO NOTHING RETURNING email_id`,[batch.batch_id,s.store_id,s.store_email,JSON.stringify(s.assignment_ids)])).rows[0];
  if(!delivery)continue;
  await c.query(`INSERT INTO public.nems_email_notifications(email_id,recipient_email,subject,message) VALUES($1,LOWER($2),$3,$4)`,[delivery.email_id,s.store_email,'NEMS new task assignments · '+batch.batch_id,'New monitoring tasks assigned. Store access and task status will be checked before sending.']);
 }
 return {emails:stores.length,batch_id:batch.batch_id};
}
function register({app,pool,authenticate,adminOnly,secureRoute,accessibleStores}){
 app.post('/api/admin/task-review/preview',authenticate,adminOnly,secureRoute(async(req,res)=>{
  const ids=idsOf(req.body?.supplier_ids);const rows=await readProducts(pool,ids);res.json(analyze(rows,ids));
 }));
 return {prepareEmail:async(row,recipient)=>{
  if(recipient.role!=='STORE')throw new Error('Task batch emails are for STORE accounts only');
  const d=(await pool.query(`SELECT * FROM public.nems_task_batch_deliveries WHERE email_id=$1 AND LOWER(recipient_email)=LOWER($2)`,[row.email_id,row.recipient_email])).rows[0];
  if(!d)throw new Error('Task batch delivery not found');
  const stores=await accessibleStores(pool,recipient);if(!stores.some(s=>String(s.store_id)===String(d.store_id)))throw new Error('Recipient no longer has access to this store');
  const tasks=(await pool.query(`SELECT a.assignment_id,a.expiry_scope,sp.supplier_name,s.store_name,
    COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at
    FROM public.nems_task_assignments a JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id JOIN public.stores s ON s.store_id=a.store_id
    WHERE a.assignment_id=ANY($1::bigint[]) AND a.store_id=$2 AND a.status='ACTIVE'
      AND NOT EXISTS(SELECT 1 FROM public.nems_monitoring_submissions sub WHERE sub.assignment_id=a.assignment_id AND sub.submitted_at>COALESCE((SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity'))
    ORDER BY sp.supplier_name,a.assignment_id`,[d.assignment_ids,d.store_id])).rows;
  if(!tasks.length)throw new Error('No unfinished active tasks remain in this assignment batch');
  const lines=tasks.map((a,i)=>`${i+1}. ${a.supplier_name}\nTask #${a.assignment_id} | Scope: ${a.expiry_scope} | Deadline: ${a.due_at?new Date(a.due_at).toLocaleString('en-GB',{timeZone:'Asia/Manila'})+' (Philippine time)':'None'}`);
  return `${row.subject}\n\nStore: ${tasks[0].store_name}\n${tasks.length} monitoring task(s) were assigned together.\n\n${lines.join('\n\n')}\n\nOpen NEMS > My Task. Confirm actual quantities and expiration dates, or NO STOCK. Save each item, then Submit the task before its deadline. Check the pack description; do not encode case quantities as pieces.\nhttps://nems-app.onrender.com/`;
 }};
}
module.exports={analyze,possiblePack,applyReview,queueBatch,register,idsOf};
