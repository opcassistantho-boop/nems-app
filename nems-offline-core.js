(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.NemsOfflineCore=factory();})(globalThis,()=>{
'use strict';
const iso=()=>new Date().toISOString();
function entriesOf(p){const out=[];for(let i=1;i<=3;i++)if(p['expiration_'+i])out.push({date:String(p['expiration_'+i]).slice(0,10),qty:Number(p['qty_'+i])});for(const r of p.extra_expirations||[])out.push({date:String(r.date||r.expiration_date).slice(0,10),qty:Number(r.qty??r.quantity)});return out;}
function validateRows(rows){if(!rows.length||rows.length>100)throw Error('Enter 1–100 expiration dates.');for(const r of rows){if(!/^\d{4}-\d{2}-\d{2}$/.test(r.date)||!Number.isFinite(Date.parse(r.date))||new Date(r.date).toISOString().slice(0,10)!==r.date||r.qty===''||r.qty==null||!Number.isInteger(Number(r.qty))||Number(r.qty)<0)throw Error('Each row needs a valid expiration date and whole-number quantity (0 or more).');}return rows.map(r=>({date:r.date,qty:Number(r.qty)}));}
function taskPayload(rows,noStock,name,remarks,revision){if(!name.trim()||!remarks.trim()||name.length>120||remarks.length>2000)throw Error('Enter your employee name (up to 120 characters) and remarks (up to 2000).');const p={expected_revision:revision??null,no_stock:!!noStock,employee_name:name.trim(),store_remarks:remarks.trim()};const values=noStock?[]:validateRows(rows);for(let i=1;i<=3;i++){p['expiration_'+i]=values[i-1]?.date||null;p['qty_'+i]=values[i-1]?.qty??null;}p.extra_expirations=values.slice(3);return p;}
function storePayload(rows,name,remarks,revision,product){if(!name.trim()||!remarks.trim()||name.length>120||remarks.length>2000)throw Error('Enter your employee name and remarks.');return{expected_revision:revision??null,product_id:Number(product.product_id),employee_name:name.trim(),store_remarks:remarks.trim(),store_barcode:product.master_barcode||'',srp:product.master_srp??null,expirations:validateRows(rows).map(r=>({expiration_date:r.date,quantity:r.qty}))};}
function taskLocked(task){return task.status!=='ACTIVE'||!!task.due_at&&new Date(task.due_at).getTime()<=Date.now();}
function destination(entry){return entry.type==='store'?'/api/store/monitoring':entry.type==='task'?`/api/store/tasks/${entry.task_id}/products/${entry.product_id}`:`/api/store/tasks/${entry.task_id}/submit`;}
function method(entry){return entry.type==='task'?'PUT':'POST';}
function outstanding(e){return e.status!=='synced'&&e.status!=='cancelled';}
function queue(state,entry){
 const same=state.queue.find(e=>outstanding(e)&&e.type===entry.type&&String(e.task_id||'')===String(entry.task_id||'')&&String(e.product_id||'')===String(entry.product_id||''));
 if(same&&['uncertain','sending'].includes(same.status))throw Error('This save has an unconfirmed server result. Sync it with its original request key before editing it.');
 if(entry.type==='task'&&state.queue.some(e=>outstanding(e)&&e.type==='submit'&&String(e.task_id)===String(entry.task_id)))throw Error('Cancel the queued submission before changing task products.');
 const value={...entry,id:crypto.randomUUID(),key:crypto.randomUUID(),recorded_at:iso(),status:'pending',note:'Saved on this device only; not in monitoring downloads or submitted tasks.'};
 if(same)state.queue[state.queue.indexOf(same)]=value;else state.queue.push(value);return value;
}
// Server authority, expected revisions and original idempotency keys are never bypassed.
async function syncEntry(state,e,io){
 if(!outstanding(e)||e.status==='review')return;
 if(Date.now()-Date.parse(e.recorded_at)>29*86400000){e.status='review';e.note='This draft is over 29 days old. Review current server data before retrying; old save receipts may expire.';await io.persist();return;}
 if(e.type==='submit'&&state.queue.some(x=>x!==e&&x.type==='task'&&String(x.task_id)===String(e.task_id)&&outstanding(x))){e.note='Task submission waits for every product save to sync successfully.';await io.persist();return;}
 const uncertain=e.status==='uncertain'||e.status==='sending';
 try{
   if(!uncertain&&e.type!=='store'){
     const live=await io.request(`/api/store/tasks/${e.task_id}/products`);
     if(e.payload.offline_task_cycle&&live.task?.task_cycle!==e.payload.offline_task_cycle){e.status='review';e.note='Task was reopened or changed to another cycle. Download and review it before submitting new data.';await io.persist();return;}
     if(live.locked){e.status='review';e.note='NOT included or submitted: this task is now closed or past its deadline. Product stock may be sent to Store Encoding separately after review.';await io.persist();return;}
   }
   if(!uncertain&&e.type==='submit'){
       const local=state.taskData[String(e.task_id)];
       if(local)e.payload.offline_product_revisions=local.products.map(p=>({product_id:Number(p.product_id),revision:p.revision??null}));
   }
   e.status='sending';e.note='Awaiting server confirmation…';await io.persist();
   const response=await io.request(destination(e),{method:method(e),body:e.payload,key:e.key});
   e.status='synced';e.synced_at=iso();e.note=e.type==='submit'?'SUBMITTED: server confirmed.':'Synced to server.'+(response.task_warning?' '+response.task_warning:'');e.response=response;
   const product=state.snapshot.products.find(p=>Number(p.product_id)===Number(e.product_id));
   if(e.type==='store'){
      const row={product_id:e.product_id,revision:response.revision,store_barcode:e.payload.store_barcode,srp:e.payload.srp,expirations:e.payload.expirations.map(r=>({date:r.expiration_date,qty:r.quantity}))};state.snapshot.monitoring=state.snapshot.monitoring.filter(r=>Number(r.product_id)!==Number(e.product_id));state.snapshot.monitoring.push(row);
   }else if(e.type==='task'){
      const task=state.taskData[String(e.task_id)],p=task?.products.find(p=>Number(p.product_id)===Number(e.product_id));if(p)Object.assign(p,e.payload,{revision:response.revision,encoded:true});
   }else{const task=state.taskData[String(e.task_id)];if(task){task.task.submitted=true;task.locked=taskLocked(task.task);}}
   await io.persist();
 }catch(error){
   if(error.status===401||error.status===403){e.status=uncertain?'uncertain':'pending';e.note='Log in online again with the same store account before syncing.';await io.persist();throw error;}
   if(!error.status||error.status>=500||error.requestPending){e.status='uncertain';e.note='Server result unconfirmed. Reconnect and sync again using the same request key. Do not re-enter this save.';await io.persist();throw error;}
   e.status='review';e.note='NOT included/submitted. '+error.message;await io.persist();
 }
}
return{entriesOf,validateRows,taskPayload,storePayload,taskLocked,destination,method,outstanding,queue,syncEntry};
});
