'use strict';
const warningText=flags=>flags.length?'Not included in My Task for '+flags.map(t=>'task #'+t.assignment_id+(t.due_at?' (deadline '+new Date(t.due_at).toLocaleString('en-GB',{timeZone:'Asia/Manila'})+' Philippine time)':'')+' — '+(t.reason||'task closed')).join('; ')+'. Saved in Store Monitoring only. This does not complete or reopen the task.':'';
function exclusions(tasks,when=Date.now()){
 return tasks.filter(t=>t.submitted||t.status!=='ACTIVE'||(t.due_at&&new Date(t.due_at).getTime()<=when)).map(t=>({assignment_id:t.assignment_id,status:t.status,due_at:t.due_at||null,reason:t.submitted?'task already submitted':t.status!=='ACTIVE'?'task '+String(t.status||'closed').toLowerCase():'saved after task deadline'}));
}
function annotate(row,flags=[]){
 const source=row.monitoring_id==null?'MY TASK':'STORE ENCODING';
 return {...row,encoding_source:source,my_task_inclusion:flags.length?'NOT INCLUDED IN MY TASK (see listed tasks)':source==='MY TASK'?'SAVED IN MY TASK':'STORE ENCODING — task confirmation is separate',task_reminder:warningText(flags),excluded_task_ids:flags.map(t=>String(t.assignment_id)).join(', ')};
}
async function enrich(client,rows){
 const keys=[],lookup=new Map();
 for(const r of rows){if(r.monitoring_id==null)continue;const key=String(r.monitoring_id);if(!lookup.has(key)){lookup.set(key,keys.length);keys.push({i:keys.length,monitoring_id:r.monitoring_id});}}
 if(!keys.length)return rows.map(r=>annotate(r));
 const result=await client.query(`SELECT k.i,m.updated_at,
  sr.details->'task_exclusions' AS recorded_exclusions,
  COALESCE(ts.tasks,'[]'::jsonb) AS task_states
  FROM jsonb_to_recordset($1::jsonb) AS k(i int,monitoring_id int)
  JOIN public.monitoring m ON m.monitoring_id=k.monitoring_id
  LEFT JOIN LATERAL(SELECT r.details FROM public.nems_store_remarks r
   WHERE LOWER(r.store_email)=LOWER(m.store_email) AND r.product_id=m.product_id AND r.source='STORE_ENCODING'
     AND r.details->>'revision'=m.xmin::text
   ORDER BY r.created_at DESC,r.remark_id DESC LIMIT 1) sr ON TRUE
  LEFT JOIN LATERAL(SELECT jsonb_agg(jsonb_build_object('assignment_id',a.assignment_id,'status',a.status,
    'due_at',COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')))) AS tasks
   FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id
   WHERE LOWER(TRIM(s.store_email))=LOWER(TRIM(m.store_email)) AND LOWER(TRIM(s.store_name))=LOWER(TRIM(m.store_name))
     AND LOWER(TRIM(sp.supplier_name))=LOWER(TRIM(m.supplier))) ts ON TRUE`,[JSON.stringify(keys)]);
 const flags=new Map(result.rows.map(r=>[Number(r.i),Array.isArray(r.recorded_exclusions)?r.recorded_exclusions:exclusions((r.task_states||[]).map(t=>({...t,status:'ACTIVE'})),new Date(r.updated_at).getTime())]));
 return rows.map(r=>annotate(r,r.monitoring_id==null?[]:(flags.get(lookup.get(String(r.monitoring_id)))||[])));
}
function columns(r){return {'Encoding Source':r.encoding_source||'','My Task Inclusion':r.my_task_inclusion||'','Task Reminder':r.task_reminder||'','Excluded Task IDs':r.excluded_task_ids||'','Monitoring Saved At':r.updated_at||''};}
function archiveColumns(r){
 const history=(r.monitoring_snapshot?.employee_history||[]).filter(x=>x.source==='STORE_ENCODING'&&Array.isArray(x.details?.task_exclusions)).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
 const fromStore=(r.monitoring_snapshot?.active_entries||[]).some(x=>x.monitoring_id!=null);
 const flags=fromStore?(history[0]?.details.task_exclusions||[]):[];
 return columns({...annotate({monitoring_id:r.original_monitoring_id},flags),my_task_inclusion:flags.length?'NOT INCLUDED IN MY TASK (see listed tasks)':'ARCHIVED — see submission history',updated_at:r.monitoring_snapshot?.monitoring?.updated_at||''});
}
module.exports={exclusions,warningText,enrich,annotate,columns,archiveColumns};
