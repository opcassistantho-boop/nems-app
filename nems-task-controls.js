'use strict';
const id=v=>Number.isSafeInteger(Number(v))&&Number(v)>0?Number(v):null;
const fault=(status,message)=>Object.assign(new Error(message),{status});
const eligible=(action,t)=>action==='CANCEL'?t.display_status!=='CANCELLED':['OVERDUE','SUBMITTED','CLOSED'].includes(t.display_status);
function selection(body){
 if(!Array.isArray(body.assignments)||!body.assignments.length||body.assignments.length>1000)throw fault(400,'Select between 1 and 1000 store assignments');
 const rows=body.assignments.map(r=>({assignment_id:id(r?.assignment_id),revision:String(r?.revision||'')}));
 if(rows.some(r=>!r.assignment_id||!/^\d+$/.test(r.revision))||new Set(rows.map(r=>r.assignment_id)).size!==rows.length)throw fault(400,'Invalid selection. Refresh task details and select stores again.');
 return rows;
}
module.exports=function registerTaskControls({app,pool,authenticate,adminOnly,secureRoute,transaction,taskTrackerSQL,scalePageQuery,notify,accessibleStores}){
 const route=[authenticate,adminOnly];
 app.get('/api/admin/task-groups',...route,secureRoute(async(req,res)=>{
  const {sql,args}=taskTrackerSQL(req.user,{search:req.query.search});
  const status=String(req.query.status||'');
  if(status&&!['PENDING','OVERDUE','SUBMITTED','CANCELLED','CLOSED'].includes(status))throw fault(400,'Invalid status');
  const values=[...args];if(status)values.push(status);
  const group=`SELECT supplier_id,supplier_name,COUNT(DISTINCT store_id)::int AS stores,
   COUNT(*) FILTER(WHERE display_status='PENDING')::int AS pending,
   COUNT(*) FILTER(WHERE display_status='OVERDUE')::int AS overdue,
   COUNT(*) FILTER(WHERE display_status='SUBMITTED')::int AS submitted,
   COUNT(*) FILTER(WHERE display_status='CANCELLED')::int AS cancelled,
   COUNT(*) FILTER(WHERE display_status='CLOSED')::int AS closed,
   MIN(due_at) AS earliest_deadline,MAX(due_at) AS latest_deadline,
   COUNT(*) FILTER(WHERE due_at IS NULL)::int AS no_deadline,MAX(assigned_at) AS latest_assignment
   FROM (${sql}) t GROUP BY supplier_id,supplier_name
   ${status?'HAVING COUNT(*) FILTER(WHERE display_status=$'+values.length+')>0':''}`;
  res.json(await scalePageQuery(pool,req.query,`SELECT * FROM (${group}) grouped`,values,"CASE WHEN pending+overdue>0 THEN 0 ELSE 1 END,latest_assignment DESC NULLS LAST,supplier_id DESC"));
 }));
 app.get('/api/admin/task-groups/:supplierId/stores',...route,secureRoute(async(req,res)=>{
  const supplierId=id(req.params.supplierId);if(!supplierId)throw fault(400,'Invalid supplier');
  const rounds=(await pool.query(`SELECT COALESCE(assignment_batch::text,'legacy') AS round_key,MAX(assigned_at) AS assigned_at,COUNT(*)::int AS stores FROM public.nems_task_assignments WHERE supplier_id=$1 GROUP BY assignment_batch ORDER BY MAX(assigned_at) DESC NULLS LAST,COALESCE(assignment_batch::text,'legacy')`,[supplierId])).rows;
  const round=String(req.query.round||rounds[0]?.round_key||'legacy');
  if(rounds.length&&!rounds.some(r=>r.round_key===round))throw fault(400,'Choose a valid assignment round');
  const {sql,args}=taskTrackerSQL(req.user,{supplier:supplierId});
  args.push(round);
  const rows=(await pool.query(`SELECT t.*,a.xmin::text AS revision,
    (SELECT to_jsonb(x) FROM (SELECT employee_name,explanation,submitted_at FROM public.nems_task_overdue_explanations e WHERE e.assignment_id=t.assignment_id ORDER BY submitted_at DESC LIMIT 1) x) AS explanation,
    (SELECT to_jsonb(x) FROM (SELECT action_type,reason,actor_email,new_due_at,created_at FROM public.nems_task_admin_actions h WHERE h.assignment_id=t.assignment_id ORDER BY created_at DESC,action_id DESC LIMIT 1) x) AS admin_note
    FROM (${sql}) t JOIN public.nems_task_assignments a ON a.assignment_id=t.assignment_id WHERE COALESCE(a.assignment_batch::text,'legacy')=$${args.length} ORDER BY t.store_name,t.assignment_id LIMIT 1001`,args)).rows;
  if(rows.length>1000)throw fault(409,'More than 1000 stores are assigned. Contact ADMIN before changing this supplier.');
  res.json({supplier_id:supplierId,supplier_name:rows[0]?.supplier_name||'',rounds,current_round:round,records:rows});
 }));
 for(const action of ['REOPEN','CANCEL'])app.post('/api/admin/task-groups/:supplierId/'+action.toLowerCase(),...route,secureRoute(async(req,res)=>{
  const supplierId=id(req.params.supplierId),chosen=selection(req.body||{});
  if(!supplierId)throw fault(400,'Invalid supplier');
  const reason=String(req.body.reason||'').trim();
  if(!reason||reason.length>2000)throw fault(400,'Enter an explanation for the selected stores (1-2000 characters)');
  const due=action==='REOPEN'?new Date(req.body.due_at):null;
  if(action==='REOPEN'&&(!req.body.due_at||!Number.isFinite(due.getTime())||due.getTime()<=Date.now()))throw fault(400,'Choose a future deadline');
  const result=await transaction(async c=>{
   const ids=chosen.map(r=>r.assignment_id);
   const locked=(await c.query(`SELECT a.assignment_id,a.store_id,a.status,
    COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,a.xmin::text AS revision
    FROM public.nems_task_assignments a WHERE a.supplier_id=$1 AND a.assignment_id=ANY($2::bigint[]) ORDER BY a.assignment_id FOR UPDATE`,[supplierId,ids])).rows;
   if(locked.length!==chosen.length)throw fault(409,'A selected assignment is missing or belongs to another supplier. Refresh details.');
   const {sql,args}=taskTrackerSQL(req.user,{supplier:supplierId});
   const current=(await c.query(`SELECT * FROM (${sql}) t WHERE t.assignment_id=ANY($${args.length+1}::bigint[])`,[...args,ids])).rows;
   const state=new Map(current.map(t=>[String(t.assignment_id),t]));
   for(const t of locked){
    if(String(t.revision)!==chosen.find(r=>r.assignment_id===Number(t.assignment_id)).revision)throw fault(409,'A selected task changed. Refresh details before continuing.');
    if(!state.has(String(t.assignment_id))||!eligible(action,state.get(String(t.assignment_id))))throw fault(409,action==='REOPEN'?'Only overdue, submitted or closed tasks can be reopened. Cancelled tasks cannot be reopened.':'A selected task is already cancelled. Refresh details.');
   }
   // Recheck time after row locks; no expired deadline can be installed after waiting.
   if(action==='REOPEN'&&due.getTime()<=Date.now())throw fault(409,'The selected new deadline has already passed');
   if(action==='REOPEN'){
    await c.query(`INSERT INTO public.nems_task_reopen_history(assignment_id,reopened_by,previous_due_at,new_due_at,reason,reopened_at)
     SELECT a.assignment_id,$3,COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')),$4::timestamptz,$5,clock_timestamp()
     FROM public.nems_task_assignments a WHERE a.supplier_id=$1 AND a.assignment_id=ANY($2::bigint[])`,[supplierId,ids,req.user.email,due.toISOString(),reason]);
   }
   await c.query(`INSERT INTO public.nems_task_admin_actions(assignment_id,store_id,action_type,actor_email,reason,previous_status,previous_due_at,new_due_at,created_at)
    SELECT a.assignment_id,a.store_id,$3,$4,$5,a.status,COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')),$6::timestamptz,clock_timestamp()
    FROM public.nems_task_assignments a WHERE a.supplier_id=$1 AND a.assignment_id=ANY($2::bigint[])`,[supplierId,ids,action,req.user.email,reason,due?.toISOString()||null]);
   if(action==='REOPEN')await c.query(`UPDATE public.nems_task_assignments SET status='ACTIVE',due_at=$3::timestamptz,due_date=($3::timestamptz AT TIME ZONE 'Asia/Manila')::date WHERE supplier_id=$1 AND assignment_id=ANY($2::bigint[])`,[supplierId,ids,due.toISOString()]);
   else await c.query(`UPDATE public.nems_task_assignments SET status='CANCELLED' WHERE supplier_id=$1 AND assignment_id=ANY($2::bigint[])`,[supplierId,ids]);
   for(const t of current){
    const deadline=due?' New deadline: '+due.toLocaleString('en-GB',{timeZone:'Asia/Manila'})+' (Philippine time).':'';
    if(t.store_email)await notify(c,t.store_email,req.user.email,'MESSAGE',action==='REOPEN'?'Task reopened':'Task cancelled',`Task #${t.assignment_id} · ${t.supplier_name}.${deadline}\n${reason}`,'TASK',t.assignment_id,false);
   }
   return {count:locked.length,assignment_ids:ids};
  });
  res.json({...result,message:`${action==='REOPEN'?'Reopened':'Cancelled'} ${result.count} selected store assignment(s). Other stores were not changed.`});
 }));
 app.get('/api/tasks/:id/admin-note',authenticate,secureRoute(async(req,res)=>{
  const assignment=id(req.params.id);if(!assignment)throw fault(400,'Invalid task');
  const stores=await accessibleStores(pool,req.user);
  const rows=(await pool.query(`SELECT a.assignment_id,h.action_type,h.reason,h.actor_email,h.new_due_at,h.created_at FROM public.nems_task_assignments a
    LEFT JOIN LATERAL (SELECT * FROM public.nems_task_admin_actions x WHERE x.assignment_id=a.assignment_id ORDER BY created_at DESC,action_id DESC LIMIT 1) h ON TRUE
    WHERE a.assignment_id=$1 AND a.store_id=ANY($2::bigint[])`,[assignment,stores.map(s=>s.store_id)])).rows;
  if(!rows.length)throw fault(404,'Task not found in your authorized stores');res.json(rows[0]);
 }));
};
module.exports.eligible=eligible;module.exports.selection=selection;
