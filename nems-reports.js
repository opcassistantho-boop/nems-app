'use strict';
// Privileged server module. No browser/database public access policies are required.
const TZ='Asia/Manila', OVERDUE_START='2026-11-30';
const email=v=>String(v||'').trim().toLowerCase();
const day=v=>v instanceof Date?v.toISOString().slice(0,10):String(v||'').slice(0,10);
const localDay=v=>new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date(v));
const month=v=>localDay(v).slice(0,7)+'-01';
const nextMonth=v=>{const d=new Date(v+'T00:00:00Z');d.setUTCMonth(d.getUTCMonth()+1);return day(d);};
const boundary=d=>Date.parse(d+'T00:00:00+08:00');
const inPeriod=(v,start,end)=>!!v&&Date.parse(v)>=boundary(start)&&Date.parse(v)<boundary(end);
const num=v=>Number.isFinite(Number(v))?Number(v):0;
const sum=(rows,key)=>rows.reduce((n,r)=>n+num(r[key]),0);
const stockKey=r=>email(r.store_email)+'|'+r.product_id+'|'+day(r.expiration_date);
const taskKey=r=>String(r.assignment_id);
const overdueEligible=t=>t.due_at&&localDay(t.due_at)>=OVERDUE_START;
const round=n=>Math.round(n*100)/100;
function taskState(t,asOf){
 if(t.status==='CANCELLED')return 'CANCELLED';
 if(t.first_submitted_at){if(!t.due_at)return 'SUBMITTED (NO DEADLINE)';if(!overdueEligible(t))return 'SUBMITTED (PRE-START DEADLINE)';return Date.parse(t.first_submitted_at)>Date.parse(t.due_at)?'SUBMITTED LATE':'SUBMITTED ON TIME';}
 if(t.status!=='ACTIVE')return 'CLOSED';
 if(t.due_at&&Date.parse(t.due_at)<asOf)return overdueEligible(t)?'OVERDUE':'PRE-START OVERDUE EXCLUDED';
 return 'PENDING';
}
function mergeYear(snapshots){
 const latest=snapshots.at(-1);
 const data={...latest.payload};
 // Event histories are unioned by primary key, never summed across repeated snapshots.
 for(const [field,key] of [['stores','store_id'],['activities','remark_id'],['reports','report_id'],['explanations','explanation_id'],['tasks','assignment_id']]){
  const all=new Map();for(const s of snapshots)for(const r of s.payload[field]||[])all.set(String(r[key]??(r.assignment_id+'|'+r.submitted_at)),r);
  data[field]=[...all.values()];
 }
 data.coverage=snapshots.map(s=>({month:day(s.month_key),first_capture:s.first_captured_at,as_of:s.captured_at}));
 data.captured_at=latest.captured_at;
 data.first_captured_at=snapshots[0].first_captured_at;
 return data;
}
function buildReport(data,start,end,ids,previous=null){
 const allowed=new Set(ids.map(String));
 const stores=(data.stores||[]).filter(s=>allowed.has(String(s.store_id)));
 const byEmail=new Map(stores.map(s=>[email(s.store_email),s]));
 const permitted=r=>byEmail.has(email(r.store_email));
 const activities=(data.activities||[]).filter(r=>permitted(r)&&inPeriod(r.created_at,start,end));
 const stock=(data.stock||[]).filter(permitted);
 const currentTasks=(data.tasks||[]).filter(t=>allowed.has(String(t.store_id))&&Date.parse(t.assigned_at)<boundary(end));
 const asOf=Math.min(Date.parse(data.captured_at),boundary(end));
 const previousIssues=new Set(previous?buildReport(previous,start,end,ids).actions.map(r=>r.issue_key):[]);
 const taskRows=currentTasks.map(t=>({...t,state:taskState(t,asOf)})).filter(t=>
  inPeriod(t.assigned_at,start,end)||inPeriod(t.due_at,start,end)||inPeriod(t.first_submitted_at,start,end)||['PENDING','OVERDUE'].includes(t.state));
 const reportRows=(data.reports||[]).filter(permitted);
 const latestReports=new Map();
 for(const r of reportRows.sort((a,b)=>Date.parse(a.reported_at)-Date.parse(b.reported_at)))latestReports.set(stockKey(r),r);
 const stockRows=stock.map(r=>{
  const days=Math.round((Date.parse(day(r.expiration_date)+'T00:00:00Z')-Date.parse(localDay(asOf-1)+'T00:00:00Z'))/86400000);
  const report=latestReports.get(stockKey(r));
  return {...r,expiry_days:days,bucket:days<0?'EXPIRED':days<=30?'0-30 DAYS':days<=60?'31-60 DAYS':days<=90?'61-90 DAYS':'OVER 90 DAYS',
   stock_value:r.landed_cost==null?null:round(num(r.quantity)*num(r.landed_cost)),
   report_status:report?.validation_status||'MISSING',reported_action:report?.product_status||'NOT REPORTED',report_remarks:report?.store_remarks||''};
 }).filter(r=>r.expiry_days<=90);
 const group=(rows,key)=>{const map=new Map();for(const r of rows){const k=key(r);if(!map.has(k))map.set(k,[]);map.get(k).push(r);}return map;};
 const storesById=new Map(stores.map(s=>[String(s.store_id),s]));
 const explanationsByTask=group(data.explanations||[],r=>String(r.assignment_id));
 const actions=[];
 for(const t of taskRows.filter(t=>['PENDING','OVERDUE'].includes(t.state))){
  const s=storesById.get(String(t.store_id));
  const reasons=(explanationsByTask.get(String(t.assignment_id))||[]).sort((a,b)=>Date.parse(b.submitted_at)-Date.parse(a.submitted_at));
  actions.push({issue_key:'TASK:'+t.assignment_id,store:s?.store_name,store_id:t.store_id,concern:t.state+' task #'+t.assignment_id+' / '+t.supplier_name,
   responsible:[s?.store_name,...(s?.as_emails||[]),...(s?.aom_emails||[])].filter(Boolean).join('; '),required_action:'Confirm all required products and submit the task; explain missed deadline if overdue',target_date:t.due_at||'Set in meeting',reason:reasons[0]?.explanation||'',status:'OPEN'});
 }
 for(const r of stockRows.filter(r=>r.bucket==='EXPIRED')){
  const s=byEmail.get(email(r.store_email));
  actions.push({issue_key:'STOCK:'+stockKey(r),store:r.store_name,store_id:s?.store_id,concern:'Expired: '+r.product_name+' / '+day(r.expiration_date)+' / '+r.report_status,
   responsible:[s?.store_name,...(s?.as_emails||[]),...(s?.aom_emails||[])].filter(Boolean).join('; '),required_action:r.report_status==='PENDING'?'AS to review expired report':r.report_status==='MISSING'||r.report_status==='REJECTED'?'Store to submit/correct expired report':'Follow up on expired stock still ON STORE',target_date:'Set in meeting',reason:r.report_remarks,status:'OPEN'});
 }
 for(const a of actions)a.movement=previousIssues.has(a.issue_key)?'CARRIED OVER':'NEW / FIRST OBSERVED';
 const activityByStore=group(activities,r=>email(r.store_email)),tasksByStore=group(taskRows,r=>String(r.store_id)),allTasksByStore=group(currentTasks,r=>String(r.store_id)),expiredByStore=group(stockRows.filter(r=>r.bucket==='EXPIRED'),r=>email(r.store_email));
 const compliance=stores.map(s=>{
  const a=(activityByStore.get(email(s.store_email))||[]);
  const saves=a.filter(r=>r.details?.event!=='TASK_SUBMIT');
  const tasks=(tasksByStore.get(String(s.store_id))||[]);
  const assigned=(allTasksByStore.get(String(s.store_id))||[]).filter(r=>inPeriod(r.assigned_at,start,end));
  const expired=(expiredByStore.get(email(s.store_email))||[]);
  return {store:s.store_name,as:(s.as_emails||[]).join('; '),aom:(s.aom_emails||[]).join('; '),encoding_activity:saves.length?'ENCODED':'NO ENCODING ACTIVITY RECORDED',
   saved_product_events:saves.length,last_encoding:saves.map(r=>r.created_at).sort().at(-1)||s.last_encoding_at||'',employees:[...new Set(saves.map(r=>r.employee_name).filter(Boolean))].join('; '),
   task_assignment:assigned.length?'TASK ASSIGNED THIS PERIOD':'NO NEW TASK ASSIGNED',assigned:assigned.length,
   submitted_total:tasks.filter(t=>t.first_submitted_at&&inPeriod(t.first_submitted_at,start,end)).length,
   submitted_before_official_start:tasks.filter(t=>t.state==='SUBMITTED (PRE-START DEADLINE)'&&inPeriod(t.first_submitted_at,start,end)).length,
   submitted_on_time:tasks.filter(t=>t.state==='SUBMITTED ON TIME'&&inPeriod(t.first_submitted_at,start,end)).length,
   submitted_late:tasks.filter(t=>t.state==='SUBMITTED LATE'&&inPeriod(t.first_submitted_at,start,end)).length,
   pending:tasks.filter(t=>t.state==='PENDING').length,overdue:tasks.filter(t=>t.state==='OVERDUE').length,
   newly_overdue:tasks.filter(t=>t.state==='OVERDUE'&&inPeriod(t.due_at,start,end)).length,
   carried_over_overdue:tasks.filter(t=>t.state==='OVERDUE'&&Date.parse(t.due_at)<boundary(start)).length,
   incomplete_products:tasks.filter(t=>['PENDING','OVERDUE'].includes(t.state)).reduce((n,t)=>n+Math.max(0,num(t.required_products)-num(t.saved_products)),0),
   expired_missing_report:expired.filter(r=>r.report_status==='MISSING').length,
   expired_pending_review:expired.filter(r=>r.report_status==='PENDING').length,expired_rejected:expired.filter(r=>r.report_status==='REJECTED').length};
 });
 const summary={stores:stores.length,stores_with_encoding:compliance.filter(s=>s.saved_product_events>0).length,stores_without_encoding:compliance.filter(s=>!s.saved_product_events).length,
  assigned:sum(compliance,'assigned'),submitted_total:sum(compliance,'submitted_total'),submitted_before_official_start:sum(compliance,'submitted_before_official_start'),submitted_on_time:sum(compliance,'submitted_on_time'),submitted_late:sum(compliance,'submitted_late'),pending:sum(compliance,'pending'),overdue:sum(compliance,'overdue'),newly_overdue:sum(compliance,'newly_overdue'),carried_over_overdue:sum(compliance,'carried_over_overdue'),
  expired_quantity:sum(stockRows.filter(r=>r.bucket==='EXPIRED'),'quantity'),expired_value:round(sum(stockRows.filter(r=>r.bucket==='EXPIRED'),'stock_value')),
  near_expiry_quantity:sum(stockRows.filter(r=>r.bucket!=='EXPIRED'),'quantity'),near_expiry_value:round(sum(stockRows.filter(r=>r.bucket!=='EXPIRED'),'stock_value')),stock_rows_missing_cost:stockRows.filter(r=>r.landed_cost==null).length};
 const priorities=[];
 for(const field of ['store_name','supplier','product_name']){
  const groups=new Map();for(const r of stockRows){const key=r[field]||'Unknown',a=groups.get(key)||{category:field,name:key,expired_value:0,near_expiry_value:0};a[r.bucket==='EXPIRED'?'expired_value':'near_expiry_value']+=num(r.stock_value);groups.set(key,a);}
  priorities.push(...[...groups.values()].sort((a,b)=>(b.expired_value+b.near_expiry_value)-(a.expired_value+a.near_expiry_value)).slice(0,10));
 }
 return {summary,compliance,tasks:taskRows,stock:stockRows,activities,reports:reportRows.filter(r=>inPeriod(r.reported_at,start,end)||inPeriod(r.validated_at,start,end)||r.validation_status==='PENDING'),actions,priorities,
  metadata:{period_start:start,period_end_exclusive:end,captured_at:data.captured_at,first_capture:data.first_captured_at,coverage:data.coverage||[],overdue_start:OVERDUE_START,
   notes:'Saved does not mean submitted. Quantities are recorded units, not a count of unique products. Expiry buckets use snapshot date. Missing cost is not valued. Counts describe NEMS records; physical stock requires verification. Pre-November-30 deadlines never count as overdue. Historical deadlines cannot be reconstructed where changed before snapshots. Partial coverage is not zero activity.'}};
}
function workbook(XLSX,report,comparison=[],trend=[]){
 const wb=XLSX.utils.book_new();
 const add=(name,rows)=>{
  // Force strings to text; never turn user-entered remarks into spreadsheet formulas.
  const records=rows.length?rows:[{Note:'No matching records'}];
  const sheet=XLSX.utils.json_to_sheet(records);
  const keys=[...new Set(records.flatMap(r=>Object.keys(r)))];
  sheet['!cols']=keys.map(k=>({wch:Math.min(55,Math.max(14,k.length+2,...records.slice(0,200).map(r=>Math.min(55,String(r[k]??'').length+2))))}));
  if(sheet['!ref'])sheet['!autofilter']={ref:sheet['!ref']};
  XLSX.utils.book_append_sheet(wb,sheet,name);
 };
 add('Read Me',Object.entries(report.metadata).map(([key,value])=>({field:key,value:typeof value==='object'?JSON.stringify(value):value})));
 add('Summary',Object.entries(report.summary).map(([metric,value])=>({metric,value})));
 add('Store Compliance',report.compliance);
 add('Tasks',report.tasks.map(t=>({store:t.store_name,task_id:t.assignment_id,supplier:t.supplier_name,assigned_at:t.assigned_at,deadline:t.due_at,status:t.state,first_submission:t.first_submitted_at,latest_submission:t.latest_submitted_at,required_products:t.required_products,saved_products:t.saved_products})));
 add('Stock Details',report.stock.map(r=>({store:r.store_name,product_id:r.product_id,sku:r.sku,product:r.product_name,supplier:r.supplier,expiration_date:day(r.expiration_date),quantity:num(r.quantity),landed_cost:r.landed_cost,value:r.stock_value,bucket:r.bucket,report_status:r.report_status,reported_action:r.reported_action,remarks:r.report_remarks})));
 add('Expired Reports',report.reports.map(r=>({store:r.store_name,product_id:r.product_id,product:r.product_name,expiry:day(r.expiration_date),quantity:r.quantity,action:r.product_status,status:r.validation_status,employee:r.employee_name,remarks:r.store_remarks,reported_at:r.reported_at,validated_at:r.validated_at,decision_remarks:r.validation_remarks})));
 add('Employee Activity',report.activities.map(r=>({store:r.store_name,employee:r.employee_name,product_id:r.product_id,source:r.source,event:r.details?.event==='TASK_SUBMIT'?'SUBMIT':'SAVE',date:r.created_at,remarks:r.remarks})));
 add('Priorities',report.priorities);add('Meeting Actions',report.actions.map(a=>({...a,meeting_action:'',meeting_owner:'',meeting_target_date:'',meeting_follow_up_status:''})));add('Comparison',comparison);add('Monthly Trend',trend);
 return XLSX.write(wb,{type:'buffer',bookType:'xlsx',compression:true});
}
function registerReports({app,pool,authenticate,adminOnly,secureRoute,transaction,accessibleStores,combinedMonitoringEntries,XLSX}){
 let busy=false,lastTick=0;
 async function capture(c,now){
  const key=month(now);
  const stores=(await c.query(`SELECT s.*,
   (SELECT MAX(r.created_at) FROM public.nems_store_remarks r WHERE LOWER(r.store_email)=LOWER(s.store_email) AND r.source IN ('STORE_ENCODING','MY_TASKS') AND COALESCE(r.details->>'event','')<>'TASK_SUBMIT') AS last_encoding_at,
   ARRAY(SELECT LOWER(as_email) FROM public.as_store_assignments a WHERE a.store_id=s.store_id) AS as_emails,
   ARRAY(SELECT LOWER(aom_email) FROM public.aom_store_assignments a WHERE a.store_id=s.store_id) AS aom_emails
   FROM public.stores s WHERE s.status='ACTIVE'`)).rows;
  const stock=(await c.query(`SELECT m.*,p.landed_cost FROM (${combinedMonitoringEntries}) m JOIN public.products p ON p.product_id=m.product_id`)).rows;
  const tasks=(await c.query(`WITH required AS (SELECT LOWER(TRIM(supplier_name)) AS supplier_key,COUNT(*)::int AS n FROM public.products WHERE status='ACTIVE' AND store_task_visible=TRUE GROUP BY LOWER(TRIM(supplier_name))),
   saved AS (SELECT pr.assignment_id,COUNT(*)::int AS n FROM public.nems_task_product_progress pr JOIN public.products p ON p.product_id=pr.product_id WHERE p.status='ACTIVE' AND p.store_task_visible=TRUE AND (pr.no_stock=TRUE OR pr.expiration_1 IS NOT NULL OR pr.expiration_2 IS NOT NULL OR pr.expiration_3 IS NOT NULL OR jsonb_array_length(COALESCE(pr.extra_expirations,'[]'::jsonb))>0) GROUP BY pr.assignment_id)
   SELECT a.*,s.store_name,s.store_email,sp.supplier_name,
   COALESCE(a.due_at,((a.due_date+1)::timestamp AT TIME ZONE 'Asia/Manila')) AS due_at,
   sub.first_submitted_at,sub.latest_submitted_at,
   COALESCE(req.n,0) AS required_products, COALESCE(sv.n,0) AS saved_products
   FROM public.nems_task_assignments a JOIN public.stores s ON s.store_id=a.store_id JOIN public.suppliers sp ON sp.supplier_id=a.supplier_id
   LEFT JOIN required req ON req.supplier_key=LOWER(TRIM(sp.supplier_name)) LEFT JOIN saved sv ON sv.assignment_id=a.assignment_id
   LEFT JOIN LATERAL (SELECT MIN(submitted_at) AS first_submitted_at,MAX(submitted_at) AS latest_submitted_at
     FROM public.nems_monitoring_submissions x WHERE x.assignment_id=a.assignment_id
     AND x.submitted_at>COALESCE((SELECT MAX(h.reopened_at) FROM public.nems_task_reopen_history h WHERE h.assignment_id=a.assignment_id),'-infinity')) sub ON TRUE`)).rows;
  const activities=(await c.query(`SELECT remark_id,store_name,store_email,product_id,assignment_id,employee_name,remarks,source,created_at,details->>'event' AS event
    FROM public.nems_store_remarks WHERE source IN ('STORE_ENCODING','MY_TASKS') AND created_at>=($1::date::timestamp AT TIME ZONE 'Asia/Manila')`,[key])).rows.map(r=>({...r,details:{event:r.event}}));
  const reports=(await c.query(`SELECT r.*,p.product_name FROM public.nems_expired_status_reports r LEFT JOIN public.products p ON p.product_id=r.product_id`)).rows;
  const explanations=(await c.query(`SELECT * FROM public.nems_task_overdue_explanations`)).rows;
  const payload={stores,stock,tasks,activities,reports,explanations,captured_at:new Date(now).toISOString()};
  await c.query(`INSERT INTO public.nems_meeting_snapshots(month_key,first_captured_at,captured_at,payload) VALUES($1,$2,$2,$3::jsonb)
   ON CONFLICT(month_key) DO UPDATE SET captured_at=EXCLUDED.captured_at,payload=EXCLUDED.payload
   WHERE nems_meeting_snapshots.month_key=date_trunc('month',NOW() AT TIME ZONE 'Asia/Manila')::date`,[key,new Date(now).toISOString(),JSON.stringify(payload)]);
 }
 async function queue(c,report){
  const users=(await c.query("SELECT email,role FROM public.users WHERE status='ACTIVE' AND role IN ('AS','AOM','HEAD','ADMIN') ORDER BY LOWER(email)")).rows;
  for(const u of users){
   const stores=await accessibleStores(c,u);
   const sourceIds=new Set((report.payload.data.stores||[]).map(s=>String(s.store_id)));
   const ids=stores.map(s=>String(s.store_id)).filter(id=>sourceIds.has(id));
   if(!ids.length)continue;
   const reserved=await c.query(`INSERT INTO public.nems_meeting_deliveries(report_id,recipient_email,recipient_role,store_ids,email_id)
    VALUES($1,$2,$3,$4::jsonb,nextval(pg_get_serial_sequence('public.nems_email_notifications','email_id')))
    ON CONFLICT(report_id,recipient_email) DO NOTHING RETURNING email_id`,[report.report_id,email(u.email),u.role,JSON.stringify(ids)]);
   if(!reserved.rows.length)continue;
   await c.query(`INSERT INTO public.nems_email_notifications(email_id,recipient_email,subject,message)
    VALUES($1,$2,$3,$4)`,[reserved.rows[0].email_id,email(u.email),`NEMS ${report.report_type==='MONTHLY'?'monthly':'yearly'} meeting report · ${day(report.period_start)}`,'Report is queued. Authorized store scope will be checked before sending.']);
  }
 }
 async function tick(force=false){
  if(busy||(!force&&Date.now()-lastTick<600000))return;
  busy=true;lastTick=Date.now();
  try{await transaction(async c=>{
   await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
   const lock=(await c.query("SELECT pg_try_advisory_xact_lock(hashtextextended('nems-meeting-reports',0)) AS locked")).rows[0];
   if(!lock?.locked)return;
   const now=Date.now(),key=month(now);
   await capture(c,now);
   const snapshots=(await c.query(`SELECT s.* FROM public.nems_meeting_snapshots s WHERE s.month_key<$1::date
    AND NOT EXISTS(SELECT 1 FROM public.nems_meeting_reports r WHERE r.report_type='MONTHLY' AND r.period_start=s.month_key) ORDER BY s.month_key`,[key])).rows;
   for(const s of snapshots){
    const start=day(s.month_key),end=nextMonth(start),data={...s.payload,captured_at:s.captured_at,first_captured_at:s.first_captured_at,coverage:[{month:start,first_capture:s.first_captured_at,as_of:s.captured_at}]};
    await c.query(`INSERT INTO public.nems_meeting_reports(report_type,period_start,period_end,payload) VALUES('MONTHLY',$1,$2,$3::jsonb) ON CONFLICT(report_type,period_start) DO NOTHING`,[start,end,JSON.stringify({data})]);
   }
   const years=(await c.query(`SELECT DISTINCT EXTRACT(YEAR FROM s.month_key)::int AS year FROM public.nems_meeting_snapshots s
    WHERE s.month_key<date_trunc('year',$1::date)::date AND NOT EXISTS(SELECT 1 FROM public.nems_meeting_reports r WHERE r.report_type='YEARLY' AND r.period_start=date_trunc('year',s.month_key)::date)`,[key])).rows;
   for(const {year} of years){
    const y=String(year);
    const months=(await c.query('SELECT * FROM public.nems_meeting_snapshots WHERE month_key>=$1::date AND month_key<$2::date ORDER BY month_key',[y+'-01-01',(Number(y)+1)+'-01-01'])).rows;
    await c.query(`INSERT INTO public.nems_meeting_reports(report_type,period_start,period_end,payload) VALUES('YEARLY',$1,$2,$3::jsonb) ON CONFLICT(report_type,period_start) DO NOTHING`,[y+'-01-01',(Number(y)+1)+'-01-01',JSON.stringify({data:mergeYear(months)})]);
   }
   // Recover unscheduled deliveries after a restart; uniqueness makes this idempotent.
   const ready=(await c.query('SELECT * FROM public.nems_meeting_reports WHERE dispatched_at IS NULL ORDER BY period_start,report_type')).rows;
   for(const report of ready){await queue(c,report);await c.query('UPDATE public.nems_meeting_reports SET dispatched_at=NOW() WHERE report_id=$1',[report.report_id]);}
  });}catch(e){console.error('[NEMS meeting reports]',e.code||e.message);if(force)throw Object.assign(new Error('Report check failed. Confirm nems-reports.sql was run and check the server logs.'),{status:500});}finally{busy=false;}
 }
 async function packageFor(report,user,restrictedIds=null){
  if(!['AS','AOM','HEAD','ADMIN'].includes(user.role))throw Object.assign(new Error('Management report access required'),{status:403});
  const allowed=await accessibleStores(pool,user);
  const scope=new Set((restrictedIds||allowed.map(s=>String(s.store_id))).map(String));
  const ids=allowed.map(s=>String(s.store_id)).filter(id=>scope.has(id));
  const priorRow=(await pool.query(`SELECT payload,period_start,period_end FROM public.nems_meeting_reports WHERE report_type=$1 AND period_start<$2 ORDER BY period_start DESC LIMIT 1`,[report.report_type,report.period_start])).rows[0]||null;
  const previous=priorRow?.payload.data||null;
  const data=report.payload.data,result=buildReport(data,day(report.period_start),day(report.period_end),ids,previous);
  if(!result.compliance.length)throw Object.assign(new Error('No authorized stores in this report'),{status:403});
  const prior=previous?buildReport(previous,day(priorRow.period_start),day(priorRow.period_end),ids):null;
  const comparison=['expired_quantity','expired_value','near_expiry_quantity','near_expiry_value','overdue'].map(metric=>({metric,previous:prior?.summary[metric]??'UNAVAILABLE',current:result.summary[metric],change:prior?round(result.summary[metric]-prior.summary[metric]):'UNAVAILABLE'}));
  const trend=[];
  if(report.report_type==='YEARLY'){
   const monthly=(await pool.query(`SELECT * FROM public.nems_meeting_reports WHERE report_type='MONTHLY' AND period_start>=$1 AND period_start<$2 ORDER BY period_start`,[report.period_start,report.period_end])).rows;
   for(let n=1;n<=12;n++){const key=day(report.period_start).slice(0,4)+'-'+String(n).padStart(2,'0')+'-01',m=monthly.find(r=>day(r.period_start)===key);trend.push(m?{month:key,coverage:'RECORDED SNAPSHOT',...buildReport(m.payload.data,day(m.period_start),day(m.period_end),ids).summary}:{month:key,coverage:'UNAVAILABLE — NO SNAPSHOT'});}
  }
  return {result,buffer:workbook(XLSX,result,comparison,trend)};
 }
 async function prepareEmail(row,recipient){
  const delivery=(await pool.query(`SELECT d.*,r.report_type,r.period_start,r.period_end,r.payload FROM public.nems_meeting_deliveries d
   JOIN public.nems_meeting_reports r ON r.report_id=d.report_id WHERE d.email_id=$1 AND LOWER(d.recipient_email)=LOWER($2)`,[row.email_id,row.recipient_email])).rows[0];
  if(!delivery)throw new Error('Meeting report delivery not found');
  if(recipient.role!==delivery.recipient_role)throw new Error('Report recipient role changed; download using current access in NEMS');
  const {result,buffer}=await packageFor(delivery,recipient,delivery.store_ids);
  if(buffer.length>14*1024*1024)throw new Error('Report exceeds email attachment limit; download it inside NEMS');
  const s=result.summary;
  const name=`NEMS_${delivery.report_type}_${day(delivery.period_start)}.xlsx`;
  return {message:`${row.subject}\n\nStores: ${s.stores}\nWith encoding activity: ${s.stores_with_encoding}\nNo encoding activity recorded: ${s.stores_without_encoding}\nTasks assigned: ${s.assigned}\nSubmitted total: ${s.submitted_total}\nSubmitted on time: ${s.submitted_on_time}; late: ${s.submitted_late}\nPending: ${s.pending}; overdue: ${s.overdue} (${s.carried_over_overdue} carried over)\nExpired stock value: PHP ${s.expired_value.toFixed(2)}\nNear-expiry stock value: PHP ${s.near_expiry_value.toFixed(2)}\n\nData captured: ${result.metadata.captured_at}\nFirst capture: ${result.metadata.first_capture}. Coverage may be partial; see Read Me and Monthly Trend.\nOverdue compliance starts November 30, 2026. Saved is not submitted. See the attached Excel for store compliance, expiry details, employee activity and meeting actions. Stock values are snapshot balances, not annual sums.`,attachment:[{name,content:buffer.toString('base64')}]};
 }
 app.get('/api/meeting-reports',authenticate,secureRoute(async(req,res)=>{
  if(!['AS','AOM','HEAD','ADMIN'].includes(req.user.role))throw Object.assign(new Error('Management report access required'),{status:403});
  const rows=(await pool.query('SELECT report_id,report_type,period_start,period_end,generated_at FROM public.nems_meeting_reports ORDER BY period_start DESC,report_type LIMIT 120')).rows;
  const latest=(await pool.query('SELECT month_key,first_captured_at,captured_at FROM public.nems_meeting_snapshots ORDER BY month_key DESC LIMIT 1')).rows[0]||null;
  res.json({reports:rows,overdue_start:OVERDUE_START,current_snapshot:latest});
 }));
 app.get('/api/meeting-reports/:id/download',authenticate,secureRoute(async(req,res)=>{
  if(!/^\d+$/.test(req.params.id))throw Object.assign(new Error('Invalid report'),{status:400});
  const report=(await pool.query('SELECT * FROM public.nems_meeting_reports WHERE report_id=$1',[req.params.id])).rows[0];
  if(!report)throw Object.assign(new Error('Report not found'),{status:404});
  const {buffer}=await packageFor(report,req.user);
  res.set({'Cache-Control':'no-store','Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':`attachment; filename="NEMS_${report.report_type}_${day(report.period_start)}.xlsx"`});res.send(buffer);
 }));
 app.post('/api/admin/meeting-reports/run',authenticate,adminOnly,secureRoute(async(req,res)=>{await tick(true);res.json({message:'Report check completed. Open current reports or Email Status. Only closed reporting periods generate reports.'});}));
 return {tick,prepareEmail};
}
module.exports={registerReports,buildReport,mergeYear,workbook,taskState,overdueEligible,month,nextMonth,localDay};
