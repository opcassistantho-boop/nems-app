'use strict';
const ROLES=['ADMIN','HEAD','AS','AOM'];
const STATUSES=['NO_ACCOUNT','SETUP_INCOMPLETE','PROFILE_MISMATCH','INACTIVE','INVITED','NO_LOGIN_RECORDED','LOGGED_IN','PREVIOUS_ACTIVITY','PASSWORD_CHANGE_RECORDED'];
const LABELS={NO_ACCOUNT:'No account',SETUP_INCOMPLETE:'Account setup incomplete',PROFILE_MISMATCH:'Account / store mismatch',INACTIVE:'Account inactive',INVITED:'Invitation recorded · no login recorded',NO_LOGIN_RECORDED:'No sign-in/activity record available',LOGGED_IN:'Sign-in recorded',PREVIOUS_ACTIVITY:'Previous NEMS activity found',PASSWORD_CHANGE_RECORDED:'Store password change recorded'};
function classify(row){
 let status;
 if(!row.account_email)status='NO_ACCOUNT';
 else if(!row.profile_matches)status='PROFILE_MISMATCH';
 else if(row.account_status!=='ACTIVE')status='INACTIVE';
 else if(!row.auth_linked)status='SETUP_INCOMPLETE';
 else if(row.last_login_at||row.last_auth_sign_in_at)status='LOGGED_IN';
 else if(row.last_activity_at)status='PREVIOUS_ACTIVITY';
 else if(row.last_self_password_change_at)status='PASSWORD_CHANGE_RECORDED';
 else if(row.invitation_at)status='INVITED';
 else status='NO_LOGIN_RECORDED';
 return{...row,tracker_status:status,status_label:LABELS[status],has_account:!!row.account_email};
}
function filterRows(rows,query){
 const status=String(query.status||'ALL');if(status!=='ALL'&&!STATUSES.includes(status))throw Object.assign(Error('Invalid account status filter'),{status:400});
 const term=String(query.search||'').trim().slice(0,100).toLowerCase();
 return rows.filter(r=>(status==='ALL'||r.tracker_status===status)&&(!term||[r.store_name,r.store_email,r.employee_name,r.as_contacts,r.aom_contacts,r.status_label].join(' ').toLowerCase().includes(term)));
}
module.exports=function registerAccountTracker({app,pool,authenticate,secureRoute,storeScope,XLSX,appError}){
 const authorized=user=>{if(!ROLES.includes(user?.role))throw appError(403,'Management access required');};
 async function rowsFor(user){
   authorized(user);const scope=storeScope(user,'s');
   const data=await pool.query(`SELECT s.store_id,s.store_name,s.store_email,s.status AS store_status,
       u.email AS account_email,u.status AS account_status,
       (u.role='STORE' AND LOWER(TRIM(COALESCE(u.store_name,'')))=LOWER(TRIM(s.store_name))) AS profile_matches,
       (u.auth_user_id IS NOT NULL) AS auth_linked,u.auth_user_id AS _auth_id,
       CASE WHEN u.role='STORE' AND LOWER(TRIM(COALESCE(u.store_name,'')))=LOWER(TRIM(s.store_name)) THEN u.full_name END AS employee_name,
       l.first_recorded_login_at,l.last_login_at,COALESCE(l.successful_logins,0)::text AS successful_logins,
       i.requested_at AS invitation_at,i.delivery_status AS invitation_delivery,
       activity.last_activity_at,activity.activity_source,pa.last_self_password_change_at,admin_pw.last_admin_password_change_at,
       COALESCE(as_team.contacts,'') AS as_contacts,COALESCE(aom_team.contacts,'') AS aom_contacts
       FROM public.stores s
       LEFT JOIN LATERAL(SELECT email,store_name,role,status,auth_user_id,full_name FROM public.users WHERE LOWER(email)=LOWER(s.store_email) ORDER BY (role='STORE') DESC,email LIMIT 1) u ON TRUE
       LEFT JOIN public.nems_account_login_activity l ON LOWER(l.email)=LOWER(s.store_email) AND l.auth_user_id=u.auth_user_id AND l.role='STORE' AND LOWER(TRIM(COALESCE(l.store_name,'')))=LOWER(TRIM(s.store_name))
       LEFT JOIN LATERAL(SELECT requested_at,delivery_status FROM public.nems_password_reset_history h
         WHERE LOWER(h.recipient_email)=LOWER(s.store_email) AND h.source='NEW_ACCOUNT_INVITATION' AND h.request_status='ACCEPTED'
         ORDER BY requested_at DESC,request_id DESC LIMIT 1) i ON TRUE
       LEFT JOIN LATERAL(
         SELECT last_activity_at,activity_source FROM (
           SELECT MAX(r.created_at) AS last_activity_at,'Store employee encoding/history'::text AS activity_source
           FROM public.nems_store_remarks r WHERE LOWER(r.store_email)=LOWER(s.store_email)
             AND LOWER(r.account_email)=LOWER(s.store_email) AND LOWER(TRIM(r.store_name))=LOWER(TRIM(s.store_name))
           UNION ALL
           SELECT MAX(h.changed_at),'Store monitoring history' FROM public.nems_monitoring_history h
           WHERE LOWER(h.store_email)=LOWER(s.store_email) AND LOWER(h.changed_by)=LOWER(s.store_email)
             AND LOWER(TRIM(h.store_name))=LOWER(TRIM(s.store_name))
           UNION ALL
           SELECT MAX(sub.submitted_at),'Task submission' FROM public.nems_monitoring_submissions sub
           JOIN public.nems_task_assignments a ON a.assignment_id=sub.assignment_id
           WHERE a.store_id=s.store_id AND LOWER(sub.submitted_by)=LOWER(s.store_email)
         ) events WHERE last_activity_at IS NOT NULL ORDER BY last_activity_at DESC LIMIT 1
       ) activity ON TRUE
       LEFT JOIN LATERAL(SELECT MAX(changed_at) AS last_self_password_change_at FROM public.nems_account_password_activity p
         WHERE LOWER(p.email)=LOWER(s.store_email) AND p.auth_user_id=u.auth_user_id) pa ON TRUE
       LEFT JOIN LATERAL(SELECT MAX(completed_at) AS last_admin_password_change_at FROM public.nems_admin_password_changes p
         WHERE LOWER(p.recipient_email)=LOWER(s.store_email) AND p.change_status='CHANGED') admin_pw ON TRUE
       LEFT JOIN LATERAL(SELECT string_agg(COALESCE(NULLIF(TRIM(x.full_name),''),a.as_email)||' <'||a.as_email||'>','; ' ORDER BY a.as_email) AS contacts
         FROM public.as_store_assignments a LEFT JOIN public.users x ON LOWER(x.email)=LOWER(a.as_email) WHERE a.store_id=s.store_id) as_team ON TRUE
       LEFT JOIN LATERAL(SELECT string_agg(COALESCE(NULLIF(TRIM(x.full_name),''),a.aom_email)||' <'||a.aom_email||'>','; ' ORDER BY a.aom_email) AS contacts
         FROM public.aom_store_assignments a LEFT JOIN public.users x ON LOWER(x.email)=LOWER(a.aom_email) WHERE a.store_id=s.store_id) aom_team ON TRUE
       WHERE ${scope.sql} ORDER BY s.store_name,s.store_id`,scope.args);
   let authHistoryAvailable=true;const ids=[...new Set(data.rows.filter(r=>r.profile_matches&&r._auth_id).map(r=>r._auth_id))];let history=[];
   if(ids.length){try{history=(await pool.query('SELECT auth_user_id,last_auth_sign_in_at FROM public.nems_account_auth_history($1::uuid[])',[ids])).rows;}
     catch(e){authHistoryAvailable=false;console.warn('[NEMS account Auth history]',e.code||'UNAVAILABLE');}}
   const byId=new Map(history.map(r=>[String(r.auth_user_id),r.last_auth_sign_in_at]));
   return data.rows.map(({_auth_id,...row})=>classify({...row,last_auth_sign_in_at:row.profile_matches?byId.get(String(_auth_id))||null:null,auth_history_available:authHistoryAvailable}));
 }
 app.get('/api/account-tracker',authenticate,secureRoute(async(req,res)=>{
   const rows=await rowsFor(req.user),filtered=filterRows(rows,req.query),page=Math.max(1,parseInt(req.query.page,10)||1),limit=50;
   const summary={stores:rows.length,with_account:rows.filter(r=>r.has_account).length,without_account:rows.filter(r=>!r.has_account).length,login_recorded:rows.filter(r=>(r.last_login_at||r.last_auth_sign_in_at)&&r.profile_matches).length,previous_activity:rows.filter(r=>r.last_activity_at&&r.profile_matches).length};
   for(const code of STATUSES)summary[code]=rows.filter(r=>r.tracker_status===code).length;
   res.set('Cache-Control','no-store');res.json({records:filtered.slice((page-1)*limit,page*limit),has_more:filtered.length>page*limit,page,total:filtered.length,summary,note:'Includes historical Supabase sign-ins and existing NEMS activity, shown separately from newly tracked NEMS logins. Activity is not proof of a specific login date. Only confirmed password-change records are shown; an invitation or password-reset request does not prove a change. No record available does not mean never used.'+(rows.some(r=>!r.auth_history_available)?' Supabase sign-in history is unavailable: check nems-account-history.sql and the privileged database role.':'')});
 }));
 app.get('/api/account-tracker/export',authenticate,secureRoute(async(req,res)=>{
   const rows=filterRows(await rowsFor(req.user),req.query);
   const records=rows.map(r=>({'Store':r.store_name,'Store Email':r.store_email||'','Store Status':r.store_status,'Account Exists':r.has_account?'Yes':'No','Account Status':r.account_status||'No account','Account Matches Store':r.profile_matches?'Yes':'No','Auth Account Linked':r.auth_linked?'Yes':'No','Tracker Status':r.status_label,'AS':r.as_contacts,'AOM':r.aom_contacts,'Last Invitation Accepted At':r.invitation_at||'','Invitation Delivery Status':r.invitation_delivery||'No record','First Recorded NEMS Login':r.first_recorded_login_at||'','Last Recorded NEMS Login':r.last_login_at||'','Historical Supabase Sign-in':r.last_auth_sign_in_at||'No record available','Supabase History Available':r.auth_history_available?'Yes':'No','Previous NEMS Activity At':r.last_activity_at||'No record available','Activity Source':r.activity_source||'','Confirmed Store Password Change':r.last_self_password_change_at||'No record available','Admin Password Change Record (email)':r.last_admin_password_change_at||'No record available','Successful Logins Since Tracking Began':Number(r.successful_logins)||0}));
   const book=XLSX.utils.book_new();XLSX.utils.book_append_sheet(book,XLSX.utils.json_to_sheet(records.length?records:[{Result:'No matching stores'}]),'Store Accounts');
   XLSX.utils.book_append_sheet(book,XLSX.utils.json_to_sheet([{Note:'Sources are separate: historical Supabase sign-in, successful NEMS login recorded by the tracker, prior store activity, confirmed self password changes, and admin password-change records for the email. None of these dates are invented or substituted for another type of event.'},{Note:'Invitation/reset requests do not prove password changes. Historical store activity can predate a recreated account; admin password changes do not prove the store changed its password. Missing records do not mean never used.'},{Note:'Rows follow the current user store access and selected search/status filters. Timestamps are ISO UTC.'}]),'Notes');
   res.set({'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="NEMS_Account_Tracker.xlsx"','Cache-Control':'private, no-store'});res.send(XLSX.write(book,{type:'buffer',bookType:'xlsx'}));
 }));
 return{rowsFor};
};
module.exports.classify=classify;module.exports.filterRows=filterRows;
