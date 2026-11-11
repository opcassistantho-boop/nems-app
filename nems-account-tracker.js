'use strict';
const ROLES=['ADMIN','HEAD','AS','AOM'];
const STATUSES=['NO_ACCOUNT','SETUP_INCOMPLETE','PROFILE_MISMATCH','INACTIVE','INVITED','NO_LOGIN_RECORDED','LOGGED_IN'];
const LABELS={NO_ACCOUNT:'No account',SETUP_INCOMPLETE:'Account setup incomplete',PROFILE_MISMATCH:'Account / store mismatch',INACTIVE:'Account inactive',INVITED:'Invitation recorded · no login recorded',NO_LOGIN_RECORDED:'No login recorded',LOGGED_IN:'Login recorded'};
function classify(row){
 let status;
 if(!row.account_email)status='NO_ACCOUNT';
 else if(!row.profile_matches)status='PROFILE_MISMATCH';
 else if(row.account_status!=='ACTIVE')status='INACTIVE';
 else if(!row.auth_linked)status='SETUP_INCOMPLETE';
 else if(row.last_login_at)status='LOGGED_IN';
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
       (u.auth_user_id IS NOT NULL) AS auth_linked,
       CASE WHEN u.role='STORE' AND LOWER(TRIM(COALESCE(u.store_name,'')))=LOWER(TRIM(s.store_name)) THEN u.full_name END AS employee_name,
       l.first_recorded_login_at,l.last_login_at,COALESCE(l.successful_logins,0)::text AS successful_logins,
       i.requested_at AS invitation_at,i.delivery_status AS invitation_delivery,
       COALESCE(as_team.contacts,'') AS as_contacts,COALESCE(aom_team.contacts,'') AS aom_contacts
       FROM public.stores s
       LEFT JOIN LATERAL(SELECT email,store_name,role,status,auth_user_id,full_name FROM public.users WHERE LOWER(email)=LOWER(s.store_email) ORDER BY (role='STORE') DESC,email LIMIT 1) u ON TRUE
       LEFT JOIN public.nems_account_login_activity l ON LOWER(l.email)=LOWER(s.store_email) AND l.auth_user_id=u.auth_user_id AND l.role='STORE' AND LOWER(TRIM(COALESCE(l.store_name,'')))=LOWER(TRIM(s.store_name))
       LEFT JOIN LATERAL(SELECT requested_at,delivery_status FROM public.nems_password_reset_history h
         WHERE LOWER(h.recipient_email)=LOWER(s.store_email) AND h.source='NEW_ACCOUNT_INVITATION' AND h.request_status='ACCEPTED'
         ORDER BY requested_at DESC,request_id DESC LIMIT 1) i ON TRUE
       LEFT JOIN LATERAL(SELECT string_agg(COALESCE(NULLIF(TRIM(x.full_name),''),a.as_email)||' <'||a.as_email||'>','; ' ORDER BY a.as_email) AS contacts
         FROM public.as_store_assignments a LEFT JOIN public.users x ON LOWER(x.email)=LOWER(a.as_email) WHERE a.store_id=s.store_id) as_team ON TRUE
       LEFT JOIN LATERAL(SELECT string_agg(COALESCE(NULLIF(TRIM(x.full_name),''),a.aom_email)||' <'||a.aom_email||'>','; ' ORDER BY a.aom_email) AS contacts
         FROM public.aom_store_assignments a LEFT JOIN public.users x ON LOWER(x.email)=LOWER(a.aom_email) WHERE a.store_id=s.store_id) aom_team ON TRUE
       WHERE ${scope.sql} ORDER BY s.store_name,s.store_id`,scope.args);
   return data.rows.map(classify);
 }
 app.get('/api/account-tracker',authenticate,secureRoute(async(req,res)=>{
   const rows=await rowsFor(req.user),filtered=filterRows(rows,req.query),page=Math.max(1,parseInt(req.query.page,10)||1),limit=50;
   const summary={stores:rows.length,with_account:rows.filter(r=>r.has_account).length,without_account:rows.filter(r=>!r.has_account).length,login_recorded:rows.filter(r=>r.last_login_at&&r.profile_matches).length};
   for(const code of STATUSES)summary[code]=rows.filter(r=>r.tracker_status===code).length;
   res.set('Cache-Control','no-store');res.json({records:filtered.slice((page-1)*limit,page*limit),has_more:filtered.length>page*limit,page,total:filtered.length,summary,note:'Login tracking begins after deployment of this update. No login recorded does not prove that the account never logged in before. Invitation recorded means the email service accepted a request, not confirmed delivery or password setup.'});
 }));
 app.get('/api/account-tracker/export',authenticate,secureRoute(async(req,res)=>{
   const rows=filterRows(await rowsFor(req.user),req.query);
   const records=rows.map(r=>({'Store':r.store_name,'Store Email':r.store_email||'','Store Status':r.store_status,'Account Exists':r.has_account?'Yes':'No','Account Status':r.account_status||'No account','Account Matches Store':r.profile_matches?'Yes':'No','Auth Account Linked':r.auth_linked?'Yes':'No','Tracker Status':r.status_label,'AS':r.as_contacts,'AOM':r.aom_contacts,'Last Invitation Accepted At':r.invitation_at||'','Invitation Delivery Status':r.invitation_delivery||'No record','First Recorded NEMS Login':r.first_recorded_login_at||'','Last Recorded NEMS Login':r.last_login_at||'','Successful Logins Since Tracking Began':Number(r.successful_logins)||0}));
   const book=XLSX.utils.book_new();XLSX.utils.book_append_sheet(book,XLSX.utils.json_to_sheet(records.length?records:[{Result:'No matching stores'}]),'Store Accounts');
   XLSX.utils.book_append_sheet(book,XLSX.utils.json_to_sheet([{Note:'Account existence and login activity are separate. Login history starts with deployment of this update; missing records do not prove a store never logged in.'},{Note:'Invitation accepted by the email provider does not confirm delivery, password setup, or use of NEMS.'},{Note:'Rows follow the current user store access and selected search/status filters. Timestamps are ISO UTC.'}]),'Notes');
   res.set({'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','Content-Disposition':'attachment; filename="NEMS_Account_Tracker.xlsx"','Cache-Control':'private, no-store'});res.send(XLSX.write(book,{type:'buffer',bookType:'xlsx'}));
 }));
 return{rowsFor};
};
module.exports.classify=classify;module.exports.filterRows=filterRows;
