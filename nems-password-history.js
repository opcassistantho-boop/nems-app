'use strict';
const {randomUUID}=require('crypto');
module.exports=function createPasswordHistory(pool){
 const safeCode=value=>/^[A-Za-z][A-Za-z0-9_:-]{0,79}$/.test(String(value||''))?String(value):null;
 async function begin({email,source,actorEmail=null,provider}){
  const id=randomUUID();
  await pool.query(`INSERT INTO public.nems_password_reset_history
   (request_id,recipient_email,source,actor_email,provider) VALUES ($1::uuid,$2,$3,$4,$5)`,[id,email,source,actorEmail,provider]);
  return id;
 }
 async function finish(id,{state,httpStatus=null,code=null,messageId=null}){
  await pool.query(`UPDATE public.nems_password_reset_history SET request_status=$2,
   provider_http_status=$3,result_code=$4,provider_message_id=COALESCE($5,provider_message_id),completed_at=clock_timestamp()
   WHERE request_id=$1::uuid`,[id,state,httpStatus,safeCode(code),messageId?String(messageId).slice(0,500):null]);
 }
 async function event(body){
  const event=String(body.event||'');
  if(!['delivered','hard_bounce','blocked','invalid','error'].includes(event))return;
  const tags=[...(Array.isArray(body.tags)?body.tags:[]),...(typeof body.tag==='string'?body.tag.split(/[ ,]+/):[])];
  const tag=tags.find(t=>/^nems-reset-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(t)));
  const mid=body['message-id']||body.messageId;
  if(!tag&&!mid)return;
  await pool.query(`UPDATE public.nems_password_reset_history SET delivery_status=$3,
   delivered_at=CASE WHEN $3='DELIVERED' THEN COALESCE(delivered_at,clock_timestamp()) ELSE delivered_at END,
   delivery_event=$4 WHERE provider='BREVO' AND
   (request_id=$1::uuid OR ($2::text IS NOT NULL AND provider_message_id=$2)) AND delivery_status<>'DELIVERED'`,
   [tag?String(tag).slice(11):null,typeof mid==='string'?mid.slice(0,500):null,event==='delivered'?'DELIVERED':'FAILED',event]);
 }
 function register({app,authenticate,adminOnly,pageQuery}){
  app.get('/api/admin/password-reset-history',authenticate,adminOnly,async(req,res)=>{
   // Explicit guard also protects against a future incorrectly configured middleware.
   if(req.user?.role!=='ADMIN')return res.status(403).json({error:'ADMIN access required'});
   try{
    const args=[],term=String(req.query.search||'').trim().slice(0,100);
    const where=term?` WHERE POSITION(LOWER($1::text) IN LOWER(CONCAT_WS(' ',h.recipient_email,u.store_name,h.source,h.actor_email,h.provider,h.request_status,h.delivery_status,h.result_code,h.requested_at::text)))>0`:'';
    if(term)args.push(term);
    const data=await pageQuery(pool,req.query,`SELECT h.request_id,h.recipient_email,u.store_name,
     h.source,h.actor_email,h.provider,h.request_status,h.provider_http_status,h.result_code,
     h.delivery_status,h.requested_at,h.completed_at,h.delivered_at
     FROM public.nems_password_reset_history h
     LEFT JOIN LATERAL(SELECT store_name FROM public.users WHERE LOWER(email)=h.recipient_email LIMIT 1) u ON TRUE${where}`,args,'h.requested_at DESC,h.request_id DESC');
    res.set('Cache-Control','no-store');return res.json(data);
   }catch(e){console.error('[NEMS password history]',e.code||'QUERY_FAILED');return res.status(503).json({error:'Password Reset History unavailable. Check that nems-password-history.sql was installed.'});}
  });
 }
 return {begin,finish,event,register};
};
