'use strict';
const crypto=require('crypto');
const MAX_FILE=5*1024*1024,MAX_TOTAL=10*1024*1024,MAX_COUNT=3;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TYPES={pdf:'application/pdf',xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',xls:'application/vnd.ms-excel',csv:'text/csv',docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',doc:'application/msword',pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',ppt:'application/vnd.ms-powerpoint',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',txt:'text/plain'};
function inspect(name,buffer){
 name=String(name||'').normalize('NFC').split(/[\\/]/).at(-1).replace(/[\x00-\x1f\x7f]/g,'').trim();
 if(!name||name.length>180)throw Object.assign(Error('Use a filename of 1–180 characters.'),{status:400});
 const ext=name.split('.').at(-1).toLowerCase(),mime=TYPES[ext];
 if(!mime)throw Object.assign(Error('Allowed: Excel, CSV, PDF, Word, PowerPoint, PNG, JPG and TXT.'),{status:400});
 if(!Buffer.isBuffer(buffer)||!buffer.length||buffer.length>MAX_FILE)throw Object.assign(Error('Each attachment must be between 1 byte and 5 MB.'),{status:400});
 let good=true;
 if(ext==='pdf')good=buffer.subarray(0,5).toString()==='%PDF-';
 if(['xlsx','docx','pptx'].includes(ext))good=buffer.length>=4&&buffer.readUInt32LE(0)===0x04034b50;
 if(['xls','doc','ppt'].includes(ext))good=buffer.subarray(0,8).equals(Buffer.from('d0cf11e0a1b11ae1','hex'));
 if(ext==='png')good=buffer.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'));
 if(ext==='jpg'||ext==='jpeg')good=buffer.length>=3&&buffer[0]===255&&buffer[1]===216&&buffer[2]===255;
 if(ext==='csv'||ext==='txt')good=!buffer.includes(0);
 if(!good)throw Object.assign(Error('The file contents do not match its extension. Export or save the file again.'),{status:400});
 return{name,mime,size:buffer.length,hash:crypto.createHash('sha256').update(buffer).digest('hex')};
}
function idsOf(value){if(value===undefined)return[];if(!Array.isArray(value)||value.length>MAX_COUNT||value.some(x=>typeof x!=='string'||!UUID.test(x))||new Set(value).size!==value.length)throw Object.assign(Error('Choose up to 3 valid attachments.'),{status:400});return value;}
module.exports=function createAttachments({pool,app,express,authenticate,secureRoute,requireStore,accessibleStores,appError}){
 async function authorize(user,messageId){
   if(!/^\d+$/.test(String(messageId)))throw appError(400,'Invalid message');
   const result=await pool.query(`SELECT m.message_id,c.store_id FROM public.nems_messages m JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id WHERE m.message_id=$1 AND (
       $3::boolean OR LOWER(m.sender_email)=LOWER($2) OR EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND LOWER(n.recipient_email)=LOWER($2)) OR
       NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND n.title LIKE 'NEMS direct message · %'))`,[messageId,user.email,['ADMIN','HEAD'].includes(user.role)]);
   if(!result.rowCount)throw appError(404,'Message not available');await requireStore(pool,user,result.rows[0].store_id);return result.rows[0];
 }
 async function enrich(rows,client=pool){
   if(!rows.length)return rows;const ids=rows.map(r=>r.message_id);
   const files=await client.query(`SELECT l.message_id,f.file_id,f.file_name,f.content_type,f.size_bytes FROM public.nems_message_file_links l JOIN public.nems_message_files f ON f.file_id=l.file_id WHERE l.message_id=ANY($1::bigint[]) ORDER BY f.file_name,f.file_id`,[ids]);
   const map=new Map();for(const f of files.rows){const id=String(f.message_id);if(!map.has(id))map.set(id,[]);map.get(id).push({file_id:f.file_id,file_name:f.file_name,content_type:f.content_type,size_bytes:f.size_bytes});}return rows.map(r=>({...r,attachments:map.get(String(r.message_id))||[]}));
 }
 async function claim(client,owner,ids){
   ids=idsOf(ids);if(!ids.length)return[];
   const r=await client.query(`SELECT file_id,file_name,size_bytes FROM public.nems_message_files WHERE file_id=ANY($1::uuid[]) AND LOWER(owner_email)=LOWER($2) ORDER BY file_id FOR UPDATE`,[ids,owner]);
   if(r.rows.length!==ids.length)throw appError(403,'An attachment is unavailable or belongs to another account');
   if(r.rows.reduce((n,f)=>n+Number(f.size_bytes),0)>MAX_TOTAL)throw appError(400,'Attachments together must not exceed 10 MB');return r.rows;
 }
 async function link(client,messageIds,files){if(files.length&&messageIds.length)await client.query(`INSERT INTO public.nems_message_file_links(message_id,file_id) SELECT m.id,f.id FROM unnest($1::bigint[]) m(id) CROSS JOIN unnest($2::uuid[]) f(id) ON CONFLICT DO NOTHING`,[messageIds,files.map(f=>f.file_id)]);}
 let uploads=0;const uploadOwners=new Set();
 const uploadGate=(req,res,next)=>{const owner=String(req.user.email).toLowerCase();if(uploads>=3||uploadOwners.has(owner))return res.status(429).json({error:'Another upload is processing. Wait a moment and try again.'});uploads++;uploadOwners.add(owner);let released=false;const release=()=>{if(released)return;released=true;uploads--;uploadOwners.delete(owner);};res.once('finish',release);res.once('close',release);next();};
 app.post('/api/message-files',authenticate,uploadGate,express.raw({type:'application/octet-stream',limit:MAX_FILE}),secureRoute(async(req,res)=>{
   if(!['STORE','AS','AOM','HEAD','ADMIN'].includes(req.user.role))throw appError(403,'Message access required');
   if(!(await accessibleStores(pool,req.user)).length)throw appError(403,'No authorized store conversations');
   let name;try{name=decodeURIComponent(req.get('X-File-Name')||'');}catch(_){throw appError(400,'Invalid filename');}
   const f=inspect(name,req.body),id=crypto.randomUUID(),client=await pool.connect();
   try{await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(hashtextextended('nems-message-files-quota',0))");
     // Only abandoned uploads are removed; files attached to messages are retained.
     await client.query(`DELETE FROM public.nems_message_files f WHERE f.file_id IN (SELECT x.file_id FROM public.nems_message_files x WHERE x.created_at<NOW()-INTERVAL '24 hours' AND NOT EXISTS(SELECT 1 FROM public.nems_message_file_links l WHERE l.file_id=x.file_id) ORDER BY x.created_at LIMIT 50)`);
     const used=Number((await client.query(`SELECT COALESCE(SUM(size_bytes),0)::text AS bytes FROM public.nems_message_files`)).rows[0].bytes);
     const cap=Math.max(10,Math.min(1000,Number(process.env.NEMS_MESSAGE_FILES_MB)||100))*1024*1024;
     if(used+f.size>cap)throw appError(413,'Attachment storage is full. Contact ADMIN; text messages remain available.');
     await client.query(`INSERT INTO public.nems_message_files(file_id,owner_email,file_name,content_type,size_bytes,sha256,file_data) VALUES($1,LOWER($2),$3,$4,$5,$6,$7)`,[id,req.user.email,f.name,f.mime,f.size,f.hash,req.body]);await client.query('COMMIT');res.status(201).json({file_id:id,file_name:f.name,size_bytes:f.size});
   }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 }));
 app.get('/api/message-files/message/:messageId',authenticate,secureRoute(async(req,res)=>{await authorize(req.user,req.params.messageId);const rows=await enrich([{message_id:req.params.messageId}]);res.set('Cache-Control','no-store');res.json(rows[0].attachments);}));
 let downloads=0;const downloadGate=(req,res,next)=>{if(downloads>=8)return res.status(429).json({error:'Downloads are busy. Try again shortly.'});downloads++;let released=false;const release=()=>{if(!released){released=true;downloads--;}};res.once('finish',release);res.once('close',release);next();};
 app.get('/api/message-files/:fileId/download',authenticate,downloadGate,secureRoute(async(req,res)=>{
   if(!UUID.test(req.params.fileId))throw appError(400,'Invalid attachment');
   const stores=await accessibleStores(pool,req.user);
   const permitted=await pool.query(`SELECT 1 FROM public.nems_message_file_links l JOIN public.nems_messages m ON m.message_id=l.message_id JOIN public.nems_conversations c ON c.conversation_id=m.conversation_id
       WHERE l.file_id=$1 AND c.store_id=ANY($4::bigint[]) AND ($3::boolean OR LOWER(m.sender_email)=LOWER($2) OR
       EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND LOWER(n.recipient_email)=LOWER($2)) OR
       NOT EXISTS(SELECT 1 FROM public.nems_notifications n WHERE n.reference_type='MESSAGE' AND n.reference_id=m.message_id AND n.title LIKE 'NEMS direct message · %')) LIMIT 1`,[req.params.fileId,req.user.email,['ADMIN','HEAD'].includes(req.user.role),stores.map(s=>s.store_id)]);
   if(!permitted.rowCount)throw appError(404,'Attachment not available in your authorized conversations');
   const row=(await pool.query(`SELECT file_name,content_type,file_data FROM public.nems_message_files WHERE file_id=$1`,[req.params.fileId])).rows[0];if(!row)throw appError(404,'Attachment not found');
   const encoded=encodeURIComponent(row.file_name).replace(/[!'()*]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase());
   res.set({'Content-Type':row.content_type,'Content-Disposition':`attachment; filename="NEMS-attachment"; filename*=UTF-8''${encoded}`,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});res.send(row.file_data);
 }));
 return{claim,link,enrich};
};
module.exports.inspect=inspect;module.exports.idsOf=idsOf;
