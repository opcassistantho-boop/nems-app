'use strict';
// Only compress completed textual GET responses. No dependency/package changes.
const {gzip}=require('node:zlib');
module.exports=function bandwidth(req,res,next){
    if(req.method!=='GET'||/^\/api\/(?:login|password|me)(?:\/|$)/.test(req.path))return next();
    const send=res.send;
    res.send=function(body){
        const type=String(res.getHeader('Content-Type')||'');
        if((typeof body!=='string'&&!Buffer.isBuffer(body))||!/(?:json|javascript|text\/|svg\+xml)/i.test(type)||res.headersSent||res.statusCode!==200||res.getHeader('Content-Encoding')||/no-transform/i.test(String(res.getHeader('Cache-Control')||'')))return send.call(this,body);
        res.vary('Accept-Encoding');
        if(req.acceptsEncodings('gzip','identity')!=='gzip')return send.call(this,body);
        const data=Buffer.isBuffer(body)?body:Buffer.from(body);
        if(data.length<1024||data.length>8*1024*1024)return send.call(this,body);
        gzip(data,{level:4},(err,compressed)=>{
            if(res.destroyed||res.writableEnded)return;
            if(err||compressed.length>=data.length)return send.call(res,body);
            res.setHeader('Content-Encoding','gzip');
            res.removeHeader('Content-Length');res.removeHeader('ETag');
            send.call(res,compressed);
        });
        return this;
    };
    next();
};
