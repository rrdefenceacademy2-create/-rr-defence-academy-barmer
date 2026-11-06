/**
 * RR DEFENCE ACADEMY BARMER — Razorpay + Firebase Auth + Cloudflare D1
 * No real checkout unless PAYMENTS_ENABLED=true and API keys are configured.
 * Node >=22 / Cloudflare Workers, no runtime npm dependencies.
 */
const PRICE_PAISE=19900;
const PRODUCT='mega30_v1';
const TE= new TextEncoder();
let cachedKeys=null, cachedKeysUntil=0;
function json(data,status=200,origin=null){
 const h={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
 if(origin){h['Access-Control-Allow-Origin']=origin;h['Vary']='Origin';}
 return new Response(JSON.stringify(data),{status,headers:h});
}
function err(status,message,origin){return json({error:message},status,origin)}
function getOrigin(request,env){const o=request.headers.get('Origin');return o&&o===env.SITE_ORIGIN?o:null}
function isAllowed(request,env){const o=request.headers.get('Origin');return !o || o===env.SITE_ORIGIN}
function isCfg(env){const mode=env.RAZORPAY_MODE;const k=env.RAZORPAY_KEY_ID||'';const keysMatch=mode==='test'?k.startsWith('rzp_test_'):mode==='live'&&k.startsWith('rzp_live_');return Boolean(env.DB&&env.FIREBASE_PROJECT_ID&&keysMatch&&env.RAZORPAY_KEY_SECRET&&env.RAZORPAY_WEBHOOK_SECRET)}
function enabled(env){return env.PAYMENTS_ENABLED==='true'&&env.POLICIES_READY==='true'&&isCfg(env)}
function hex2bytes(s){if(typeof s!=='string'||!/^[0-9a-f]{64}$/i.test(s))return null;return Uint8Array.from(s.match(/../g),p=>parseInt(p,16))}
async function hmacValid(secret,content,signature){let bytes=hex2bytes(signature);if(!bytes||!secret)return false;const key=await crypto.subtle.importKey('raw',TE.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);return crypto.subtle.verify('HMAC',key,bytes,TE.encode(content))}
function b64(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))}
function decodeJson(s){return JSON.parse(new TextDecoder().decode(b64(s)))}
async function firebaseUser(request,env){
 const token=request.headers.get('Authorization')?.match(/^Bearer ([-\w.]+)$/)?.[1];
 if(!token||!env.FIREBASE_PROJECT_ID)throw new Error('LOGIN_REQUIRED');
 const parts=token.split('.');if(parts.length!==3)throw new Error('LOGIN_REQUIRED');
 const header=decodeJson(parts[0]), payload=decodeJson(parts[1]);
 if(header.alg!=='RS256'||typeof header.kid!=='string')throw new Error('LOGIN_REQUIRED');
 const now=Math.floor(Date.now()/1000),id=env.FIREBASE_PROJECT_ID;
 if(payload.email_verified!==true||payload.aud!==id||payload.iss!==`https://securetoken.google.com/${id}`||typeof payload.sub!=='string'||!payload.sub||payload.sub.length>128||typeof payload.exp!=='number'||payload.exp<=now||typeof payload.iat!=='number'||payload.iat>now||typeof payload.auth_time!=='number'||payload.auth_time>now)throw new Error('LOGIN_REQUIRED');
 if(!cachedKeys||Date.now()>cachedKeysUntil){
  const r=await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  if(!r.ok)throw new Error('AUTH_NOT_AVAILABLE');
  const j=await r.json();cachedKeys=j.keys;cachedKeysUntil=Date.now()+Math.min(3600,Math.max(120,parseInt(r.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1]||'600')))*1000;
 }
 const jwk=cachedKeys.find(k=>k.kid===header.kid);if(!jwk)throw new Error('LOGIN_REQUIRED');
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,b64(parts[2]),TE.encode(parts[0]+'.'+parts[1])))throw new Error('LOGIN_REQUIRED');
 return payload.sub;
}
async function bodyJson(request,limit=20000){const raw=await request.text();if(raw.length>limit)throw new Error('BODY_TOO_LARGE');return JSON.parse(raw)}
function idValid(s){return typeof s==='string'&&/^[a-z0-9_\-]{2,40}$/.test(s)}
async function razorpay(env,path,method='GET',payload=null){
 const r=await fetch('https://api.razorpay.com/v1'+path,{method,headers:{'Authorization':'Basic '+btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`),'Content-Type':'application/json'},body:payload?JSON.stringify(payload):undefined});
 const val=await r.json().catch(()=>({}));if(!r.ok)throw new Error('GATEWAY_'+r.status);return val;
}
async function hasPass(db,uid){const r=await db.prepare('SELECT order_id FROM entitlements WHERE uid=? AND product=? AND active=1').bind(uid,PRODUCT).first();return Boolean(r)}
async function applyCaptured(db,order,paymentId){
 if(order.status==='refunded')return false;
 // D1 batch provides transactional write and idempotent entitlement creation.
 await db.batch([
  db.prepare("UPDATE purchase_orders SET status='paid',payment_id=? WHERE order_id=? AND status <> 'refunded'").bind(paymentId,order.order_id),
  // Grant only if the order is STILL paid in this transaction; a stale
  // pre-refund order snapshot must never reactivate an entitlement.
  db.prepare(`INSERT INTO entitlements(uid,product,order_id,active,created_at)
    SELECT uid, ?, order_id, 1, ? FROM purchase_orders WHERE order_id=? AND status='paid'
    ON CONFLICT(uid,product) DO UPDATE SET active=1,order_id=excluded.order_id`).bind(PRODUCT,Date.now(),order.order_id)
 ]);
 return true;
}
async function revokeRefund(db,order){
 await db.prepare("UPDATE purchase_orders SET status='refunded' WHERE order_id=?").bind(order.order_id).run();
 const other=await db.prepare("SELECT order_id FROM purchase_orders WHERE uid=? AND status='paid' AND order_id<>? LIMIT 1").bind(order.uid,order.order_id).first();
 if(!other)await db.prepare('UPDATE entitlements SET active=0 WHERE uid=? AND product=?').bind(order.uid,PRODUCT).run();
}
async function webhook(request,env){
 if(!env.RAZORPAY_WEBHOOK_SECRET)return err(503,'Webhook is not configured');
 const raw=await request.text();if(raw.length>200000)return err(413,'Too large');
 if(!await hmacValid(env.RAZORPAY_WEBHOOK_SECRET,raw,request.headers.get('X-Razorpay-Signature')))return err(400,'Invalid webhook signature');
 const data=JSON.parse(raw);
 if(data.event==='payment.captured'){
  const p=data.payload?.payment?.entity;
  if(p?.id&&p?.order_id&&p.amount===PRICE_PAISE&&p.currency==='INR'&&p.status==='captured'){
   // A webhook payload may be replayed or arrive after a refund. Require the
   // gateway's CURRENT payment state before granting an entitlement.
   const actual=await razorpay(env,'/payments/'+encodeURIComponent(p.id));
   if(actual.id===p.id&&actual.order_id===p.order_id&&actual.amount===PRICE_PAISE&&actual.currency==='INR'&&actual.status==='captured'){
    const order=await env.DB.prepare('SELECT * FROM purchase_orders WHERE order_id=?').bind(p.order_id).first();
    if(order&&order.amount===PRICE_PAISE&&order.currency==='INR')await applyCaptured(env.DB,order,p.id);
   }
  }
 }
 if(data.event==='payment.refunded'||data.event==='refund.processed'){
  const p=data.event==='payment.refunded'?data.payload?.payment?.entity:null;
  const refund=data.event==='refund.processed'?data.payload?.refund?.entity:null;
  const paymentId=p?.id||refund?.payment_id;
  if(paymentId){
   // Confirm full refund from gateway (partial refunds must NOT remove access).
   const actual=await razorpay(env,'/payments/'+encodeURIComponent(paymentId));
   if(actual.status==='refunded'&&actual.amount_refunded>=PRICE_PAISE){
    // Refund events can arrive BEFORE the capture webhook has recorded the
    // payment_id. The confirmed payment's order_id still identifies the order.
    const order=await env.DB.prepare('SELECT * FROM purchase_orders WHERE payment_id=? OR order_id=?').bind(paymentId,actual.order_id||'').first();
    if(order&&order.amount===PRICE_PAISE&&order.currency==='INR')await revokeRefund(env.DB,order);
   }
  }
 }
 return json({ok:true});
}
async function resultFor(db,uid,testId){
 const a=await db.prepare('SELECT * FROM attempts WHERE uid=? AND test_id=?').bind(uid,testId).first();
 if(!a||a.submitted_at===null)return null;
 const t=await db.prepare('SELECT questions_json FROM exams WHERE id=?').bind(testId).first();
 const qs=JSON.parse(t.questions_json);
 return {testId,score:a.score,outOf:qs.length*2,answers:JSON.parse(a.answers_json),key:qs.map(q=>q.correct),submittedAt:a.submitted_at};
}
async function adminOk(request,env){const key=request.headers.get('X-Admin-Key');if(!env.ADMIN_SECRET||!key)return false;const a=await crypto.subtle.digest('SHA-256',TE.encode(key));const b=await crypto.subtle.digest('SHA-256',TE.encode(env.ADMIN_SECRET));return a.byteLength===b.byteLength&&new Uint8Array(a).every((x,i)=>x===new Uint8Array(b)[i])}

// Google Play in-app purchases (separate from Razorpay web checkout).
const PLAY_PRODUCT='rrda_mega30_199';
const PLAY_PACKAGE='com.rrdefenceacademy.barmer';
let playAccessToken='',playAccessUntil=0;
function playEnabled(env){return env.PLAY_PURCHASES_ENABLED==='true'&&env.POLICIES_READY==='true'&&Boolean(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON&&env.DB&&env.FIREBASE_PROJECT_ID)}
function base64url(raw){let b='';for(const c of new Uint8Array(raw))b+=String.fromCharCode(c);return btoa(b).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}
async function playToken(env){
 if(playAccessToken&&Date.now()<playAccessUntil)return playAccessToken;
 const sa=JSON.parse(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON);
 if(!sa.client_email||!sa.private_key)throw Error('PLAY_SERVICE_ACCOUNT_INVALID');
 const now=Math.floor(Date.now()/1000);
 const header=base64url(TE.encode(JSON.stringify({alg:'RS256',typ:'JWT'})));
 const payload=base64url(TE.encode(JSON.stringify({iss:sa.client_email,scope:'https://www.googleapis.com/auth/androidpublisher',aud:'https://oauth2.googleapis.com/token',iat:now,exp:now+3500})));
 const keyRaw=Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----|\s/g,'')),x=>x.charCodeAt(0));
 const key=await crypto.subtle.importKey('pkcs8',keyRaw,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
 const sig=base64url(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,TE.encode(`${header}.${payload}`)));
 const response=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion:`${header}.${payload}.${sig}`})});
 if(!response.ok)throw Error('PLAY_OAUTH_'+response.status);
 const data=await response.json();playAccessToken=data.access_token;playAccessUntil=Date.now()+Math.max(60,(Number(data.expires_in)||3600)-120)*1000;return playAccessToken;
}
async function playGet(env,token,ack=false){
 const url=`https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PLAY_PACKAGE}/purchases/products/${PLAY_PRODUCT}/tokens/${encodeURIComponent(token)}${ack?'/acknowledge':''}`;
 const response=await fetch(url,{method:ack?'POST':'GET',headers:{Authorization:'Bearer '+await playToken(env),...(ack?{'Content-Type':'application/json'}:{})},body:ack?'{}':undefined});
 if(!response.ok)throw Error('PLAY_PURCHASE_API_'+response.status);
 return ack?{}:response.json();
}
async function verifyPlay(request,env,uid,origin){
 if(!playEnabled(env))return err(503,'Google Play billing not configured',origin);
 const data=await bodyJson(request,12000);
 const token=data.purchaseToken;
 if(data.productId!==PLAY_PRODUCT||typeof token!=='string'||token.length<8||token.length>8192||!/^[a-zA-Z0-9.\-_]+$/.test(token))return err(400,'Invalid purchase',origin);
 const state=await playGet(env,token);
 if(state.purchaseState!==0)return err(409,'Purchase is not completed',origin);
 const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',TE.encode(token)))).map(b=>b.toString(16).padStart(2,'0')).join('');
 const prev=await env.DB.prepare('SELECT uid FROM play_purchases WHERE token_hash=?').bind(hash).first();
 if(prev&&prev.uid!==uid)return err(403,'This purchase belongs to another account',origin);
 await env.DB.batch([
  env.DB.prepare('INSERT OR IGNORE INTO play_purchases(token_hash,uid,product_id,created_at) VALUES(?,?,?,?)').bind(hash,uid,PLAY_PRODUCT,Date.now()),
  env.DB.prepare(`INSERT INTO entitlements(uid,product,order_id,active,created_at) VALUES(?,?,?,?,?) ON CONFLICT(uid,product) DO UPDATE SET active=1,order_id=excluded.order_id`).bind(uid,PRODUCT,'play_'+hash.slice(0,50),1,Date.now())
 ]);
 if(state.acknowledgementState===0)await playGet(env,token,true);
 return json({ok:true,unlocked:true},200,origin);
}

async function api(request,env,ctx){
 const url=new URL(request.url),path=url.pathname,origin=getOrigin(request,env),method=request.method;
 if(method==='OPTIONS'){
  if(!isAllowed(request,env))return err(403,'Origin not allowed');
  return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':origin||'null','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Authorization, Content-Type, X-Admin-Key','Access-Control-Max-Age':'600','Vary':'Origin'}});
 }
 if(!isAllowed(request,env))return err(403,'Origin not allowed');
 if(path==='/api/health'&&method==='GET')return json({ok:true,service:'RR Defence Academy payment backend',mode:env.RAZORPAY_MODE==='live'?'live':'test'},200,origin);
 if(path==='/api/config'&&method==='GET')return json({name:'RR DEFENCE ACADEMY BARMER',amount:PRICE_PAISE,currency:'INR',package:'30 Mega Tests',gatewayReady:enabled(env),mode:env.RAZORPAY_MODE==='live'?'live':'test',playBillingReady:playEnabled(env),keyId:enabled(env)?env.RAZORPAY_KEY_ID:null},200,origin);
 if(path==='/api/webhook'&&method==='POST')return webhook(request,env);
 if(!env.DB)return err(503,'Database is not configured',origin);
 if(path==='/api/admin/tests'&&method==='POST'){
  if(!await adminOk(request,env))return err(403,'Admin access denied',origin);
  const p=await bodyJson(request,120000);if(!idValid(p.id)||typeof p.title!=='string'||p.title.length>100||!Array.isArray(p.questions)||p.questions.length!==50)return err(400,'Invalid test: require 50 questions',origin);
  const questions=p.questions.map(q=>({q:q.q,options:q.options,correct:q.correct}));
  if(!questions.every(q=>typeof q.q==='string'&&q.q.length<700&&Array.isArray(q.options)&&q.options.length===4&&q.options.every(s=>typeof s==='string'&&s.length<350)&&Number.isInteger(q.correct)&&q.correct>=0&&q.correct<=3))return err(400,'Invalid questions',origin);
  const used=await env.DB.prepare('SELECT test_id FROM attempts WHERE test_id=? LIMIT 1').bind(p.id).first();
  if(used)return err(409,'Test already attempted; publish a new version instead of overwriting',origin);
  await env.DB.prepare('INSERT INTO exams(id,title,questions_json,published) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,questions_json=excluded.questions_json,published=excluded.published').bind(p.id,p.title,JSON.stringify(questions),p.published===true?1:0).run();
  return json({ok:true,id:p.id,published:p.published===true},200,origin);
 }
 if(path==='/api/tests'&&method==='GET'){
  const qs=await env.DB.prepare('SELECT id,title,published FROM exams WHERE published=1 ORDER BY id').all();return json({tests:qs.results||[]},200,origin);
 }
 let uid;try{uid=await firebaseUser(request,env);}catch(e){return err(e.message==='AUTH_NOT_AVAILABLE'?503:401,'Please sign in again',origin)}
 if(path==='/api/googleplay/verify'&&method==='POST')return verifyPlay(request,env,uid,origin);
 if(path==='/api/me'&&method==='GET')return json({uid,unlocked:await hasPass(env.DB,uid)},200,origin);
 if(path==='/api/order'&&method==='POST'){
  if(!enabled(env))return err(503,'Payment checkout is not active yet',origin);
  if(await hasPass(env.DB,uid))return json({alreadyUnlocked:true},200,origin);
  const recent=await env.DB.prepare("SELECT order_id FROM purchase_orders WHERE uid=? AND status='created' AND created_at>? ORDER BY created_at DESC LIMIT 1").bind(uid,Date.now()-2*60*1000).first();
  if(recent)return json({keyId:env.RAZORPAY_KEY_ID,orderId:recent.order_id,amount:PRICE_PAISE,currency:'INR'},200,origin);
  const receipt='rrda_'+crypto.randomUUID().replaceAll('-','').slice(0,25);
  const order=await razorpay(env,'/orders','POST',{amount:PRICE_PAISE,currency:'INR',receipt,partial_payment:false,notes:{product:PRODUCT}});
  if(!order.id||order.amount!==PRICE_PAISE||order.currency!=='INR')return err(502,'Invalid gateway order',origin);
  await env.DB.prepare('INSERT INTO purchase_orders(order_id,uid,amount,currency,status,created_at) VALUES(?,?,?,?,?,?)').bind(order.id,uid,PRICE_PAISE,'INR','created',Date.now()).run();
  return json({keyId:env.RAZORPAY_KEY_ID,orderId:order.id,amount:PRICE_PAISE,currency:'INR'},200,origin);
 }
 if(path==='/api/verify'&&method==='POST'){
  if(!enabled(env))return err(503,'Checkout unavailable',origin);
  const x=await bodyJson(request);
  if(!/^order_[A-Za-z0-9]+$/.test(x.razorpay_order_id||'')||!/^pay_[A-Za-z0-9]+$/.test(x.razorpay_payment_id||''))return err(400,'Invalid identifiers',origin);
  const order=await env.DB.prepare('SELECT * FROM purchase_orders WHERE order_id=? AND uid=?').bind(x.razorpay_order_id,uid).first();
  if(!order||order.amount!==PRICE_PAISE||order.currency!=='INR'||order.status==='refunded')return err(403,'Order not owned by this student',origin);
  if(!await hmacValid(env.RAZORPAY_KEY_SECRET,order.order_id+'|'+x.razorpay_payment_id,x.razorpay_signature))return err(400,'Signature mismatch',origin);
  const payment=await razorpay(env,'/payments/'+encodeURIComponent(x.razorpay_payment_id));
  if(payment.order_id!==order.order_id||payment.amount!==PRICE_PAISE||payment.currency!=='INR'||payment.status!=='captured')return err(409,'Payment is not captured yet; check back later',origin);
  await applyCaptured(env.DB,order,payment.id);
  return json({ok:true,unlocked:true},200,origin);
 }
 const match=path.match(/^\/api\/tests\/([a-z0-9_\-]{2,40})\/(start|submit|result)$/);
 if(match){
  const [_,testId,action]=match;
  if(!await hasPass(env.DB,uid))return err(402,'Buy package to unlock tests',origin);
  const t=await env.DB.prepare('SELECT * FROM exams WHERE id=? AND published=1').bind(testId).first();if(!t)return err(404,'Test not published',origin);
  const qs=JSON.parse(t.questions_json);
  if(action==='start'&&method==='POST'){
   const now=Date.now();
   await env.DB.prepare('INSERT OR IGNORE INTO attempts(uid,test_id,started_at,deadline,submitted_at,score,answers_json) VALUES(?,?,?,?,NULL,NULL,NULL)').bind(uid,testId,now,now+3600000).run();
   const a=await env.DB.prepare('SELECT * FROM attempts WHERE uid=? AND test_id=?').bind(uid,testId).first();
   if(a.submitted_at!==null)return json({finished:true,score:a.score},200,origin);
   if(now>a.deadline)return err(409,'Time expired: contact admin for review',origin);
   return json({testId,title:t.title,deadline:a.deadline,questions:qs.map(({q,options},i)=>({number:i+1,q,options}))},200,origin);
  }
  if(action==='submit'&&method==='POST'){
   const a=await env.DB.prepare('SELECT * FROM attempts WHERE uid=? AND test_id=?').bind(uid,testId).first();if(!a)return err(400,'Start the test first',origin);
   if(a.submitted_at!==null)return json({alreadySubmitted:true,score:a.score},200,origin);
   const x=await bodyJson(request,10000),answers=x.answers;
   if(!Array.isArray(answers)||answers.length!==qs.length||!answers.every(v=>v===null||[0,1,2,3].includes(v)))return err(400,'Invalid answer sheet',origin);
   const now=Date.now();if(now>a.deadline+30000)return err(409,'Test time expired; contact admin',origin);
   const score=answers.reduce((sum,v,i)=>sum+(v===qs[i].correct?2:0),0);
   const done=await env.DB.prepare('UPDATE attempts SET submitted_at=?,score=?,answers_json=? WHERE uid=? AND test_id=? AND submitted_at IS NULL').bind(now,score,JSON.stringify(answers),uid,testId).run();
   if(done.meta?.changes===0){const prev=await resultFor(env.DB,uid,testId);return json({alreadySubmitted:true,score:prev?.score},200,origin)}
   return json({ok:true,score,outOf:qs.length*2},200,origin);
  }
  if(action==='result'&&method==='GET'){
   const result=await resultFor(env.DB,uid,testId);if(!result)return err(404,'No completed attempt yet',origin);return json(result,200,origin);
  }
 }
 return err(404,'Not found',origin);
}
export default {async fetch(request,env,ctx){
  try{return await api(request,env,ctx)}catch(e){
   const origin=getOrigin(request,env);
   if(e.message==='BODY_TOO_LARGE')return err(413,'Payload too large',origin);
   if(e instanceof SyntaxError)return err(400,'Malformed JSON',origin);
   console.error('RRDA_API_ERROR',String(e?.message||e).replace(/[\r\n]/g,''));
   return err(500,'Server error; retry or contact academy',origin);
  }
}};
export const internalForTests={hmacValid,hex2bytes,applyCaptured,PRICE_PAISE};
