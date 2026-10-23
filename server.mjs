import http from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { resolve, sep, extname } from 'node:path';
import { randomBytes, timingSafeEqual, createHmac, createHash } from 'node:crypto';

// AHRE Exam Preparation • By Cesar Ignacio
// Render web-service version. All study files, photos and question bank need authentication.
const PORT = Number(process.env.PORT || 10000);
const ROOT = resolve(process.cwd(), 'public');
const COOKIE = 'ahre_session';
const CSRF_COOKIE = 'ahre_form_nonce';
const SESSION_AGE = 60 * 60 * 24 * 7;
const attempts = new Map();
const baseHeaders = {
  'Cache-Control': 'private, no-store, max-age=0',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
};
const loginCSS = `<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100svh;background:radial-gradient(ellipse at 45% 0,#173e4b,#0b1728 65%);color:#f4f8ff;font:16px/1.5 system-ui,-apple-system,sans-serif;display:grid;place-items:center;padding:22px}main{width:min(100%,430px);padding:30px;background:#14253b;border:1px solid #30455f;border-radius:22px;box-shadow:0 18px 44px #050f1aaa}.brand{text-align:center;margin:0 0 25px}.mark{font-size:44px;font-weight:900;letter-spacing:-3px;color:#71e6c5}.brand h1{font-size:26px;line-height:1.2;margin:6px 0}.brand p{margin:8px 0;color:#b0c2d5}.by{font-weight:700;color:#71e6c5}label{display:block;margin:14px 0 6px;color:#d0deea;font-size:14px}input{display:block;width:100%;height:52px;border-radius:12px;border:1px solid #475f7b;background:#0b1728;color:white;font:inherit;padding:0 15px}input:focus-visible,button:focus-visible{outline:3px solid #71e6c5}button{width:100%;min-height:53px;border:0;border-radius:12px;background:#71e6c5;color:#082820;font-weight:800;font-size:16px;margin-top:23px;cursor:pointer}.error{background:#462b39;border-left:4px solid #ff9a98;padding:12px;border-radius:8px}.hint{margin-top:24px;font-size:12px;color:#aabed4;text-align:center}</style>`;
function makeLoginForm() {
  const nonce = randomBytes(24).toString('base64url');
  const csrf = hmac('login:' + nonce);
  const cookie = `${CSRF_COOKIE}=${nonce}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`;
  return { csrf, cookie };
}
function readCookie(req, name) {
  const found = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return found ? found.slice(name.length + 1) : '';
}
function validCsrf(req, submitted) {
  const nonce = readCookie(req, CSRF_COOKIE);
  return /^[a-zA-Z0-9_-]{32}$/.test(nonce) && /^[a-zA-Z0-9_-]{43}$/.test(submitted) && compare(submitted, hmac('login:' + nonce));
}
function showLogin(res, error=false, status=200, method='GET') {
  const form = makeLoginForm();
  reply(res, status, method === 'HEAD' ? '' : loginHTML(error, form.csrf), {
    'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': form.cookie
  });
}
function loginHTML(error=false, token='') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#0b1728"><title>Log in | AHRE Exam Preparation</title>${loginCSS}</head><body><main><div class="brand"><div class="mark">✚</div><h1>AHRE Exam Preparation</h1><p>Alberta HCA Practice Exam</p><div class="by">By Cesar Ignacio</div></div>${error?'<p class="error" role="alert">Invalid username or password, or too many attempts. Please try again later.</p>':''}<form action="/login" method="post"><input type="hidden" name="csrf" value="${token}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="120" placeholder="Enter username"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="500" placeholder="Enter password"><button type="submit">Log in →</button></form><p class="hint">For students with shared login details. Scores stay on this device.</p></main></body></html>`;
}
function reply(res,status,body,headers={}) {res.writeHead(status,{...baseHeaders,...headers});res.end(body);}
function redirect(res,cookie) {const h={Location:'/'};if(cookie)h['Set-Cookie']=cookie;reply(res,303,'',h);}
function compare(a,b) {const aa=createHash('sha256').update(a).digest(),bb=createHash('sha256').update(b).digest();return timingSafeEqual(aa,bb);}
function ver() {return createHash('sha256').update(process.env.LOGIN_PASSWORD).digest('hex');}
function hmac(s) {return createHmac('sha256',process.env.SESSION_SECRET).update(s).digest('base64url');}
function session() {const exp=Math.floor(Date.now()/1000)+SESSION_AGE;return `${exp}.${hmac(`${exp}.${ver()}`)}`;}
function isAuthed(req) {const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));if(!raw)return false;const tok=raw.slice(COOKIE.length+1);const m=/^(\d{10,12})\.([A-Za-z0-9_-]{43})$/.exec(tok);if(!m)return false;const exp=Number(m[1]),now=Math.floor(Date.now()/1000);if(exp<now||exp>now+SESSION_AGE+120)return false;return compare(m[2],hmac(`${exp}.${ver()}`));}
// Browser form posts use a signed, first-party cookie-bound CSRF token instead of
// comparing Origin/Host, which can be rewritten by reverse proxies or mobile browsers.
function getIp(req) {return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim().slice(0,80);}
function checkRate(req) {const ip=getIp(req),now=Date.now();let a=attempts.get(ip)||{n:0,until:now+15*60*1000};if(a.until<now)a={n:0,until:now+15*60*1000};if(attempts.size>10000)attempts.clear();attempts.set(ip,a);return a.n<15;}
function bumpRate(req) {const a=attempts.get(getIp(req));if(a)a.n++;}
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json; charset=utf-8','.webmanifest':'application/manifest+json'};
const server=http.createServer(async(req,res)=>{
  try {
    if(!process.env.LOGIN_USERNAME||!process.env.LOGIN_PASSWORD||!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32||process.env.LOGIN_PASSWORD.includes('REPLACE_WITH')||process.env.SESSION_SECRET.includes('REPLACE_WITH')) {reply(res,503,'Login secrets are not configured. Set LOGIN_USERNAME, LOGIN_PASSWORD and SESSION_SECRET on Render.',{'Content-Type':'text/plain; charset=utf-8'});return;}
    const url=new URL(req.url,'http://localhost');
    if(req.method==='POST' && (url.pathname==='/login'||url.pathname==='/logout')) {
      if(url.pathname==='/logout') {
        // SameSite=Lax session cookie is not sent on cross-site form POSTs.
        redirect(res,`${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
        return;
      }
      const chunks=[];let size=0;
      for await (const part of req) {size+=part.length;if(size>4096){reply(res,413,'Request too large');return;}chunks.push(part);}
      const form=new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
      if(!validCsrf(req,form.get('csrf')||'')) {
        console.warn('Login form CSRF validation failed; first-party form cookie missing or mismatched');
        showLogin(res,true,400);
        return;
      }
      if(!checkRate(req)) {showLogin(res,true,429);return;}
      const user=form.get('username')||'',pass=form.get('password')||'';
      if(user.length>120||pass.length>500){reply(res,400,'Invalid form');return;}
      if(!(compare(user,process.env.LOGIN_USERNAME)&&compare(pass,process.env.LOGIN_PASSWORD))) {
        bumpRate(req);showLogin(res,true,401);return;
      }
      attempts.delete(getIp(req));
      redirect(res,`${COOKIE}=${session()}; Path=/; Max-Age=${SESSION_AGE}; HttpOnly; Secure; SameSite=Lax`);
      return;
    }
    if(req.method!=='GET'&&req.method!=='HEAD'){reply(res,405,'Method not allowed',{Allow:'GET, HEAD, POST'});return;}
    if(!isAuthed(req)) {showLogin(res,false,200,req.method);return;}
    if(url.pathname==='/login'){redirect(res);return;}
    let p;try{p=decodeURIComponent(url.pathname);}catch{reply(res,400,'Bad request');return;}
    if(p.includes('\0')||p.includes('\\')){reply(res,400,'Bad request');return;}
    let file=resolve(ROOT,'.'+p);if(!file.startsWith(ROOT+sep)&&file!==ROOT){reply(res,403,'Forbidden');return;}
    if(file===ROOT)file=resolve(ROOT,'index.html');
    if(!existsSync(file)||!statSync(file).isFile()){reply(res,404,'Not found');return;}
    res.writeHead(200,{...baseHeaders,'Content-Type':mime[extname(file).toLowerCase()]||'application/octet-stream'});
    if(req.method==='HEAD')res.end();else createReadStream(file).pipe(res);
  }catch(err){console.error('Request error:',err.message);if(!res.headersSent)reply(res,500,'Internal error');else res.destroy();}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`AHRE web service ready on port ${PORT}`));
