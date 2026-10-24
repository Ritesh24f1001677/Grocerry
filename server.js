const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const scrypt = promisify(crypto.scrypt);
const root = __dirname;
const dataDir = path.join(root, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'gather.sqlite'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS households (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 invite_code TEXT NOT NULL UNIQUE,
 created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS household_members (
 household_id INTEGER NOT NULL REFERENCES households(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY (household_id, user_id)
);
CREATE TABLE IF NOT EXISTS shopping_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 household_id INTEGER NOT NULL REFERENCES households(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 quantity TEXT NOT NULL DEFAULT '',
 is_bought INTEGER NOT NULL DEFAULT 0,
 added_by INTEGER NOT NULL REFERENCES users(id),
 bought_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 bought_at TEXT
);
CREATE INDEX IF NOT EXISTS items_household ON shopping_items(household_id, created_at);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
`);

const sessions = db.prepare(`SELECT users.id, users.email, users.display_name FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?`);
const memberHouse = db.prepare(`SELECT h.id,h.name,h.invite_code FROM households h JOIN household_members m ON m.household_id=h.id WHERE m.user_id=? ORDER BY m.joined_at LIMIT 1`);
const membersQuery = db.prepare(`SELECT u.id,u.display_name,u.email FROM users u JOIN household_members m ON m.user_id=u.id WHERE m.household_id=? ORDER BY m.joined_at`);
const itemQuery = db.prepare(`SELECT i.*,u.display_name AS added_name,b.display_name AS bought_name FROM shopping_items i JOIN users u ON u.id=i.added_by LEFT JOIN users b ON b.id=i.bought_by WHERE i.household_id=? ORDER BY i.created_at,i.id`);
const streams = new Map();
const cookieName = 'gather_session';
const cookieOpts = 'Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600';

function json(res, status, value, extra = {}) {
 const body = JSON.stringify(value);
 res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', ...extra });
 res.end(body);
}
function fail(res, status, message) { json(res, status, { error: message }); }
async function body(req) {
 let raw=''; for await (const chunk of req) { raw += chunk; if (raw.length > 1024*1024) throw new Error('Request is too large'); }
 return raw ? JSON.parse(raw) : {};
}
function cookie(req) { const value=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'=')); return value ? decodeURIComponent(value.slice(cookieName.length+1)) : ''; }
function userFor(req) { const token=cookie(req); return token ? (sessions.get(crypto.createHash('sha256').update(token).digest('hex'),Date.now()) || null) : null; }
function householdFor(user) { return memberHouse.get(user.id) || null; }
function requireUser(req,res) { const user=userFor(req); if(!user) fail(res,401,'Please sign in to continue.'); return user; }
function requireHousehold(user,res) { const house=householdFor(user); if(!house) fail(res,409,'Create or join a household first.'); return house; }
function emit(houseId) { const set=streams.get(houseId); if(!set) return; const msg='event: change\ndata: {}\n\n'; for(const res of set) res.write(msg); }
function mintInvite() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }
function safeUser(user) { return { id:user.id, email:user.email, display_name:user.display_name }; }

async function route(req,res) {
 const url=new URL(req.url,'http://localhost'); const p=url.pathname; const method=req.method;
 if(method==='GET' && p==='/') { res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'}); return res.end(fs.readFileSync(path.join(root,'index.html'))); }
 if(method==='GET' && p==='/app.js') { res.writeHead(200,{'Content-Type':'text/javascript; charset=utf-8','Cache-Control':'no-cache'}); return res.end(fs.readFileSync(path.join(root,'app.js'))); }
 if(method==='GET' && p==='/api/health') return json(res,200,{ok:true,database:'sqlite'});
 if(method==='POST' && p==='/api/auth/register') {
  let data; try{data=await body(req)}catch{return fail(res,400,'Invalid request.');}
  const email=String(data.email||'').trim().toLowerCase(), password=String(data.password||'');
  if(!/^\S+@\S+\.\S+$/.test(email)) return fail(res,400,'Enter a valid email address.');
  if(password.length<6) return fail(res,400,'Password must be at least 6 characters.');
  const displayName=email.split('@')[0].slice(0,40)||'Member'; const salt=crypto.randomBytes(16).toString('hex'); const hash=await scrypt(password,salt,64);
  try { const result=db.prepare('INSERT INTO users(email,display_name,password_hash) VALUES(?,?,?)').run(email,displayName,salt+':'+hash.toString('hex')); const user={id:Number(result.lastInsertRowid),email,display_name:displayName}; return createSession(res,user); }
  catch(e){if(String(e.message).includes('UNIQUE'))return fail(res,409,'An account with that email already exists.'); throw e;}
 }
 if(method==='POST' && p==='/api/auth/login') {
  let data; try{data=await body(req)}catch{return fail(res,400,'Invalid request.');}
  const email=String(data.email||'').trim().toLowerCase(), password=String(data.password||''); const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!user)return fail(res,401,'Email or password is incorrect.'); const [salt,expected]=user.password_hash.split(':'); const actual=await scrypt(password,salt,64);
  if(!crypto.timingSafeEqual(actual,Buffer.from(expected,'hex')))return fail(res,401,'Email or password is incorrect.');
  return createSession(res,user);
 }
 if(method==='POST' && p==='/api/auth/logout') { const token=cookie(req); if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(crypto.createHash('sha256').update(token).digest('hex')); return json(res,200,{ok:true},{'Set-Cookie':cookieName+'=; '+cookieOpts+'; Max-Age=0'}); }
 if(method==='GET' && p==='/api/me') { const user=userFor(req); return user?json(res,200,{user:safeUser(user)}):json(res,200,{user:null}); }
 const user=userFor(req); if(p.startsWith('/api/')&&!user)return fail(res,401,'Please sign in to continue.');
 if(method==='GET' && p==='/api/household') { const house=householdFor(user); if(!house)return json(res,200,{household:null}); return json(res,200,{household:house,members:membersQuery.all(house.id),items:itemQuery.all(house.id).map(x=>({...x,is_bought:!!x.is_bought}))}); }
 if(method==='POST' && p==='/api/household') { let d;try{d=await body(req)}catch{return fail(res,400,'Invalid request.');} const name=String(d.name||'Our groceries').trim().slice(0,50)||'Our groceries'; if(householdFor(user))return fail(res,409,'You are already in a household.'); let code=mintInvite();while(db.prepare('SELECT 1 FROM households WHERE invite_code=?').get(code))code=mintInvite();const result=db.prepare('INSERT INTO households(name,invite_code,created_by) VALUES(?,?,?)').run(name,code,user.id);db.prepare('INSERT INTO household_members(household_id,user_id) VALUES(?,?)').run(Number(result.lastInsertRowid),user.id);return json(res,201,{ok:true}); }
 if(method==='POST' && p==='/api/household/join') { let d;try{d=await body(req)}catch{return fail(res,400,'Invalid request.');}const code=String(d.code||'').trim().toUpperCase();const house=db.prepare('SELECT id FROM households WHERE invite_code=?').get(code);if(!house)return fail(res,404,'That invite code was not found.');db.prepare('INSERT OR IGNORE INTO household_members(household_id,user_id) VALUES(?,?)').run(house.id,user.id);return json(res,200,{ok:true}); }
 if(method==='GET' && p==='/api/events') { const house=requireHousehold(user,res);if(!house)return;res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('retry: 2500\n\n');if(!streams.has(house.id))streams.set(house.id,new Set());const set=streams.get(house.id);set.add(res);const ping=setInterval(()=>res.write(': ping\n\n'),25000);req.on('close',()=>{clearInterval(ping);set.delete(res);if(!set.size)streams.delete(house.id)});return; }
 const house=requireHousehold(user,res); if(!house)return;
 if(method==='POST' && p==='/api/items') { let d;try{d=await body(req)}catch{return fail(res,400,'Invalid request.');}const name=String(d.name||'').trim().slice(0,120);if(!name)return fail(res,400,'Enter an item name.');const quantity=String(d.quantity||'').trim().slice(0,20);db.prepare('INSERT INTO shopping_items(household_id,name,quantity,added_by) VALUES(?,?,?,?)').run(house.id,name,quantity,user.id);emit(house.id);return json(res,201,{ok:true}); }
 const match=p.match(/^\/api\/items\/(\d+)$/);
 if(match&&method==='PATCH') {let d;try{d=await body(req)}catch{return fail(res,400,'Invalid request.');}const id=Number(match[1]);const item=db.prepare('SELECT id FROM shopping_items WHERE id=? AND household_id=?').get(id,house.id);if(!item)return fail(res,404,'Item not found.');const bought=!!d.is_bought;db.prepare('UPDATE shopping_items SET is_bought=?,bought_by=?,bought_at=? WHERE id=? AND household_id=?').run(bought?1:0,bought?user.id:null,bought?new Date().toISOString():null,id,house.id);emit(house.id);return json(res,200,{ok:true}); }
 if(match&&method==='DELETE') {const id=Number(match[1]);db.prepare('DELETE FROM shopping_items WHERE id=? AND household_id=?').run(id,house.id);emit(house.id);return json(res,200,{ok:true});}
 if(method==='DELETE'&&p==='/api/items/bought') {db.prepare('DELETE FROM shopping_items WHERE household_id=? AND is_bought=1').run(house.id);emit(house.id);return json(res,200,{ok:true});}
 return fail(res,404,'Not found.');
}
function createSession(res,user) {const token=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(crypto.createHash('sha256').update(token).digest('hex'),user.id,Date.now()+14*86400000);db.prepare('DELETE FROM sessions WHERE expires_at<?').run(Date.now());return json(res,200,{user:safeUser(user)},{'Set-Cookie':cookieName+'='+encodeURIComponent(token)+'; '+cookieOpts});}
const server=http.createServer((req,res)=>{Promise.resolve(route(req,res)).catch(err=>{console.error(err);if(!res.headersSent)fail(res,500,'Something went wrong. Check the server terminal.');else res.end();});});
const host=process.env.HOST||'0.0.0.0';const port=Number(process.env.PORT||3000);
server.listen(port,host,()=>console.log(`Gather is ready at http://localhost:${port} (listening on ${host}:${port})`));


