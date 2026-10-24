const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { neon } = require('@neondatabase/serverless');
const scrypt = promisify(crypto.scrypt);
const cookieName = 'gather_session';
const sql = neon(process.env.DATABASE_URL || 'postgres://missing:missing@localhost/missing');
let ready;

async function init() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured.');
  if (!ready) ready = (async () => {
    await sql.query("CREATE TABLE IF NOT EXISTS app_users (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
    await sql.query("CREATE TABLE IF NOT EXISTS app_sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL)");
    await sql.query("CREATE TABLE IF NOT EXISTS households (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, invite_code TEXT NOT NULL UNIQUE, created_by BIGINT NOT NULL REFERENCES app_users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now())");
    await sql.query("CREATE TABLE IF NOT EXISTS household_members (household_id BIGINT NOT NULL REFERENCES households(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE, joined_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (household_id,user_id))");
    await sql.query("CREATE TABLE IF NOT EXISTS shopping_items (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, household_id BIGINT NOT NULL REFERENCES households(id) ON DELETE CASCADE, name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120), quantity TEXT NOT NULL DEFAULT '', is_bought BOOLEAN NOT NULL DEFAULT false, added_by BIGINT NOT NULL REFERENCES app_users(id), bought_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), bought_at TIMESTAMPTZ)");
    await sql.query("CREATE INDEX IF NOT EXISTS shopping_items_household_created ON shopping_items(household_id,created_at)");
  })();
  return ready;
}
function send(res,status,value,headers){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Cache-Control','no-store');if(headers)for(const [k,v] of Object.entries(headers))res.setHeader(k,v);res.end(JSON.stringify(value))}
function fail(res,status,message){send(res,status,{error:message})}
function body(req){if(req.body&&typeof req.body==='object')return req.body;if(typeof req.body==='string'){try{return JSON.parse(req.body)}catch{return {}}}return {}}
function tokenFrom(req){const raw=req.headers.cookie||'';const pair=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='));return pair?decodeURIComponent(pair.slice(cookieName.length+1)):''}
function hashToken(token){return crypto.createHash('sha256').update(token).digest('hex')}
async function getUser(req){const token=tokenFrom(req);if(!token)return null;const rows=await sql.query('SELECT u.id,u.email,u.display_name FROM app_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[hashToken(token)]);if(!rows[0])return null;return {...rows[0],id:Number(rows[0].id)}}
async function getHouse(userId){const rows=await sql.query('SELECT h.id,h.name,h.invite_code FROM households h JOIN household_members m ON m.household_id=h.id WHERE m.user_id=$1 ORDER BY m.joined_at LIMIT 1',[userId]);if(!rows[0])return null;return {...rows[0],id:Number(rows[0].id)}}
async function createSession(res,user){const token=crypto.randomBytes(32).toString('hex');await sql.query("INSERT INTO app_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '14 days')",[hashToken(token),user.id]);await sql.query('DELETE FROM app_sessions WHERE expires_at<now()');const secure=process.env.VERCEL?'; Secure':'';send(res,200,{user},{'Set-Cookie':cookieName+'='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age=1209600'+secure})}
function inviteCode(){return crypto.randomBytes(4).toString('hex').toUpperCase()}

module.exports = async function handler(req,res){
 try {
  const url=new URL(req.url,'https://gather.invalid');
  const parts=url.pathname.split('/').filter(Boolean);
  const path='/'+parts.slice(1).join('/');
  const method=req.method;
  if(path==='/health'&&method==='GET')return send(res,200,{ok:true,database:'neon'});
  await init();
  if(path==='/auth/register'&&method==='POST'){
    const d=body(req),email=String(d.email||'').trim().toLowerCase(),password=String(d.password||'');
    if(!email.includes('@')||!email.includes('.'))return fail(res,400,'Enter a valid email address.');
    if(password.length<6)return fail(res,400,'Password must be at least 6 characters.');
    const display_name=email.split('@')[0].slice(0,40)||'Member',salt=crypto.randomBytes(16).toString('hex'),digest=await scrypt(password,salt,64);
    try{const rows=await sql.query('INSERT INTO app_users(email,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,email,display_name',[email,display_name,salt+':'+digest.toString('hex')]);return createSession(res,{...rows[0],id:Number(rows[0].id)})}catch(e){if(e.code==='23505')return fail(res,409,'An account with that email already exists.');throw e}
  }
  if(path==='/auth/login'&&method==='POST'){
    const d=body(req),email=String(d.email||'').trim().toLowerCase(),password=String(d.password||'');const rows=await sql.query('SELECT id,email,display_name,password_hash FROM app_users WHERE email=$1',[email]);const user=rows[0];
    if(!user)return fail(res,401,'Email or password is incorrect.');const [salt,expected]=user.password_hash.split(':');const actual=await scrypt(password,salt,64);if(!crypto.timingSafeEqual(actual,Buffer.from(expected,'hex')))return fail(res,401,'Email or password is incorrect.');return createSession(res,{id:Number(user.id),email:user.email,display_name:user.display_name});
  }
  if(path==='/auth/logout'&&method==='POST'){const token=tokenFrom(req);if(token)await sql.query('DELETE FROM app_sessions WHERE token_hash=$1',[hashToken(token)]);return send(res,200,{ok:true},{'Set-Cookie':cookieName+'=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})}
  if(path==='/me'&&method==='GET'){const user=await getUser(req);return send(res,200,{user})}
  const user=await getUser(req);if(!user)return fail(res,401,'Please sign in to continue.');
  if(path==='/household'&&method==='GET'){
    const house=await getHouse(user.id);if(!house)return send(res,200,{household:null});
    const [members,items]=await Promise.all([
      sql.query('SELECT u.id,u.display_name,u.email FROM app_users u JOIN household_members m ON m.user_id=u.id WHERE m.household_id=$1 ORDER BY m.joined_at',[house.id]),
      sql.query('SELECT i.*,u.display_name AS added_name FROM shopping_items i JOIN app_users u ON u.id=i.added_by WHERE i.household_id=$1 ORDER BY i.created_at,i.id',[house.id])
    ]);
    return send(res,200,{household:house,members:members.map(x=>({...x,id:Number(x.id)})),items:items.map(x=>({...x,id:Number(x.id),household_id:Number(x.household_id),added_by:Number(x.added_by),is_bought:!!x.is_bought}))});
  }
  if(path==='/household'&&method==='POST'){
    if(await getHouse(user.id))return fail(res,409,'You are already in a household.');const d=body(req),name=String(d.name||'Our groceries').trim().slice(0,50)||'Our groceries';let code=inviteCode();
    for(let tries=0;tries<5;tries++){try{const rows=await sql.query('INSERT INTO households(name,invite_code,created_by) VALUES($1,$2,$3) RETURNING id',[name,code,user.id]);await sql.query('INSERT INTO household_members(household_id,user_id) VALUES($1,$2)',[rows[0].id,user.id]);return send(res,201,{ok:true})}catch(e){if(e.code==='23505'){code=inviteCode();continue}throw e}}return fail(res,500,'Could not create an invite code. Please try again.');
  }
  if(path==='/household/join'&&method==='POST'){
    const code=String(body(req).code||'').trim().toUpperCase(),rows=await sql.query('SELECT id FROM households WHERE invite_code=$1',[code]);if(!rows[0])return fail(res,404,'That invite code was not found.');await sql.query('INSERT INTO household_members(household_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[rows[0].id,user.id]);return send(res,200,{ok:true});
  }
  const house=await getHouse(user.id);if(!house)return fail(res,409,'Create or join a household first.');
  if(path==='/items'&&method==='POST'){
    const d=body(req),name=String(d.name||'').trim().slice(0,120);if(!name)return fail(res,400,'Enter an item name.');await sql.query('INSERT INTO shopping_items(household_id,name,quantity,added_by) VALUES($1,$2,$3,$4)',[house.id,name,String(d.quantity||'').trim().slice(0,20),user.id]);return send(res,201,{ok:true});
  }
  if(parts[1]==='items'&&parts.length===3&&/^\d+$/.test(parts[2])){
    const id=parts[2];
    if(method==='PATCH'){const bought=!!body(req).is_bought;const result=await sql.query('UPDATE shopping_items SET is_bought=$1,bought_by=$2,bought_at=CASE WHEN $1 THEN now() ELSE NULL END WHERE id=$3 AND household_id=$4 RETURNING id',[bought,bought?user.id:null,id,house.id]);if(!result.length)return fail(res,404,'Item not found.');return send(res,200,{ok:true})}
    if(method==='DELETE'){await sql.query('DELETE FROM shopping_items WHERE id=$1 AND household_id=$2',[id,house.id]);return send(res,200,{ok:true})}
  }
  if(path==='/items/bought'&&method==='DELETE'){await sql.query('DELETE FROM shopping_items WHERE household_id=$1 AND is_bought=true',[house.id]);return send(res,200,{ok:true})}
  return fail(res,404,'Not found.');
 }catch(error){console.error('Gather API error:',error);return fail(res,500,process.env.VERCEL?'Server error. Check Vercel function logs and DATABASE_URL.':'Something went wrong.')}
};
