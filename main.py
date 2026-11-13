import os, sqlite3, hashlib, hmac, secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE=Path(__file__).resolve().parent.parent
DB=os.getenv("DATABASE_PATH",str(BASE/"data"/"clinic.db"))
Path(DB).parent.mkdir(parents=True,exist_ok=True)
signer=URLSafeTimedSerializer(os.getenv("APP_SECRET","dev-secret-change-me"),salt="clinic-session")
app=FastAPI(title="Clinic Agent 2.0")
app.mount("/static",StaticFiles(directory=str(BASE/"app"/"static")),name="static")

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def pw_hash(p,s=None):
    s=s or secrets.token_bytes(16)
    return s.hex()+"$"+hashlib.scrypt(p.encode(),salt=s,n=2**14,r=8,p=1).hex()
def pw_ok(p,stored):
    try:
        s,d=stored.split("$",1)
        return hmac.compare_digest(pw_hash(p,bytes.fromhex(s)).split("$",1)[1],d)
    except Exception:return False
def init():
    with conn() as c:
        c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,ph TEXT NOT NULL,role TEXT NOT NULL,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY,patient_id INTEGER REFERENCES users(id),doctor_id INTEGER REFERENCES users(id),requested_at TEXT NOT NULL,reason TEXT NOT NULL,status TEXT DEFAULT 'pending',created TEXT NOT NULL);""")
        if not c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            for n,e,p,r in [("مدیر سامانه","admin@clinic.local","Admin123!","admin"),("دکتر نمونه","doctor@clinic.local","Doctor123!","doctor"),("بیمار نمونه","patient@clinic.local","Patient123!","patient")]:
                c.execute("INSERT INTO users(name,email,ph,role,created) VALUES(?,?,?,?,?)",(n,e,pw_hash(p),r,datetime.now(timezone.utc).isoformat()))
init()
def who(req):
    t=req.cookies.get("clinic_session")
    if not t:return None
    try:u=signer.loads(t,max_age=604800)
    except (BadSignature,SignatureExpired):return None
    with conn() as c:
        x=c.execute("SELECT id,name,email,role FROM users WHERE id=?",(u["id"],)).fetchone()
        return dict(x) if x else None
def need(req,roles=None):
    u=who(req)
    if not u:raise HTTPException(401,"ابتدا وارد حساب شوید")
    if roles and u["role"] not in roles:raise HTTPException(403,"اجازه دسترسی ندارید")
    return u

@app.get("/",response_class=HTMLResponse)
def home():return (BASE/"app"/"static"/"index.html").read_text(encoding="utf-8")
@app.get("/health")
def health():return {"status":"ok"}
@app.get("/api/me")
def me(request:Request):return {"user":who(request)}
@app.post("/api/login")
def login(email:str=Form(...),password:str=Form(...)):
    with conn() as c:x=c.execute("SELECT * FROM users WHERE email=?",(email.strip().lower(),)).fetchone()
    if not x or not pw_ok(password,x["ph"]):raise HTTPException(401,"ایمیل یا رمز عبور اشتباه است")
    r=JSONResponse({"ok":True,"user":{"id":x["id"],"name":x["name"],"email":x["email"],"role":x["role"]}})
    r.set_cookie("clinic_session",signer.dumps({"id":x["id"]}),httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","false")=="true",max_age=604800)
    return r
@app.post("/api/logout")
def logout():
    r=JSONResponse({"ok":True});r.delete_cookie("clinic_session");return r
@app.get("/api/dashboard")
def dashboard(request:Request):
    u=need(request)
    with conn() as c:
        if u["role"]=="patient":
            rows=c.execute("SELECT a.*,d.name doctor_name FROM appointments a LEFT JOIN users d ON d.id=a.doctor_id WHERE patient_id=? ORDER BY a.id DESC",(u["id"],)).fetchall()
        elif u["role"]=="doctor":
            rows=c.execute("SELECT a.*,p.name patient_name FROM appointments a JOIN users p ON p.id=a.patient_id WHERE doctor_id=? OR doctor_id IS NULL ORDER BY a.id DESC",(u["id"],)).fetchall()
        else:
            rows=c.execute("SELECT a.*,p.name patient_name,d.name doctor_name FROM appointments a JOIN users p ON p.id=a.patient_id LEFT JOIN users d ON d.id=a.doctor_id ORDER BY a.id DESC").fetchall()
        stats={k:c.execute(q).fetchone()[0] for k,q in {"appointments":"SELECT COUNT(*) FROM appointments","patients":"SELECT COUNT(*) FROM users WHERE role='patient'","doctors":"SELECT COUNT(*) FROM users WHERE role='doctor'","pending":"SELECT COUNT(*) FROM appointments WHERE status='pending'"}.items()}
    return {"user":u,"stats":stats,"appointments":[dict(x) for x in rows]}
@app.post("/api/appointments")
def add_appointment(request:Request,requested_at:str=Form(...),reason:str=Form(...)):
    u=need(request,["patient"])
    try:datetime.fromisoformat(requested_at)
    except ValueError:raise HTTPException(400,"تاریخ معتبر نیست")
    if len(reason.strip())<3:raise HTTPException(400,"علت مراجعه را کامل‌تر بنویسید")
    with conn() as c:c.execute("INSERT INTO appointments(patient_id,requested_at,reason,created) VALUES(?,?,?,?)",(u["id"],requested_at,reason.strip(),datetime.now(timezone.utc).isoformat()))
    return {"ok":True}
@app.post("/api/appointments/{aid}/status")
def set_status(aid:int,request:Request,status:str=Form(...)):
    u=need(request,["admin","doctor"])
    if status not in ("pending","confirmed","cancelled","completed"):raise HTTPException(400,"وضعیت نامعتبر")
    with conn() as c:
        a=c.execute("SELECT * FROM appointments WHERE id=?",(aid,)).fetchone()
        if not a:raise HTTPException(404,"نوبت پیدا نشد")
        if u["role"]=="doctor" and a["doctor_id"] not in (None,u["id"]):raise HTTPException(403,"دسترسی ندارید")
        c.execute("UPDATE appointments SET status=?,doctor_id=CASE WHEN ?='doctor' AND doctor_id IS NULL THEN ? ELSE doctor_id END WHERE id=?",(status,u["role"],u["id"],aid))
    return {"ok":True}
@app.get("/api/users")
def users(request:Request):
    need(request,["admin"])
    with conn() as c:rows=c.execute("SELECT id,name,email,role,created FROM users ORDER BY id DESC").fetchall()
    return {"users":[dict(x) for x in rows]}
@app.post("/api/users")
def add_user(request:Request,name:str=Form(...),email:str=Form(...),password:str=Form(...),role:str=Form(...)):
    need(request,["admin"])
    if role not in ("doctor","patient") or len(password)<10:raise HTTPException(400,"رمز حداقل ۱۰ نویسه و نقش معتبر لازم است")
    try:
        with conn() as c:c.execute("INSERT INTO users(name,email,ph,role,created) VALUES(?,?,?,?,?)",(name.strip(),email.strip().lower(),pw_hash(password),role,datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError:raise HTTPException(409,"این ایمیل قبلاً ثبت شده")
    return {"ok":True}
URGENT=["درد شدید قفسه سینه","تنگی نفس شدید","بیهوش","خونریزی شدید","قصد خودکشی","علائم سکته"]
@app.post("/api/chat")
async def chat(request:Request):
    need(request);msg=str((await request.json()).get("message","")).strip()[:4000]
    if not msg:raise HTTPException(400,"پیام خالی است")
    if any(x in msg for x in URGENT):return {"reply":"ممکن است وضعیت اورژانسی باشد. همین حالا با اورژانس محل زندگی تماس بگیرید یا به نزدیک‌ترین اورژانس بروید. منتظر پاسخ آنلاین نمانید.","urgent":True}
    key=os.getenv("OPENAI_API_KEY")
    if not key:return {"reply":"برای فعال‌شدن پاسخ هوشمند، مدیر باید OPENAI_API_KEY را در تنظیمات سرور قرار دهد. این نسخه بدون کلید، پاسخ پزشکی تولید نمی‌کند.","urgent":False}
    try:
        from openai import OpenAI
        result=OpenAI(api_key=key).responses.create(model=os.getenv("OPENAI_MODEL","gpt-4.1-mini"),input=[
        {"role":"system","content":"You are a cautious Persian health information assistant. Reply in Persian. Do not diagnose, prescribe, or change medication. Encourage licensed medical care for personal decisions. For emergencies advise local emergency services. Never fabricate sources or citations. State that this is not a substitute for a clinician."},
        {"role":"user","content":msg}])
        return {"reply":result.output_text,"urgent":False,"disclaimer":"اطلاعات عمومی است و جایگزین پزشک نیست."}
    except Exception:raise HTTPException(502,"ارتباط با هوش مصنوعی برقرار نشد")
