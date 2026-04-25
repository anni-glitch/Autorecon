import asyncio
import io
import csv
import secrets
from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, Request, Form, Response, Cookie, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException
from sqlalchemy.orm import Session
import httpx
from typing import Dict, Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import database
import models
import auth
from core.engine import run_engine
from main import AVAILABLE_MODULES

# PDF Reporting Imports
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

models.Base.metadata.create_all(bind=database.engine)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="AutoRecon SaaS", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="templates")
active_connections: Dict[int, WebSocket] = {}
scheduler = AsyncIOScheduler()

async def run_scheduled_scan(sched_id: int, target: str, stealth: bool, modules: str, owner_id: int):
    # Headless background execution
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=10)
    db = database.SessionLocal()
    try:
        job = models.ScanJob(target=target, owner_id=owner_id, status="running")
        db.add(job)
        db.commit()
        db.refresh(job)
        
        selected_modules = []
        if modules:
            target_mod_names = [x.strip() for x in modules.split(",") if x.strip()]
            for name in target_mod_names:
                if name in AVAILABLE_MODULES:
                    selected_modules.append(AVAILABLE_MODULES[name])
        else:
            selected_modules = list(AVAILABLE_MODULES.values())
            
        async with httpx.AsyncClient(timeout=15, verify=False, limits=limits) as client:
            modules_instances = [cls(client=client) for cls in selected_modules]
            findings = await run_engine(target=target, activated_modules=modules_instances, stealth=stealth)
            
            job.status = "completed"
            for f in findings:
                db_finding = models.Finding(
                    job_id=job.id, module=f.module, category=f.category,
                    severity=f.severity, title=f.title, description=f.description
                )
                db.add(db_finding)
            db.commit()
    except Exception:
        if 'job' in locals():
            job.status = "error"
            db.commit()
    finally:
        db.close()

@app.on_event("startup")
def startup_event():
    db = database.SessionLocal()
    schedules = db.query(models.ScheduledScan).all()
    for s in schedules:
        scheduler.add_job(
            run_scheduled_scan, 
            'interval', 
            hours=s.interval_hours, 
            args=[s.id, s.target, s.stealth, s.modules, s.owner_id],
            id=f"scan_{s.id}",
            replace_existing=True
        )
    db.close()
    scheduler.start()

@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown()

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/api/token")
@limiter.limit("5/minute")
async def login_for_access_token(request: Request, response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not auth.verify_password(password, user.hashed_password):
        return {"error": "Invalid username or password"}
        
    access_token = auth.create_access_token(data={"sub": user.username})
    refresh_token = auth.create_refresh_token(data={"sub": user.username})
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax", secure=True)
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, samesite="lax", secure=True)
    return {"message": "Success"}

@app.post("/api/register")
@limiter.limit("5/minute")
async def register_user(request: Request, response: Response, username: str = Form(...), password: str = Form(...), db: Session = Depends(database.get_db)):
    try:
        auth.validate_password_complexity(password)
    except ValueError as e:
        return {"error": str(e)}
        
    if await auth.is_password_compromised(password):
        return {"error": "This password has been exposed in a data breach! Please choose another."}
        
    existing = db.query(models.User).filter(models.User.username == username).first()
    if existing:
        return {"error": "Username taken"}
        
    hashed_password = auth.get_password_hash(password)
    user = models.User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    
    access_token = auth.create_access_token(data={"sub": user.username})
    refresh_token = auth.create_refresh_token(data={"sub": user.username})
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax", secure=True)
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, samesite="lax", secure=True)
    return {"message": "Success"}

@app.post("/api/refresh")
async def refresh_token(response: Response, refresh_token: Optional[str] = Cookie(None), db: Session = Depends(database.get_db)):
    if not refresh_token:
        return JSONResponse(status_code=401, content={"error": "Missing refresh token"})
    try:
        payload = auth.jwt.decode(refresh_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        if payload.get("type") != "refresh":
            return JSONResponse(status_code=401, content={"error": "Invalid token type"})
        username: str = payload.get("sub")
        if username is None:
            return JSONResponse(status_code=401, content={"error": "Invalid token"})
    except auth.JWTError:
        return JSONResponse(status_code=401, content={"error": "Token expired or invalid"})
        
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return JSONResponse(status_code=401, content={"error": "User deleted"})
        
    new_access_token = auth.create_access_token(data={"sub": user.username})
    response.set_cookie(key="access_token", value=new_access_token, httponly=True, samesite="lax", secure=True)
    return {"message": "Token refreshed"}

@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}

@app.get("/api/me")
async def read_users_me(current_user: models.User = Depends(auth.get_current_user)):
    return {"username": current_user.username, "id": current_user.id, "api_key": current_user.api_key}

@app.post("/api/keys/generate")
async def generate_api_key(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    new_key = "ar_" + secrets.token_hex(20)
    current_user.api_key = new_key
    db.commit()
    return {"api_key": new_key}

@app.post("/api/schedule")
async def schedule_scan(
    target: str = Form(...),
    stealth: bool = Form(False),
    modules: str = Form(None),
    interval_hours: int = Form(24),
    current_user: models.User = Depends(auth.get_current_user), 
    db: Session = Depends(database.get_db)
):
    sched = models.ScheduledScan(target=target, stealth=stealth, interval_hours=interval_hours, modules=modules, owner_id=current_user.id)
    db.add(sched)
    db.commit()
    db.refresh(sched)
    
    scheduler.add_job(
        run_scheduled_scan, 
        'interval', 
        hours=interval_hours, 
        args=[sched.id, target, stealth, modules, current_user.id],
        id=f"scan_{sched.id}",
        replace_existing=True
    )
    return {"message": "Scheduled", "schedule_id": sched.id}

@app.get("/api/history")
async def get_history(current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    jobs = db.query(models.ScanJob).filter(models.ScanJob.owner_id == current_user.id).order_by(models.ScanJob.created_at.desc()).limit(50).all()
    return [{"id": j.id, "target": j.target, "status": j.status, "created_at": j.created_at.isoformat()} for j in jobs]

@app.get("/api/jobs/{job_id}/findings")
async def get_job_findings(job_id: int, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id, models.ScanJob.owner_id == current_user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    findings = db.query(models.Finding).filter(models.Finding.job_id == job_id).all()
    return [{"module": f.module, "category": f.category, "severity": f.severity, "title": f.title, "description": f.description} for f in findings]

@app.get("/api/diff/{job_a}/{job_b}")
async def get_diff(job_a: int, job_b: int, current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    job1 = db.query(models.ScanJob).filter(models.ScanJob.id == job_a, models.ScanJob.owner_id == current_user.id).first()
    job2 = db.query(models.ScanJob).filter(models.ScanJob.id == job_b, models.ScanJob.owner_id == current_user.id).first()
    if not job1 or not job2:
        raise HTTPException(status_code=404, detail="Job not found")
        
    findings_a = db.query(models.Finding).filter(models.Finding.job_id == job_a).all()
    findings_b = db.query(models.Finding).filter(models.Finding.job_id == job_b).all()
    
    def hash_f(f): return (f.module, f.category, f.title)
    
    set_a = {hash_f(f): f for f in findings_a}
    set_b = {hash_f(f): f for f in findings_b}
    
    new_in_b = []
    for k in set_b.keys() - set_a.keys():
        f_dict = vars(set_b[k]).copy()
        f_dict.pop('_sa_instance_state', None)
        new_in_b.append(f_dict)
        
    resolved_in_b = []
    for k in set_a.keys() - set_b.keys():
        f_dict = vars(set_a[k]).copy()
        f_dict.pop('_sa_instance_state', None)
        resolved_in_b.append(f_dict)
        
    return {"new_findings": new_in_b, "resolved": resolved_in_b}

@app.get("/api/export/{job_id}")
async def export_job(job_id: int, format: str = "json", current_user: models.User = Depends(auth.get_current_user), db: Session = Depends(database.get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id, models.ScanJob.owner_id == current_user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    findings = db.query(models.Finding).filter(models.Finding.job_id == job_id).all()
        
    if format == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, spaceAfter=20, textColor=colors.hexColor('#1e293b'))
        finding_title_style = ParagraphStyle('FindingTitle', parent=styles['Heading3'], fontSize=12, textColor=colors.hexColor('#0f172a'), spaceBefore=10)
        desc_style = ParagraphStyle('DescStyle', parent=styles['BodyText'], fontSize=10, leftIndent=20, leading=14)
        severity_style = lambda s: ParagraphStyle('Sev', parent=styles['Normal'], fontSize=8, fontName='Helvetica-Bold', textColor=colors.white, backColor=colors.hexColor('#ef4444' if s=='Critical' else '#f97316' if s=='High' else '#eab308' if s=='Medium' else '#3b82f6' if s=='Low' else '#64748b'), borderPadding=3)

        elements = []
        elements.append(Paragraph(f"Security Scan Report: {job.target}", title_style))
        elements.append(Paragraph(f"Scan ID: {job.id} | Date: {job.created_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        if not findings:
            elements.append(Paragraph("No findings recorded.", styles['Normal']))
        else:
            for f in findings:
                elements.append(Paragraph(f.severity, severity_style(f.severity)))
                elements.append(Paragraph(f"[{f.module}] {f.title}", finding_title_style))
                elements.append(Paragraph(f.description, desc_style))
                elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 30))
        elements.append(Paragraph("Generated by AutoRecon SaaS Platform", styles['Italic']))
        
        doc.build(elements)
        buffer.seek(0)
        return Response(content=buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=Report_{job.target}_{job.id}.pdf"})

    if format == "html":
        report_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AutoRecon Report - {job.target}</title>
            <style>
                body {{ font-family: 'Inter', sans-serif; background: #f8fafc; color: #1e293b; padding: 40px; }}
                .report-card {{ background: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 30px; max-width: 900px; margin: 0 auto; }}
                h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
                .meta {{ color: #64748b; font-size: 0.9rem; margin-bottom: 30px; }}
                .finding {{ border-left: 4px solid #cbd5e1; padding: 15px; margin-bottom: 15px; background: #f1f5f9; border-radius: 0 8px 8px 0; }}
                .critical {{ border-left-color: #ef4444; }}
                .high {{ border-left-color: #f97316; }}
                .medium {{ border-left-color: #eab308; }}
                .low {{ border-left-color: #3b82f6; }}
                .info {{ border-left-color: #64748b; }}
                .severity {{ font-weight: 800; text-transform: uppercase; font-size: 0.7rem; display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; margin-bottom: 5px; }}
                .sev-critical {{ background: #ef4444; }}
                .sev-high {{ background: #f97316; }}
                .sev-medium {{ background: #eab308; }}
                .sev-low {{ background: #3b82f6; }}
                .sev-info {{ background: #64748b; }}
                .title {{ font-weight: 700; font-size: 1.1rem; margin-bottom: 5px; }}
                .desc {{ font-size: 0.95rem; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <div class="report-card">
                <h1>Security Scan Report: {job.target}</h1>
                <div class="meta">Scan ID: {job.id} | Date: {job.created_at.strftime('%Y-%m-%d %H:%M:%S')}</div>
                
                {"".join([f'<div class="finding {f.severity.lower()}"><span class="severity sev-{f.severity.lower()}">{f.severity}</span><div class="title">[{f.module}] {f.title}</div><div class="desc">{f.description}</div></div>' for f in findings]) if findings else "<p>No findings recorded.</p>"}
                
                <hr style="margin: 40px 0; border: 0; border-top: 1px solid #e2e8f0;">
                <p style="text-align: center; color: #94a3b8; font-size: 0.8rem;">Generated by AutoRecon SaaS Platform</p>
            </div>
        </body>
        </html>
        """
        return Response(content=report_html, media_type="text/html", headers={"Content-Disposition": f"attachment; filename=Report_{job.target}_{job.id}.html"})

    data = [{"module": f.module, "severity": f.severity, "category": f.category, "title": f.title, "description": f.description} for f in findings]
    
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["module", "severity", "category", "title", "description"])
        writer.writeheader()
        writer.writerows(data)
        return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=autorecon_job_{job_id}.csv"})
        
    return JSONResponse(content={"target": job.target, "date": job.created_at.isoformat(), "findings": data}, headers={"Content-Disposition": f"attachment; filename=autorecon_job_{job_id}.json"})

@app.post("/api/scan")
async def start_scan(
    target: str = Form(...), 
    stealth: bool = Form(False),
    modules: str = Form(None),
    wordlist: Optional[UploadFile] = File(None),
    current_user: models.User = Depends(auth.get_current_user), 
    db: Session = Depends(database.get_db)
):
    job = models.ScanJob(target=target, owner_id=current_user.id, status="running")
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id
    
    selected_modules = []
    if modules:
        target_mod_names = [x.strip() for x in modules.split(",") if x.strip()]
        for name in target_mod_names:
            if name in AVAILABLE_MODULES:
                selected_modules.append(AVAILABLE_MODULES[name])
    else:
        selected_modules = list(AVAILABLE_MODULES.values())
        
    wlist_data = None
    if wordlist and wordlist.filename:
        content = await wordlist.read()
        lines = [line.strip() for line in content.decode("utf-8").splitlines() if line.strip()]
        if lines:
            wlist_data = {"dir_fuzzer": lines}
        
    asyncio.create_task(background_scan_task(job_id, target, stealth, selected_modules, wlist_data))
    return {"job_id": job_id, "status": "started"}

async def background_scan_task(job_id: int, target: str, stealth: bool, selected_modules: list, custom_payloads: dict = None):
    # CRITICAL FIX: Delay engine start to allow remote WebSocket TLS handshakes to complete over the WAN
    await asyncio.sleep(1.5)
    
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=20)
    
    async def web_progress_callback(msg: dict):
        if job_id in active_connections:
            try:
                msg["job_id"] = job_id
                await active_connections[job_id].send_json(msg)
            except Exception:
                pass

    try:
        async with httpx.AsyncClient(timeout=15, verify=False, limits=limits) as client:
            modules_instances = [cls(client=client) for cls in selected_modules]
            findings = await run_engine(target=target, activated_modules=modules_instances, stealth=stealth, progress_callback=web_progress_callback, custom_payloads=custom_payloads)
            
            db = database.SessionLocal()
            try:
                job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
                if job:
                    job.status = "completed"
                    for f in findings:
                        db_finding = models.Finding(
                            job_id=job.id, module=f.module, category=f.category,
                            severity=f.severity, title=f.title, description=f.description
                        )
                        db.add(db_finding)
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
                
            if job_id in active_connections:
                try:
                    summary = {
                        "type": "scan_summary",
                        "total": len(findings),
                        "critical": len([f for f in findings if f.severity.lower() == 'critical']),
                        "high": len([f for f in findings if f.severity.lower() == 'high']),
                        "medium": len([f for f in findings if f.severity.lower() == 'medium']),
                        "low": len([f for f in findings if f.severity.lower() == 'low']),
                    }
                    await active_connections[job_id].send_json(summary)
                    await active_connections[job_id].send_json({"type": "job_complete", "job_id": job_id})
                except Exception:
                    pass
    except Exception as e:
        db = database.SessionLocal()
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if job:
            job.status = "error"
            db.commit()
        db.close()

@app.websocket("/ws/progress/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: int):
    access_token = websocket.cookies.get("access_token")
    if not access_token:
        await websocket.close(code=1008)
        return
        
    db = database.SessionLocal()
    try:
        user = auth.get_current_user(access_token=access_token, x_api_key=None, db=db)
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id, models.ScanJob.owner_id == user.id).first()
        if not job:
            await websocket.close(code=1008)
            return
    except Exception:
        db.close()
        await websocket.close(code=1008)
        return
    finally:
        db.close()
        
    await websocket.accept()
    active_connections[job_id] = websocket
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if job_id in active_connections:
            del active_connections[job_id]
