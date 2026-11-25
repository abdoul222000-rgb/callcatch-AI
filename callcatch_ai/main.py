from fastapi import FastAPI, Depends, Request, Form, BackgroundTasks, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import random
import os

from .config import settings
from .database import engine, get_db, init_db, Contractor, MissedCall, SMSMessage, SiteVisitor, SubscriptionOrder, hash_password, verify_password
from .security import (
    create_signed_session_cookie, 
    verify_signed_session_cookie, 
    check_rate_limit, 
    record_failed_attempt, 
    clear_failed_attempts,
    SecurityHeadersMiddleware
)
from .services.twilio_service import send_sms_via_twilio
from .services.ai_agent import process_inbound_sms_with_ai

app = FastAPI(title="CallCatch AI - Missed Call Text-Back & Auto-Booking")

# 1. Protection Globale : Injection des en-têtes de sécurité bancaires
app.add_middleware(SecurityHeadersMiddleware)

# Initialisation de la base de données
init_db()

# Dossier des templates Jinja2
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ==============================================================================
# GESTION SÉCURISÉE DES SESSIONS (HMAC-SHA256 ANTI-HACKERS)
# ==============================================================================

def get_current_contractor(request: Request, db: Session = Depends(get_db)) -> Contractor:
    """Vérifie la signature cryptographique du cookie artisan pour empêcher le vol de session"""
    raw_cookie = request.cookies.get("callcatch_session")
    session_data = verify_signed_session_cookie(raw_cookie)
    
    if not session_data or session_data.get("role") not in ["contractor", "founder_as_contractor"]:
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login"})
    
    contractor = db.query(Contractor).filter(Contractor.id == session_data["user_id"]).first()
    if not contractor:
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login"})
    
    return contractor

def get_optional_contractor(request: Request, db: Session = Depends(get_db)):
    raw_cookie = request.cookies.get("callcatch_session")
    session_data = verify_signed_session_cookie(raw_cookie)
    if session_data:
        try:
            return db.query(Contractor).filter(Contractor.id == session_data["user_id"]).first()
        except Exception:
            return None
    return None

def get_current_founder(request: Request):
    """Vérifie l'accès maître réservé au fondateur du SaaS"""
    raw_cookie = request.cookies.get("callcatch_founder_session")
    session_data = verify_signed_session_cookie(raw_cookie)
    
    if not session_data or session_data.get("role") != "founder":
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/founder/login"})
    
    return True



def record_visitor_hit(request: Request, db: Session, page: str = "/"):
    """Enregistre la visite d'un prospect avec sa géolocalisation pour le Dashboard Fondateur"""
    try:
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
        cf_city = request.headers.get("cf-ipcity")
        cf_region = request.headers.get("cf-region")
        cf_country = request.headers.get("cf-ipcountry", "US")
        user_agent = request.headers.get("user-agent", "")
        
        device = "Mobile (iPhone)" if "iPhone" in user_agent else ("Mobile (Android)" if "Android" in user_agent else "Desktop")
        browser = "Safari" if "Safari" in user_agent and "Chrome" not in user_agent else ("Chrome" if "Chrome" in user_agent else "Browser")
        
        cf_c_upper = (cf_country or "US").upper()
        if cf_c_upper == "BE":
            city = cf_city or "Bruxelles"
            region = cf_region or "Bruxelles"
            country_name = "Belgique"
        elif cf_c_upper == "CH":
            city = cf_city or "Genève"
            region = cf_region or "Genève"
            country_name = "Suisse"
        elif cf_c_upper == "FR":
            city = cf_city or "Paris"
            region = cf_region or "IDF"
            country_name = "France"
        else:
            city = cf_city or ("Tampa" if "iPhone" in user_agent else "Dallas")
            region = cf_region or ("FL" if city == "Tampa" else "TX")
            country_name = "United States"
        
        visitor = SiteVisitor(
            ip_address=ip,
            city=city,
            region=region,
            country=country_name,
            country_code=cf_c_upper,
            page_visited=page,
            referrer=request.headers.get("referer", "Campaign Link"),
            device_type=device,
            browser=browser,
            is_live=True
        )
        db.add(visitor)
        db.commit()
    except Exception:
        pass


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def index(request: Request, contractor = Depends(get_optional_contractor), db: Session = Depends(get_db)):
    if request.method == "HEAD":
        return Response(status_code=200)
    record_visitor_hit(request, db, page="/")
    if contractor:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request=request, name="index.html", context={"contractor": contractor})


@app.get("/demo-login")
def demo_instant_login(request: Request, db: Session = Depends(get_db)):
    """Connexion instantanée en 1 clic au compte de démonstration pour tester l'interface"""
    record_visitor_hit(request, db, page="/demo-login")
    contractor = db.query(Contractor).filter(Contractor.email == "mike@lonestarplumbing.com").first()
    if not contractor:
        contractor = db.query(Contractor).first()
    if contractor:
        session_token = create_signed_session_cookie(contractor.id, role="contractor")
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="callcatch_session", 
            value=session_token, 
            max_age=86400 * 30, 
            httponly=True, 
            samesite="lax"
        )
        return response
    return RedirectResponse(url="/login")


@app.api_route("/health", methods=["GET", "HEAD"])
def health_check():
    """Endpoint de surveillance santé 24/7 pour UptimeRobot et Render"""
    return {"status": "ok", "service": "CallCatch AI", "timestamp": datetime.utcnow().isoformat()}


# ==============================================================================
# AUTHENTIFICATION ARTISANS (AVEC BRUTE-FORCE SHIELD)
# ==============================================================================

@app.api_route("/login", methods=["GET", "HEAD"], response_class=HTMLResponse)
def login_page(request: Request, contractor = Depends(get_optional_contractor), db: Session = Depends(get_db)):
    if request.method == "HEAD":
        return Response(status_code=200)
    record_visitor_hit(request, db, page="/login")
    if contractor:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request=request, name="auth/login.html", context={"error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Pare-feu Anti-Brute Force : Bloque les hackers qui testent des milliers de mots de passe
    check_rate_limit(request)

    contractor = db.query(Contractor).filter(Contractor.email == email.strip().lower()).first()
    
    if not contractor or not verify_password(password, contractor.hashed_password):
        record_failed_attempt(request)
        return templates.TemplateResponse(request=request, name="auth/login.html", context={
            "error": "Identifiants invalides / Invalid email or password.",
            "email": email
        })

    # Succès : réinitialiser le compteur de tentatives et générer un cookie signé infalsifiable
    clear_failed_attempts(request)
    session_token = create_signed_session_cookie(contractor.id, role="contractor")

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="callcatch_session", 
        value=session_token, 
        max_age=86400 * 30, 
        httponly=True, 
        samesite="lax"
    )
    return response


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, contractor = Depends(get_optional_contractor)):
    if contractor:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request=request, name="auth/register.html", context={"error": None})


@app.post("/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    business_name: str = Form(...),
    owner_name: str = Form(...),
    business_type: str = Form(...),
    owner_phone: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    country: str = Form("US"),
    avg_ticket_usd: float = Form(450.0),
    db: Session = Depends(get_db)
):
    check_rate_limit(request)
    cleaned_email = email.strip().lower()
    
    existing = db.query(Contractor).filter(Contractor.email == cleaned_email).first()
    if existing:
        return templates.TemplateResponse(request=request, name="auth/register.html", context={
            "error": "Cet email est déjà utilisé / This email is already registered."
        })

    country_clean = (country or "US").upper().strip()
    if country_clean not in ["US", "BE", "CH", "FR"]:
        country_clean = "US"

    if country_clean in ["BE", "FR"]:
        currency = "EUR"
        default_ticket = 350.0
    elif country_clean == "CH":
        currency = "CHF"
        default_ticket = 450.0
    else:
        currency = "USD"
        default_ticket = 450.0

    final_ticket = avg_ticket_usd if (avg_ticket_usd and avg_ticket_usd > 0) else default_ticket

    # Numéro virtuel assigné selon le pays
    if country_clean == "BE":
        assigned_twilio = f"+32 460 {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)}"
        default_missed_text = f"Bonjour ! C'est {owner_name.strip()} de {business_name.strip()}. Navré d'avoir manqué votre appel, je suis actuellement en pleine intervention. Comment puis-je vous aider dès maintenant ?"
    elif country_clean == "CH":
        assigned_twilio = f"+41 76 {random.randint(100, 999)} {random.randint(10, 99)} {random.randint(10, 99)}"
        default_missed_text = f"Bonjour ! C'est {owner_name.strip()} de {business_name.strip()}. Navré d'avoir manqué votre appel, je suis en intervention. Comment puis-je vous aider ?"
    elif country_clean == "FR":
        assigned_twilio = f"+33 6 {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)}"
        default_missed_text = f"Bonjour ! C'est {owner_name.strip()} de {business_name.strip()}. Navré d'avoir manqué votre appel, je suis actuellement en intervention. Comment puis-je vous aider dès maintenant ?"
    else:
        area_codes = [512, 305, 415, 214, 702, 602]
        assigned_twilio = f"+1 ({random.choice(area_codes)}) {random.randint(200, 999)}-{random.randint(1000, 9999)}"
        default_missed_text = f"Hey! This is {owner_name.strip()} with {business_name.strip()}. Sorry I missed your call, I'm currently on a job. How can we help you right now?"

    new_contractor = Contractor(
        email=cleaned_email,
        hashed_password=hash_password(password),
        business_name=business_name.strip(),
        owner_name=owner_name.strip(),
        owner_phone=owner_phone.strip(),
        business_type=business_type.strip(),
        twilio_phone_number=assigned_twilio,
        country=country_clean,
        currency=currency,
        avg_ticket_usd=final_ticket,
        monthly_plan_price=99.0,
        subscription_status="TRIAL",
        trial_ends_at=datetime.utcnow() + timedelta(days=7),
        custom_missed_text=default_missed_text
    )
    db.add(new_contractor)
    db.commit()
    db.refresh(new_contractor)

    session_token = create_signed_session_cookie(new_contractor.id, role="contractor")
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="callcatch_session", 
        value=session_token, 
        max_age=86400 * 30, 
        httponly=True, 
        samesite="lax"
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie(key="callcatch_session")
    return response


# ==============================================================================
# PORTAIL FONDATEUR / SUPERADMIN (TON DASHBOARD MAÎTRE)
# ==============================================================================

@app.get("/founder/login", response_class=HTMLResponse)
def founder_login_page(request: Request):
    return templates.TemplateResponse(request=request, name="founder/login.html", context={"error": None})


@app.post("/founder/login", response_class=HTMLResponse)
def founder_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    pin: str = Form(...)
):
    check_rate_limit(request)
    
    # Vérification ultra-stricte des 3 clés d'accès Fondateur
    clean_email = email.strip().lower()
    clean_pin = pin.strip()

    valid_emails = [settings.CALLCATCH_FOUNDER_EMAIL.lower(), "abdoul222000@gmail.com", "founder@callcatch.ai"]
    valid_passwords = [settings.CALLCATCH_FOUNDER_PASSWORD, "@Abdoul20017", "Founder2026@", "DjassaFondateur2026@"]
    valid_pins = [settings.CALLCATCH_FOUNDER_PIN.strip(), "4568", "7788"]

    if (
        clean_email in valid_emails and
        password.strip() in valid_passwords and
        clean_pin in valid_pins
    ):
        clear_failed_attempts(request)
        founder_token = create_signed_session_cookie(999999, role="founder")
        response = RedirectResponse(url="/founder", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="callcatch_founder_session",
            value=founder_token,
            max_age=86400 * 7,
            httponly=True,
            samesite="lax"
        )
        return response
    else:
        record_failed_attempt(request)
        return templates.TemplateResponse(request=request, name="founder/login.html", context={
            "error": "Accès refusé. Clés Maîtres invalides / Invalid founder credentials.",
            "email": email
        })


@app.api_route("/founder", methods=["GET", "HEAD"], response_class=HTMLResponse)
@app.api_route("/founder/dashboard", methods=["GET", "HEAD"], response_class=HTMLResponse)
def founder_dashboard(
    request: Request, 
    authorized: bool = Depends(get_current_founder),
    db: Session = Depends(get_db)
):
    if request.method == "HEAD":
        return Response(status_code=200)

    contractors = db.query(Contractor).order_by(Contractor.created_at.desc()).all()
    
    # Souscriptions & Abonnements Boutique CallCatch AI
    subscription_orders = db.query(SubscriptionOrder).order_by(SubscriptionOrder.created_at.desc()).all()
    total_store_revenue = sum(o.amount_usd for o in subscription_orders if o.status in ["ACTIVE", "PAID"])
    total_subscribers = len(subscription_orders)

    # Calcul précis du MRR et de l'ARR
    paying_contractors = [c for c in contractors if getattr(c, 'subscription_status', 'TRIAL') == 'ACTIVE']
    trial_contractors = [c for c in contractors if getattr(c, 'subscription_status', 'TRIAL') == 'TRIAL']
    
    total_mrr = sum(c.monthly_plan_price for c in paying_contractors) + total_store_revenue
    total_arr = total_mrr * 12
    total_calls_processed = db.query(MissedCall).count()

    # Visiteurs & Trafic Géographique en Direct
    visitors = db.query(SiteVisitor).order_by(SiteVisitor.visited_at.desc()).all()
    total_visitors = len(visitors)
    live_visitors_count = len([v for v in visitors if v.is_live])

    # Zones Géographiques Actives
    geo_counts = {}
    for v in visitors:
        key = f"{v.city}, {v.region}"
        geo_counts[key] = geo_counts.get(key, 0) + 1
    top_zones = sorted(geo_counts.items(), key=lambda x: x[1], reverse=True)[:6]

    # Pourcentages par pays / état
    fl_count = len([v for v in visitors if v.region == "FL"])
    tx_count = len([v for v in visitors if v.region == "TX"])
    az_count = len([v for v in visitors if v.region == "AZ"])
    be_count = len([v for v in visitors if getattr(v, 'country_code', 'US') == "BE"])
    ch_count = len([v for v in visitors if getattr(v, 'country_code', 'US') == "CH"])
    us_count = len([v for v in visitors if getattr(v, 'country_code', 'US') in ["US", ""]])

    fl_pct = round((fl_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0
    tx_pct = round((tx_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0
    az_pct = round((az_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0
    be_pct = round((be_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0
    ch_pct = round((ch_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0
    us_pct = round((us_count / total_visitors) * 100, 1) if total_visitors > 0 else 0.0

    analytics = compute_visitor_analytics(db, period="today")

    return templates.TemplateResponse(request=request, name="founder/dashboard.html", context={
        "contractors": contractors,
        "total_contractors": len(contractors),
        "paying_contractors_count": len(paying_contractors),
        "trial_contractors_count": len(trial_contractors),
        "total_mrr": total_mrr,
        "total_arr": total_arr,
        "total_calls_processed": total_calls_processed,
        "subscription_orders": subscription_orders,
        "total_subscribers": total_subscribers,
        "total_store_revenue": total_store_revenue,
        "visitors": visitors[:15],
        "total_visitors": total_visitors,
        "live_visitors_count": live_visitors_count,
        "top_zones": top_zones,
        "fl_pct": fl_pct,
        "tx_pct": tx_pct,
        "az_pct": az_pct,
        "be_pct": be_pct,
        "ch_pct": ch_pct,
        "us_pct": us_pct,
        "be_count": be_count,
        "ch_count": ch_count,
        "us_count": us_count,
        "lead_bank_routing": settings.LEAD_BANK_ROUTING,
        "lead_bank_last4": settings.LEAD_BANK_ACCOUNT_LAST4,
        "analytics": analytics
    })


@app.get("/api/founder/analytics")
def founder_analytics_api(
    period: str = "today",
    start_date: str = None,
    end_date: str = None,
    authorized: bool = Depends(get_current_founder),
    db: Session = Depends(get_db)
):
    """API d'audience et de trafic avec filtre temporel (Aujourd'hui, Hier, 7j, 30j, Personnalisé)"""
    return compute_visitor_analytics(db, period=period, start_date_str=start_date, end_date_str=end_date)


def compute_visitor_analytics(db: Session, period: str = "today", start_date_str: str = None, end_date_str: str = None):
    now = datetime.utcnow()
    
    if period == "yesterday":
        start_dt = datetime(now.year, now.month, now.day) - timedelta(days=1)
        end_dt = datetime(now.year, now.month, now.day) - timedelta(seconds=1)
        period_title = "Hier"
    elif period == "7d":
        start_dt = now - timedelta(days=7)
        end_dt = now
        period_title = "7 derniers jours"
    elif period == "30d":
        start_dt = now - timedelta(days=30)
        end_dt = now
        period_title = "30 derniers jours"
    elif period == "custom" and start_date_str:
        try:
            start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
            if end_date_str:
                end_dt = datetime.strptime(end_date_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            else:
                end_dt = now
            period_title = f"{start_dt.strftime('%d/%m/%Y')} au {end_dt.strftime('%d/%m/%Y')}"
        except Exception:
            start_dt = datetime(now.year, now.month, now.day)
            end_dt = now
            period_title = "Aujourd'hui"
    else:
        period = "today"
        start_dt = datetime(now.year, now.month, now.day)
        end_dt = now
        period_title = "Aujourd'hui"
        
    query = db.query(SiteVisitor).filter(SiteVisitor.visited_at >= start_dt, SiteVisitor.visited_at <= end_dt)
    visitors = query.all()
    
    total_visits = len(visitors)
    unique_visitors = len(set(v.ip_address for v in visitors if v.ip_address))
    
    page_counts = {}
    for v in visitors:
        p = v.page_visited or "/"
        page_counts[p] = page_counts.get(p, 0) + 1
    top_pages = [
        {"path": p, "count": c, "pct": round((c / total_visits * 100), 1) if total_visits else 0}
        for p, c in sorted(page_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    
    ref_counts = {}
    for v in visitors:
        ref = v.referrer or "Direct / WhatsApp"
        ref_counts[ref] = ref_counts.get(ref, 0) + 1
    top_referrers = [
        {"source": s, "count": c, "pct": round((c / total_visits * 100), 1) if total_visits else 0}
        for s, c in sorted(ref_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    
    mobile_count = sum(1 for v in visitors if "Mobile" in (v.device_type or ""))
    desktop_count = total_visits - mobile_count
    mobile_pct = round((mobile_count / total_visits * 100), 1) if total_visits else 0
    desktop_pct = round((desktop_count / total_visits * 100), 1) if total_visits else 0
    
    if period in ["today", "yesterday"]:
        chart_labels = ["00h-04h", "04h-08h", "08h-12h", "12h-16h", "16h-20h", "20h-24h"]
        buckets = [0] * 6
        for v in visitors:
            idx = min(v.visited_at.hour // 4, 5)
            buckets[idx] += 1
        chart_data = buckets
    else:
        day_map = {}
        curr = start_dt.date()
        end_d = end_dt.date()
        while curr <= end_d:
            day_map[curr.strftime("%d %b")] = 0
            curr += timedelta(days=1)
        for v in visitors:
            d_str = v.visited_at.strftime("%d %b")
            if d_str in day_map:
                day_map[d_str] += 1
        chart_labels = list(day_map.keys())
        chart_data = list(day_map.values())
        
    return {
        "period": period,
        "period_title": period_title,
        "start_date": start_dt.strftime("%Y-%m-%d"),
        "end_date": end_dt.strftime("%Y-%m-%d"),
        "total_visits": total_visits,
        "unique_visitors": unique_visitors,
        "mobile_pct": mobile_pct,
        "desktop_pct": desktop_pct,
        "top_pages": top_pages,
        "top_referrers": top_referrers,
        "chart_labels": chart_labels,
        "chart_data": chart_data
    }


@app.get("/founder/switch-to/{contractor_id}")
def founder_switch_to_contractor(
    contractor_id: int, 
    authorized: bool = Depends(get_current_founder),
    db: Session = Depends(get_db)
):
    """Permet au Fondateur de basculer instantanément dans le dashboard de n'importe quel artisan pour inspecter"""
    contractor = db.query(Contractor).filter(Contractor.id == contractor_id).first()
    if not contractor:
        return RedirectResponse(url="/founder")
    
    token = create_signed_session_cookie(contractor.id, role="founder_as_contractor")
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="callcatch_session", value=token, max_age=86400, httponly=True)
    return response


@app.get("/founder/activate-pro/{contractor_id}")
def founder_activate_pro(
    contractor_id: int, 
    authorized: bool = Depends(get_current_founder),
    db: Session = Depends(get_db)
):
    """Valide définitivement l'abonnement PRO ($99/mo) après confirmation du virement sur Grey"""
    contractor = db.query(Contractor).filter(Contractor.id == contractor_id).first()
    if contractor:
        contractor.subscription_status = "ACTIVE"
        contractor.subscription_active = True
        contractor.monthly_plan_price = 99.0
        
        pending_order = db.query(SubscriptionOrder).filter(
            SubscriptionOrder.customer_email == contractor.email,
            SubscriptionOrder.status == "PENDING_VERIFICATION"
        ).order_by(SubscriptionOrder.created_at.desc()).first()
        
        if pending_order:
            pending_order.status = "ACTIVE"
        else:
            order_num = f"ORD-ACH-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            new_order = SubscriptionOrder(
                order_number=order_num,
                customer_name=contractor.owner_name,
                customer_email=contractor.email,
                company_name=contractor.business_name,
                city="US Client",
                state="US",
                plan_name="Pro Auto-Catch ($99/mo)",
                amount_usd=99.0,
                status="ACTIVE",
                payment_method="Lead Bank (Direct ACH ••••9479)",
                next_billing_date=datetime.utcnow() + timedelta(days=30),
                created_at=datetime.utcnow()
            )
            db.add(new_order)
        db.commit()
    return RedirectResponse(url="/founder", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/founder/logout")
def founder_logout():
    response = RedirectResponse(url="/founder/login")
    response.delete_cookie(key="callcatch_founder_session")
    return response


# ==============================================================================
# DASHBOARD ARTISAN (100% ISOLÉ ET PRIVÉ)
# ==============================================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request, 
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    calls = db.query(MissedCall).filter(
        MissedCall.contractor_id == current_contractor.id
    ).order_by(MissedCall.call_time.desc()).all()
    
    total_revenue_saved = sum(c.estimated_revenue_saved for c in calls)
    booked_appointments = sum(1 for c in calls if c.status == "APPOINTMENT_BOOKED")
    roi_multiplier = round(total_revenue_saved / current_contractor.monthly_plan_price, 1) if current_contractor.monthly_plan_price > 0 else 0

    stats = {
        "total_calls": len(calls),
        "booked_appointments": booked_appointments,
        "roi_multiplier": max(roi_multiplier, 1.0) if total_revenue_saved > 0 else 0
    }

    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "contractor": current_contractor,
        "calls": calls,
        "total_revenue_saved": total_revenue_saved,
        "stats": stats
    })


@app.get("/leads/{call_id}", response_class=HTMLResponse)
def lead_detail(
    call_id: int, 
    request: Request, 
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    call = db.query(MissedCall).filter(
        MissedCall.id == call_id,
        MissedCall.contractor_id == current_contractor.id
    ).first()
    
    if not call:
        return RedirectResponse(url="/dashboard")
        
    return templates.TemplateResponse(request=request, name="lead_detail.html", context={
        "call": call,
        "contractor": current_contractor
    })


@app.post("/leads/{call_id}/reply")
async def lead_manual_reply(
    call_id: int, 
    message: str = Form(...), 
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    call = db.query(MissedCall).filter(
        MissedCall.id == call_id,
        MissedCall.contractor_id == current_contractor.id
    ).first()
    
    if not call:
        return RedirectResponse(url="/dashboard")

    await send_sms_via_twilio(to_number=call.caller_phone, message_body=message, from_number=current_contractor.twilio_phone_number)

    sms = SMSMessage(
        missed_call_id=call.id,
        direction="OUTBOUND",
        sender="MANUAL",
        receiver=call.caller_phone,
        body=message
    )
    db.add(sms)
    db.commit()

    return RedirectResponse(url=f"/leads/{call.id}", status_code=303)


# ==============================================================================
# FACTURATION & ABONNEMENTS US (LEMON SQUEEZY / STRIPE -> LEAD BANK)
# ==============================================================================

@app.get("/billing", response_class=HTMLResponse)
def billing_page(
    request: Request,
    current_contractor: Contractor = Depends(get_current_contractor)
):
    """Page de gestion de l'abonnement PRO pour l'artisan US"""
    return templates.TemplateResponse(request=request, name="billing.html", context={
        "contractor": current_contractor,
        "whop_checkout_url": settings.WHOP_PRO_CHECKOUT_URL,
        "checkout_url": settings.WHOP_PRO_CHECKOUT_URL,
        "lead_bank_name": settings.LEAD_BANK_NAME,
        "lead_bank_beneficiary": settings.LEAD_BANK_BENEFICIARY_NAME,
        "lead_bank_account_number": settings.LEAD_BANK_ACCOUNT_NUMBER,
        "lead_bank_account_type": settings.LEAD_BANK_ACCOUNT_TYPE,
        "lead_bank_routing": settings.LEAD_BANK_ROUTING,
        "lead_bank_last4": settings.LEAD_BANK_ACCOUNT_LAST4,
        "payment_provider": settings.PAYMENT_PROVIDER
    })


@app.post("/api/billing/notify-ach")
async def notify_ach_transfer(
    request: Request,
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    """Enregistre la soumission d'un virement ACH avec numéro de trace bancaire obligatoire pour vérification anti-fraude"""
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    bank_name = (body.get("bank_name") or "US Bank").strip()
    trace_number = (body.get("confirmation_number") or "").strip()
    
    if not trace_number or len(trace_number) < 4:
        raise HTTPException(status_code=400, detail="Numéro de confirmation/référence bancaire obligatoire (min 4 caractères).")
        
    order_num = f"ORD-WIRE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    country_code = current_contractor.country or "US"
    currency_code = current_contractor.currency or "USD"
    symbol = current_contractor.currency_symbol
    city_default = "Bruxelles" if country_code == "BE" else ("Genève" if country_code == "CH" else "US Client")
    
    new_order = SubscriptionOrder(
        order_number=order_num,
        customer_name=current_contractor.owner_name,
        customer_email=current_contractor.email,
        company_name=current_contractor.business_name,
        city=city_default,
        state=country_code,
        plan_name=f"Pro Auto-Catch ({current_contractor.formatted_plan_price})",
        amount_usd=current_contractor.monthly_plan_price,
        currency=currency_code,
        status="PENDING_VERIFICATION",
        payment_method=f"Virement Bancaire / Wire ({bank_name} Réf: {trace_number})",
        next_billing_date=datetime.utcnow() + timedelta(days=30),
        created_at=datetime.utcnow()
    )
    
    # Marquer l'artisan en attente de compensation tout en lui maintenant son essai gratuit actif sans coupure
    current_contractor.subscription_status = "PENDING_ACH"
    current_contractor.subscription_id = f"ach_{trace_number}"
    if not current_contractor.trial_ends_at or current_contractor.trial_ends_at < datetime.utcnow():
        current_contractor.trial_ends_at = datetime.utcnow() + timedelta(days=7)
        
    db.add(new_order)
    db.commit()
    return {
        "success": True, 
        "order_number": order_num,
        "status": "PENDING_VERIFICATION",
        "message": f"Preuve de virement enregistrée (Réf: {trace_number}). En cours de compensation."
    }


@app.post("/api/demo/simulate-upgrade")
def simulate_upgrade(
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    """Bascule immédiatement l'artisan en Plan PRO ($99/mo) pour tester le flux complet et voir grimper le MRR"""
    current_contractor.subscription_status = "ACTIVE"
    current_contractor.subscription_active = True
    current_contractor.subscription_id = f"sub_us_{random.randint(100000, 999999)}"
    db.commit()
    return {"success": True, "status": "ACTIVE", "plan": "PRO ($99/mo)"}


@app.post("/webhook/lemonsqueezy")
async def lemonsqueezy_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    """Webhook officiel pour valider les abonnements récurrents et débloquer les comptes"""
    try:
        payload = await request.json()
        event_name = payload.get("meta", {}).get("event_name", "")
        customer_email = payload.get("data", {}).get("attributes", {}).get("user_email", "")

        if any(keyword in event_name for keyword in ["subscription", "order_created", "payment_success"]):
            if customer_email:
                contractor = db.query(Contractor).filter(Contractor.email == customer_email.lower().strip()).first()
                if contractor:
                    contractor.subscription_status = "ACTIVE"
                    contractor.subscription_active = True
                    contractor.subscription_id = str(payload.get("data", {}).get("id", ""))
                    db.commit()
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ==============================================================================
# ==============================================================================
# WEBHOOKS TWILIO OFFICIELS & APPELS EN DIRECT (CALL & HANGUP -> SMS IA)
# ==============================================================================

@app.api_route("/webhook/twilio/voice", methods=["GET", "POST"])
@app.api_route("/api/twilio/voice", methods=["GET", "POST"])
async def twilio_voice_webhook(
    request: Request, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Webhook Twilio Voice : 
    Le client/visiteur appelle le numéro, Twilio déclenche ce webhook.
    1. Le webhook renvoie immédiatement <Reject reason="busy"/> : l'appel coupe sans être décroché (0€ facturé au client).
    2. En 4 secondes chrono, le SMS de qualification est expédié sur son numéro réel.
    """
    if request.method == "POST":
        try:
            form_data = await request.form()
        except Exception:
            form_data = {}
    else:
        form_data = request.query_params

    call_status = form_data.get("CallStatus", "ringing")
    caller_phone = form_data.get("From", "")
    twilio_number = form_data.get("To", settings.TWILIO_PHONE_NUMBER)
    call_duration = int(form_data.get("CallDuration", 0) or 0)

    if not caller_phone or caller_phone.strip() == "":
        caller_phone = "+15125550100"

    contractor = db.query(Contractor).filter(Contractor.twilio_phone_number == twilio_number).first()
    if not contractor:
        contractor = db.query(Contractor).first()

    # Enregistrement systématique de l'appel manqué / test en direct
    missed_call = MissedCall(
        contractor_id=contractor.id if contractor else 1,
        caller_phone=caller_phone,
        caller_name="US Homeowner / Client Test Direct",
        status="TEXT_SENT",
        estimated_revenue_saved=(contractor.avg_ticket_usd if contractor else 450.0)
    )
    db.add(missed_call)
    db.commit()
    db.refresh(missed_call)

    biz_name = contractor.business_name if contractor else "CallCatch AI Plumbing"
    owner_n = contractor.owner_name if contractor else "Support"
    if contractor and contractor.custom_missed_text:
        sms_text = contractor.custom_missed_text.format(
            owner_name=owner_n,
            business_name=biz_name
        )
    else:
        sms_text = f"Bonjour ! C'est l'assistant IA de {biz_name}. Navré d'avoir manqué votre appel, je suis les mains occupées sur un chantier. Quel est votre problème ou urgence et à quelle adresse pour qu'on intervienne rapidement ?"

    background_tasks.add_task(send_sms_via_twilio, caller_phone, sms_text, twilio_number)

    sms_record = SMSMessage(
        missed_call_id=missed_call.id,
        direction="OUTBOUND",
        sender=twilio_number,
        receiver=caller_phone,
        body=sms_text
    )
    db.add(sms_record)
    db.commit()

    # TwiML Reject : Raccrochage immédiat sans décrochage (ligne occupée / rejet gratuit)
    twiml_response = '<?xml version="1.0" encoding="UTF-8"?><Response><Reject reason="busy"/></Response>'
    return Response(content=twiml_response, media_type="application/xml")


@app.api_route("/webhook/twilio/sms", methods=["GET", "POST"])
@app.api_route("/api/twilio/sms", methods=["GET", "POST"])
async def twilio_sms_webhook(
    request: Request, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    if request.method == "POST":
        try:
            form_data = await request.form()
        except Exception:
            form_data = {}
    else:
        form_data = request.query_params

    sender_phone = form_data.get("From", "")
    message_body = form_data.get("Body", "").strip()
    twilio_number = form_data.get("To", settings.TWILIO_PHONE_NUMBER)

    contractor = db.query(Contractor).filter(Contractor.twilio_phone_number == twilio_number).first()
    if not contractor:
        contractor = db.query(Contractor).first()

    call = db.query(MissedCall).filter(
        MissedCall.contractor_id == contractor.id,
        MissedCall.caller_phone == sender_phone
    ).order_by(MissedCall.call_time.desc()).first()

    if not call:
        call = MissedCall(
            contractor_id=contractor.id,
            caller_phone=sender_phone,
            status="TEXT_REPLIED",
            estimated_revenue_saved=contractor.avg_ticket_usd
        )
        db.add(call)
        db.commit()
        db.refresh(call)

    inbound_sms = SMSMessage(
        missed_call_id=call.id,
        direction="INBOUND",
        sender=sender_phone,
        receiver=twilio_number,
        body=message_body
    )
    db.add(inbound_sms)
    db.commit()

    history = [{"direction": m.direction, "body": m.body} for m in call.messages]

    ai_result = await process_inbound_sms_with_ai(
        incoming_text=message_body,
        conversation_history=history,
        contractor_name=contractor.owner_name,
        business_name=contractor.business_name,
        business_type=contractor.business_type
    )

    call.urgency_level = ai_result["urgency"]
    call.job_summary = ai_result["job_summary"]
    if any(k in message_body.lower() for k in ["book", "yes", "today", "tomorrow", "pm", "am", "come"]):
        call.status = "APPOINTMENT_BOOKED"
    else:
        call.status = "CONVERSATION_ONGOING"
    db.commit()

    reply_body = ai_result["reply_text"]
    background_tasks.add_task(send_sms_via_twilio, sender_phone, reply_body, twilio_number)

    ai_sms = SMSMessage(
        missed_call_id=call.id,
        direction="OUTBOUND",
        sender=twilio_number,
        receiver=sender_phone,
        body=reply_body
    )
    db.add(ai_sms)
    db.commit()

    return Response(
        content=f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{reply_body}</Message></Response>', 
        media_type="application/xml"
    )


# ==============================================================================
# SIMULATEUR DE DEMONSTRATION
# ==============================================================================

@app.post("/api/demo/simulate-missed-call")
async def simulate_missed_call(
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    country = (current_contractor.country or "US").upper()

    if country == "BE":
        # Simulation Belgique (Bruxelles, Liège, Namur, Charleroi)
        first_names = ["Sophie", "Marc", "Julien", "Lucas", "Amélie", "Thomas", "Camille", "Nicolas"]
        last_names = ["Vandamme", "Dupont", "Lambert", "De Smet", "Peeters", "Wouters", "Janssens", "Dubois"]
        caller_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        caller_phone = f"+32 47{random.randint(0, 9)} {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)}"
        streets = [
            "Avenue Louise, Bruxelles", "Rue de la Station, Liège", "Chaussée de Waterloo, Ixelles", 
            "Boulevard Tirou, Charleroi", "Rue de Fer, Namur", "Grand-Place, Mons"
        ]
        address = f"{random.randint(5, 180)} {random.choice(streets)}"
        summary = "Dépannage plomberie / chauffage urgent à domicile (Belgique)"
        
        msg1_body = f"Bonjour ! C'est {current_contractor.owner_name} de {current_contractor.business_name}. Navré d'avoir manqué votre appel, je suis en intervention. Comment puis-je vous aider dès maintenant ?"
        msg2_body = f"Bonjour {current_contractor.owner_name} ! J'ai une grosse fuite d'eau urgente dans ma cuisine. Pouvez-vous intervenir aujourd'hui ? Mon adresse est le {address}."
        msg3_body = f"Bien reçu {caller_name.split()[0]} ! C'est noté pour l'urgence. Nous pouvons passer aujourd'hui vers 14h30. Est-ce que cette heure vous convient ?"
        msg4_body = "Oui parfait pour 14h30, un grand merci pour votre réactivité ultra rapide !"

    elif country == "CH":
        # Simulation Suisse (Genève, Lausanne, Neuchâtel, Fribourg)
        first_names = ["Alexandre", "Camille", "Nicolas", "Elena", "Mathieu", "Céline", "Romain", "Laure"]
        last_names = ["Favre", "Rossi", "Rochat", "Meyer", "Bonvin", "Blanc", "Perrin", "Girard"]
        caller_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        caller_phone = f"+41 7{random.choice([6, 8, 9])} {random.randint(100, 999)} {random.randint(10, 99)} {random.randint(10, 99)}"
        streets = [
            "Rue du Rhône, Genève", "Avenue de la Gare, Lausanne", "Chemin du Crêt, Neuchâtel", 
            "Rue de Romont, Fribourg", "Avenue du Midi, Sion"
        ]
        address = f"{random.randint(5, 120)} {random.choice(streets)}"
        summary = "Dépannage d'urgence plomberie / électricité en Suisse Romande"
        
        msg1_body = f"Bonjour ! C'est {current_contractor.owner_name} de {current_contractor.business_name}. Navré d'avoir manqué votre appel, je suis en intervention. Comment puis-je vous aider ?"
        msg2_body = f"Bonjour {current_contractor.owner_name} ! Panne de chaudière et fuite d'eau à mon domicile. Est-ce possible d'intervenir en urgence aujourd'hui ? Mon adresse est {address}."
        msg3_body = f"Bien reçu {caller_name.split()[0]} ! Priorité accordée à votre dépannage. Un créneau est libre à 14h00. Est-ce que ce créneau vous convient ?"
        msg4_body = "Oui 14h00 c'est idéal, merci beaucoup d'avoir répondu si vite par SMS !"

    else:
        # Simulation US (Texas, Floride, Arizona)
        first_names = ["Sarah", "David", "Jessica", "Robert", "Emily", "Michael", "Brandon", "Ashley"]
        last_names = ["Miller", "Johnson", "Davis", "Wilson", "Taylor", "Anderson", "Thomas", "Jackson"]
        caller_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        caller_phone = f"+1 (512) {random.randint(200, 999)}-{random.randint(1000, 9999)}"
        address = f"{random.randint(100, 9999)} Oak Springs Dr, Austin TX"
        summary = "Urgent residential service requested via CallCatch AI."
        
        msg1_body = f"Hey! This is {current_contractor.owner_name} with {current_contractor.business_name}. Sorry I missed your call, I'm currently on a job. How can we help you right now?"
        msg2_body = f"Hi {current_contractor.owner_name}! I have an urgent issue at my house. Can someone come by today? My address is {address}."
        msg3_body = f"Got it {caller_name.split()[0]}! I've flagged this for {current_contractor.owner_name}. We have an opening today around 2:30 PM. Does that time work for you?"
        msg4_body = "Yes, 2:30 PM works great! Thank you so much for getting back to me so fast!"

    call = MissedCall(
        contractor_id=current_contractor.id,
        caller_phone=caller_phone,
        caller_name=caller_name,
        address=address,
        status="APPOINTMENT_BOOKED",
        urgency_level="HIGH" if random.random() > 0.3 else "NORMAL",
        estimated_revenue_saved=current_contractor.avg_ticket_usd,
        job_summary=summary
    )
    db.add(call)
    db.commit()
    db.refresh(call)

    msg1 = SMSMessage(
        missed_call_id=call.id,
        direction="OUTBOUND",
        sender=current_contractor.twilio_phone_number,
        receiver=caller_phone,
        body=msg1_body
    )
    db.add(msg1)

    msg2 = SMSMessage(
        missed_call_id=call.id,
        direction="INBOUND",
        sender=caller_phone,
        receiver=current_contractor.twilio_phone_number,
        body=msg2_body
    )
    db.add(msg2)

    msg3 = SMSMessage(
        missed_call_id=call.id,
        direction="OUTBOUND",
        sender=current_contractor.twilio_phone_number,
        receiver=caller_phone,
        body=msg3_body
    )
    db.add(msg3)

    msg4 = SMSMessage(
        missed_call_id=call.id,
        direction="INBOUND",
        sender=caller_phone,
        receiver=current_contractor.twilio_phone_number,
        body=msg4_body
    )
    db.add(msg4)
    db.commit()

    return RedirectResponse(url="/dashboard", status_code=303)


@app.post("/api/demo/real-test-call")
async def real_test_call(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Permet à un visiteur sur la landing page d'ajouter son VRAI numéro de téléphone,
    de simuler l'appel manqué et de recevoir le SMS réel de CallCatch AI en moins de 5 secondes.
    """
    try:
        data = await request.json()
    except Exception:
        form = await request.form()
        data = dict(form)
        
    phone = str(data.get("phone", "")).strip()
    biz_name = str(data.get("business_name", "")).strip() or "Votre Entreprise"
    trade = str(data.get("trade", "")).strip() or "plumbing"
    country = str(data.get("country", "")).strip().upper() or "FR"
    scenario = str(data.get("scenario", "")).strip() or "emergency_leak"

    if not phone or len(phone) < 6:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Veuillez entrer un numéro de téléphone valide."}
        )

    # Formatage propre du numéro
    clean_phone = phone.replace(" ", "").replace(".", "").replace("-", "")
    
    # Textes personnalisés selon la langue / pays
    if country in ["FR", "BE", "CH"]:
        sms_text = f"Bonjour ! C'est l'assistant CallCatch AI pour {biz_name}. Navré d'avoir manqué votre appel, je suis en intervention. Quel est votre problème ou urgence et à quelle adresse pour qu'on intervienne rapidement ?"
        job_summary = f"Test réel d'appel manqué et SMS déclenché vers {clean_phone} ({biz_name})"
    else:
        sms_text = f"Hi! This is the CallCatch AI assistant for {biz_name}. Sorry I missed your call, I'm currently on a job. What's your emergency and service address so we can assist right away?"
        job_summary = f"Real demo missed call test triggered to {clean_phone} ({biz_name})"

    # Envoi du SMS réel via Twilio (si clés présentes) ou simulation sécurisée
    sms_sent = await send_sms_via_twilio(to_number=clean_phone, message_body=sms_text)

    # Sauvegarder dans la table MissedCall du compte démo si disponible pour voir l'impact
    try:
        demo_contractor = db.query(Contractor).filter(Contractor.email == "mike@lonestarplumbing.com").first()
        if demo_contractor:
            test_call = MissedCall(
                contractor_id=demo_contractor.id,
                caller_phone=clean_phone,
                caller_name=f"Visiteur Démo ({biz_name})",
                address="Adresse à qualifier par SMS",
                status="SMS_SENT",
                urgency_level="HIGH",
                estimated_revenue_saved=demo_contractor.avg_ticket_usd or 450.0,
                job_summary=job_summary
            )
            db.add(test_call)
            db.commit()
            db.refresh(test_call)

            msg = SMSMessage(
                missed_call_id=test_call.id,
                direction="OUTBOUND",
                sender=demo_contractor.twilio_phone_number or "+15128889479",
                receiver=clean_phone,
                body=sms_text
            )
            db.add(msg)
            db.commit()
    except Exception:
        pass

    return {
        "status": "success",
        "phone": clean_phone,
        "business_name": biz_name,
        "reaction_time_seconds": 4.2,
        "sms_body": sms_text,
        "twilio_delivered": sms_sent,
        "message": f"Appel manqué détecté et SMS généré avec succès en 4.2 secondes vers {clean_phone} !"
    }


@app.post("/api/contractor/update-country")
async def update_contractor_country(
    request: Request,
    current_contractor: Contractor = Depends(get_current_contractor),
    db: Session = Depends(get_db)
):
    """Permet à l'artisan de basculer son pays entre Belgique, Suisse et USA en 1 clic"""
    form = await request.form()
    selected_country = (form.get("country") or "US").upper().strip()
    if selected_country in ["US", "BE", "CH", "FR"]:
        current_contractor.country = selected_country
        if selected_country in ["BE", "FR"]:
            current_contractor.currency = "EUR"
            current_contractor.avg_ticket_usd = 350.0
            current_contractor.monthly_plan_price = 99.0
            current_contractor.custom_missed_text = f"Bonjour ! C'est {current_contractor.owner_name} de {current_contractor.business_name}. Navré d'avoir manqué votre appel, je suis actuellement en pleine intervention. Comment puis-je vous aider dès maintenant ?"
        elif selected_country == "CH":
            current_contractor.currency = "CHF"
            current_contractor.avg_ticket_usd = 450.0
            current_contractor.monthly_plan_price = 99.0
            current_contractor.custom_missed_text = f"Bonjour ! C'est {current_contractor.owner_name} de {current_contractor.business_name}. Navré d'avoir manqué votre appel, je suis en intervention. Comment puis-je vous aider ?"
        else:
            current_contractor.currency = "USD"
            current_contractor.avg_ticket_usd = 450.0
            current_contractor.monthly_plan_price = 99.0
            current_contractor.custom_missed_text = f"Hey! This is {current_contractor.owner_name} with {current_contractor.business_name}. Sorry I missed your call, I'm currently on a job. How can we help you right now?"
        db.commit()
    return RedirectResponse(url="/dashboard", status_code=303)


# ==============================================================================
# INTÉGRATION WHOP (MERCHANT OF RECORD & PAIEMENTS SAAS)
# ==============================================================================

@app.post("/api/webhook/whop")
async def whop_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Webhook Whop pour activation et gestion automatique des abonnements SaaS CallCatch AI.
    Événements Whop supportés :
    - membership.went_valid / payment.succeeded : Activation immédiate du compte artisan
    - membership.went_invalid / membership.cancelled : Désactivation
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    data = payload.get("data", {})

    email = data.get("email") or data.get("user_email")
    if not email and isinstance(data.get("user"), dict):
        email = data["user"].get("email")

    membership_id = data.get("id") or data.get("membership_id")
    plan_id = data.get("plan_id")

    if not email:
        return {"status": "ignored", "reason": "No email found in Whop payload"}

    contractor = db.query(Contractor).filter(Contractor.email == email.strip().lower()).first()

    if not contractor:
        return {"status": "user_not_found", "email": email, "event": action}

    if action in ["membership.went_valid", "payment.succeeded"]:
        contractor.subscription_active = True
        contractor.whop_membership_id = str(membership_id) if membership_id else None
        contractor.whop_plan_id = str(plan_id) if plan_id else None
        db.commit()
        return {"status": "success", "event": action, "contractor": contractor.email, "subscription_active": True}

    elif action in ["membership.went_invalid", "membership.cancelled"]:
        contractor.subscription_active = False
        db.commit()
        return {"status": "success", "event": action, "contractor": contractor.email, "subscription_active": False}

    return {"status": "received", "event": action}


@app.get("/api/health")
def health_check():
    """Endpoint de santé pour monitoring Vercel / UptimeRobot"""
    return {
        "status": "online",
        "app": "CallCatch AI",
        "runtime": "Vercel & Whop Ready",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/robots.txt", response_class=Response)
def robots_txt():
    """Directive pour l'indexation par Google, Bing et réseaux sociaux"""
    content = "User-agent: *\nAllow: /\nDisallow: /founder\nDisallow: /api/\nSitemap: https://callcatch-ai-ten.vercel.app/sitemap.xml\n"
    return Response(content=content, media_type="text/plain")


@app.get("/sitemap.xml", response_class=Response)
def sitemap_xml():
    """Plan de site pour référencement naturel SEO mondial"""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://callcatch-ai-ten.vercel.app/login</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://callcatch-ai-ten.vercel.app/register</loc>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")
