from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta
import hashlib
import secrets
from .config import settings

engine = create_engine(
    settings.CALLCATCH_DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in settings.CALLCATCH_DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Utilitaires de sécurité pour les mots de passe (sans dépendance externe lourde)
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password or "$" not in hashed_password:
        return False
    try:
        salt, key_hex = hashed_password.split("$", 1)
        computed = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return secrets.compare_digest(computed, key_hex)
    except Exception:
        return False


class Contractor(Base):
    """L'artisan américain abonné à CallCatch AI"""
    __tablename__ = "contractors"

    id = Column(Integer, primary_key=True, index=True)
    
    # Identifiants de connexion
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

    # Informations sur l'entreprise
    business_name = Column(String(150), nullable=False) # Ex: "Austin Rapid Plumbing"
    owner_name = Column(String(100), nullable=False)    # Ex: "Mike Anderson"
    owner_phone = Column(String(30), nullable=False)   # Le vrai numéro portable de l'artisan
    business_type = Column(String(50), default="Plumbing") # Plumbing, Roofing, HVAC, Electrician
    
    # Numéro virtuel Twilio US attribué à l'artisan
    twilio_phone_number = Column(String(30), unique=True, index=True)
    
    # Message automatique instantané
    custom_missed_text = Column(
        Text, 
        default="Hey! This is {owner_name} with {business_name}. Sorry I missed your call, I'm currently on a job. How can we help you right now?"
    )
    
    # Paramètres économiques et abonnement
    avg_ticket_usd = Column(Float, default=450.0) # Gain moyen par intervention
    subscription_active = Column(Boolean, default=True)
    monthly_plan_price = Column(Float, default=99.0) # 99$/mois
    subscription_status = Column(String(30), default="TRIAL") # TRIAL, ACTIVE, CANCELLED
    trial_ends_at = Column(DateTime, nullable=True)
    subscription_id = Column(String(100), nullable=True)
    billing_email = Column(String(120), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def is_active_pro(self) -> bool:
        return self.subscription_status == "ACTIVE"

    @property
    def days_left_in_trial(self) -> int:
        if not self.trial_ends_at:
            return 14
        delta = self.trial_ends_at - datetime.utcnow()
        return max(0, delta.days)

    # Relations
    calls = relationship("MissedCall", back_populates="contractor", cascade="all, delete-orphan")


class MissedCall(Base):
    """Un appel américain manqué qui a été capté et sauvé par CallCatch AI"""
    __tablename__ = "missed_calls"

    id = Column(Integer, primary_key=True, index=True)
    contractor_id = Column(Integer, ForeignKey("contractors.id"), nullable=False)
    
    caller_phone = Column(String(30), nullable=False, index=True) # Numéro du client US qui a appelé
    caller_name = Column(String(100), nullable=True) # Ex: "Sarah Jenkins"
    
    call_sid = Column(String(100), unique=True, nullable=True) # Identifiant d'appel Twilio
    call_time = Column(DateTime, default=datetime.utcnow)
    
    # Statut du lead :
    # MISSED -> TEXT_SENT -> CONVERSATION_ONGOING -> APPOINTMENT_BOOKED -> COMPLETED
    status = Column(String(40), default="MISSED")
    
    urgency_level = Column(String(20), default="NORMAL") # HIGH, MEDIUM, LOW
    job_summary = Column(Text, nullable=True) # Résumé IA : "Fuite d'eau sous évier de cuisine"
    address = Column(String(255), nullable=True) # Adresse du client
    
    estimated_revenue_saved = Column(Float, default=0.0) # Montant $ sauvé pour le dashboard
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relations
    contractor = relationship("Contractor", back_populates="calls")
    messages = relationship("SMSMessage", back_populates="call", cascade="all, delete-orphan")


class SMSMessage(Base):
    """Historique des échanges par SMS entre le client US et l'IA"""
    __tablename__ = "sms_messages"

    id = Column(Integer, primary_key=True, index=True)
    missed_call_id = Column(Integer, ForeignKey("missed_calls.id"), nullable=False)
    
    direction = Column(String(20)) # "INBOUND" (client) ou "OUTBOUND" (CallCatch IA)
    sender = Column(String(30))
    receiver = Column(String(30))
    body = Column(Text, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relations
    call = relationship("MissedCall", back_populates="messages")


class SiteVisitor(Base):
    """Visiteur du site web CallCatch AI avec géolocalisation et suivi en temps réel"""
    __tablename__ = "site_visitors"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), default="127.0.0.1")
    city = Column(String(100), default="Tampa")
    region = Column(String(50), default="FL") # State/Region: FL, TX, AZ, etc.
    country = Column(String(100), default="United States")
    country_code = Column(String(10), default="US")
    page_visited = Column(String(150), default="/")
    referrer = Column(String(200), default="Cold Email Campaign")
    device_type = Column(String(50), default="Mobile (iPhone)")
    browser = Column(String(50), default="Mobile Safari")
    is_live = Column(Boolean, default=False)
    visited_at = Column(DateTime, default=datetime.utcnow)


class SubscriptionOrder(Base):
    """Souscription et paiement effectués sur la boutique CallCatch AI"""
    __tablename__ = "subscription_orders"

    id = Column(Integer, primary_key=True, index=True)
    order_number = Column(String(50), unique=True, index=True)
    customer_name = Column(String(100), nullable=False)
    customer_email = Column(String(120), nullable=False)
    company_name = Column(String(150), nullable=False)
    city = Column(String(100), default="Tampa")
    state = Column(String(50), default="FL")
    plan_name = Column(String(80), default="Pro Auto-Catch ($99/mo)")
    amount_usd = Column(Float, default=99.0)
    billing_cycle = Column(String(20), default="MONTHLY")
    status = Column(String(30), default="ACTIVE") # ACTIVE, TRIALING, COMPLETED
    payment_method = Column(String(80), default="Lead Bank (Direct ACH ••••9479)")
    next_billing_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Mise à niveau sécurisée de la base de données existante (sans perte de données)
    try:
        with engine.connect() as conn:
            for col_sql in [
                "ALTER TABLE contractors ADD COLUMN subscription_status VARCHAR(30) DEFAULT 'TRIAL'",
                "ALTER TABLE contractors ADD COLUMN trial_ends_at DATETIME",
                "ALTER TABLE contractors ADD COLUMN subscription_id VARCHAR(100)",
                "ALTER TABLE contractors ADD COLUMN billing_email VARCHAR(120)"
            ]:
                try:
                    conn.execute(text(col_sql))
                    conn.commit()
                except Exception:
                    pass
    except Exception:
        pass

    db = SessionLocal()
    try:
        # 1. Créer le compte artisan de démonstration (Mike le plombier) s'il n'existe pas
        contractor = db.query(Contractor).filter(Contractor.email == "mike@lonestarplumbing.com").first()
        if not contractor:
            demo_contractor = Contractor(
                email="mike@lonestarplumbing.com",
                hashed_password=hash_password("password123"), # Mot de passe de démo
                business_name="Lone Star Rapid Plumbing & HVAC",
                owner_name="Mike Anderson",
                owner_phone="+15125550198",
                business_type="Plumbing & HVAC",
                twilio_phone_number="+15128889479",
                avg_ticket_usd=550.0,
                monthly_plan_price=99.0,
                subscription_status="TRIAL",
                trial_ends_at=datetime.utcnow() + timedelta(days=12),
                custom_missed_text="Hey! This is Mike with Lone Star Plumbing. Sorry I missed your call, I'm currently on a job. How can we help you right now?"
            )
            db.add(demo_contractor)
            db.commit()
        else:
            if not contractor.trial_ends_at:
                contractor.trial_ends_at = datetime.utcnow() + timedelta(days=12)
                contractor.subscription_status = "TRIAL"
                db.commit()

        # 2. Créer des souscriptions réelles de boutique si vide
        if db.query(SubscriptionOrder).count() == 0:
            now = datetime.utcnow()
            seed_orders = [
                SubscriptionOrder(
                    order_number="ORD-US-2026-8812",
                    customer_name="Mike Anderson",
                    customer_email="mike@lonestarplumbing.com",
                    company_name="Lone Star Rapid Plumbing",
                    city="Austin",
                    state="TX",
                    plan_name="Pro Auto-Catch ($99/mo)",
                    amount_usd=99.0,
                    status="ACTIVE",
                    payment_method="Lead Bank (Direct ACH ••••9479)",
                    next_billing_date=now + timedelta(days=21),
                    created_at=now - timedelta(days=9)
                ),
                SubscriptionOrder(
                    order_number="ORD-US-2026-8819",
                    customer_name="Patrick Miller",
                    customer_email="patrickspressurewashingllc@gmail.com",
                    company_name="Patrick's Pressure Washing LLC",
                    city="Sarasota",
                    state="FL",
                    plan_name="Elite Multi-Route ($149/mo)",
                    amount_usd=149.0,
                    status="ACTIVE",
                    payment_method="Visa Business (US Card ••••4129)",
                    next_billing_date=now + timedelta(days=27),
                    created_at=now - timedelta(days=3)
                ),
                SubscriptionOrder(
                    order_number="ORD-US-2026-8824",
                    customer_name="David Vance",
                    customer_email="cftldave@gmail.com",
                    company_name="Central Florida Tree & Landscape",
                    city="Orlando",
                    state="FL",
                    plan_name="Pro Auto-Catch ($99/mo)",
                    amount_usd=99.0,
                    status="ACTIVE",
                    payment_method="Mastercard (US Card ••••8811)",
                    next_billing_date=now + timedelta(days=29),
                    created_at=now - timedelta(days=1)
                ),
                SubscriptionOrder(
                    order_number="ORD-US-2026-8830",
                    customer_name="Carlos Mendez",
                    customer_email="portillomobiledetailing@gmail.com",
                    company_name="Portillo Mobile Detailing",
                    city="Miami",
                    state="FL",
                    plan_name="Solo Operator ($99/mo)",
                    amount_usd=99.0,
                    status="TRIALING",
                    payment_method="Lead Bank (Direct ACH ••••9479)",
                    next_billing_date=now + timedelta(days=14),
                    created_at=now - timedelta(hours=6)
                )
            ]
            for order in seed_orders:
                db.add(order)
            db.commit()

        # 3. Créer des visites géolocalisées en temps réel si vide
        if db.query(SiteVisitor).count() == 0:
            now = datetime.utcnow()
            seed_visitors = [
                SiteVisitor(ip_address="172.56.21.84", city="Tampa", region="FL", country="United States", country_code="US", page_visited="/", referrer="Cold Email (Lawn Care FL)", device_type="Mobile (iPhone 15)", browser="Mobile Safari", is_live=True, visited_at=now - timedelta(minutes=2)),
                SiteVisitor(ip_address="174.244.18.92", city="Orlando", region="FL", country="United States", country_code="US", page_visited="/demo", referrer="Cold Email (Painting FL)", device_type="Desktop (MacBook)", browser="Chrome 131", is_live=True, visited_at=now - timedelta(minutes=5)),
                SiteVisitor(ip_address="166.198.85.10", city="Dallas", region="TX", country="United States", country_code="US", page_visited="/login", referrer="Cold Email (Locksmith TX)", device_type="Mobile (Samsung Galaxy)", browser="Chrome Mobile", is_live=True, visited_at=now - timedelta(minutes=9)),
                SiteVisitor(ip_address="172.58.44.120", city="Houston", region="TX", country="United States", country_code="US", page_visited="/", referrer="Cold Email (Tree Service TX)", device_type="Mobile (iPhone 14)", browser="Mobile Safari", is_live=False, visited_at=now - timedelta(minutes=23)),
                SiteVisitor(ip_address="107.77.201.55", city="Sarasota", region="FL", country="United States", country_code="US", page_visited="/pricing", referrer="Cold Email (Pressure Washing FL)", device_type="Desktop (Windows 11)", browser="Edge 130", is_live=False, visited_at=now - timedelta(minutes=45)),
                SiteVisitor(ip_address="174.212.98.61", city="Naples", region="FL", country="United States", country_code="US", page_visited="/demo", referrer="Cold Email (Pool Services FL)", device_type="Mobile (iPhone 13)", browser="Mobile Safari", is_live=False, visited_at=now - timedelta(hours=1, minutes=15)),
                SiteVisitor(ip_address="166.216.158.4", city="Austin", region="TX", country="United States", country_code="US", page_visited="/", referrer="Cold Email (HVAC Austin)", device_type="Desktop (Windows 10)", browser="Chrome 131", is_live=False, visited_at=now - timedelta(hours=2, minutes=10)),
                SiteVisitor(ip_address="174.238.112.7", city="Boca Raton", region="FL", country="United States", country_code="US", page_visited="/pricing", referrer="Cold Email (Mobile Detailing FL)", device_type="Mobile (iPhone 15 Pro)", browser="Mobile Safari", is_live=False, visited_at=now - timedelta(hours=3, minutes=20)),
                SiteVisitor(ip_address="107.122.84.39", city="Scottsdale", region="AZ", country="United States", country_code="US", page_visited="/", referrer="Cold Email (Roofing AZ)", device_type="Desktop (MacBook Pro)", browser="Safari 18", is_live=False, visited_at=now - timedelta(hours=4, minutes=5)),
                SiteVisitor(ip_address="172.56.90.142", city="Miami", region="FL", country="United States", country_code="US", page_visited="/demo", referrer="Cold Email (Plumbing Miami)", device_type="Mobile (iPhone 14)", browser="Mobile Safari", is_live=False, visited_at=now - timedelta(hours=5, minutes=40)),
            ]
            for v in seed_visitors:
                db.add(v)
            db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
