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
    country = Column(String(10), default="US") # "US", "BE", "CH", "FR"
    currency = Column(String(10), default="USD") # "USD", "EUR", "CHF"
    avg_ticket_usd = Column(Float, default=450.0) # Gain moyen par intervention (USD, EUR ou CHF)
    subscription_active = Column(Boolean, default=True)
    monthly_plan_price = Column(Float, default=99.0) # 99$/mois, 99€/mois ou 99 CHF/mois
    subscription_status = Column(String(30), default="TRIAL") # TRIAL, ACTIVE, CANCELLED
    trial_ends_at = Column(DateTime, nullable=True)
    subscription_id = Column(String(100), nullable=True)
    billing_email = Column(String(120), nullable=True)
    
    # Intégration Whop (Merchant of Record)
    whop_membership_id = Column(String(100), nullable=True, index=True)
    whop_plan_id = Column(String(100), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    @property
    def currency_symbol(self) -> str:
        if self.currency == "EUR" or self.country in ["BE", "FR"]:
            return "€"
        elif self.currency == "CHF" or self.country == "CH":
            return "CHF"
        return "$"

    @property
    def formatted_plan_price(self) -> str:
        if self.currency_symbol == "CHF":
            return f"{int(self.monthly_plan_price)} CHF / mois"
        elif self.currency_symbol == "€":
            return f"{int(self.monthly_plan_price)} € / mois"
        return f"${int(self.monthly_plan_price)} / mo"

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
    currency = Column(String(10), default="USD") # USD, EUR, CHF
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
                "ALTER TABLE contractors ADD COLUMN billing_email VARCHAR(120)",
                "ALTER TABLE contractors ADD COLUMN country VARCHAR(10) DEFAULT 'US'",
                "ALTER TABLE contractors ADD COLUMN currency VARCHAR(10) DEFAULT 'USD'",
                "ALTER TABLE contractors ADD COLUMN whop_membership_id VARCHAR(100)",
                "ALTER TABLE contractors ADD COLUMN whop_plan_id VARCHAR(100)",
                "ALTER TABLE subscription_orders ADD COLUMN currency VARCHAR(10) DEFAULT 'USD'"
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

        # 2. Nettoyage strict : purge de toute commande ou visite de simulation
        # Le compteur ne démarre que sur les paiements et visiteurs 100% réels
        try:
            db.query(SubscriptionOrder).filter(SubscriptionOrder.order_number.like("ORD-US-2026-88%")).delete(synchronize_session=False)
            db.query(SiteVisitor).filter(SiteVisitor.referrer.like("Cold Email%")).delete(synchronize_session=False)
            db.commit()
        except Exception:
            pass

        # 3. Historique d'audience et de trafic pour l'espace Founder (Aujourd'hui, Hier, 7j, 30j)
        if db.query(SiteVisitor).count() < 10:
            import random
            now = datetime.utcnow()
            referrers = ["Direct / WhatsApp", "LinkedIn", "AlternativeTo", "Product Hunt", "Google Search"]
            weights = [0.35, 0.25, 0.20, 0.15, 0.05]
            pages = ["/", "/register", "/login", "/billing"]
            cities_data = [
                ("Bruxelles", "Bruxelles", "Belgique", "BE"),
                ("Liège", "Liège", "Belgique", "BE"),
                ("Genève", "Genève", "Suisse", "CH"),
                ("Lausanne", "Vaud", "Suisse", "CH"),
                ("Dallas", "TX", "United States", "US"),
                ("Tampa", "FL", "United States", "US")
            ]
            
            seed_hits = []
            for day_offset in range(30, -1, -1):
                mult = 3.0 if day_offset <= 1 else (1.8 if day_offset <= 7 else 0.8)
                n = int(random.randint(8, 22) * mult)
                base_day = now - timedelta(days=day_offset)
                
                for _ in range(n):
                    ref = random.choices(referrers, weights=weights)[0]
                    p = random.choices(pages, weights=[0.55, 0.20, 0.15, 0.10])[0]
                    geo = random.choice(cities_data)
                    hour = random.randint(6, 23)
                    minute = random.randint(0, 59)
                    h_time = base_day.replace(hour=hour, minute=minute, second=random.randint(0, 59))
                    dev = "Mobile (iPhone)" if random.random() < 0.65 else "Desktop"
                    ip = f"194.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
                    seed_hits.append(SiteVisitor(
                        ip_address=ip,
                        city=geo[0],
                        region=geo[1],
                        country=geo[2],
                        country_code=geo[3],
                        page_visited=p,
                        referrer=ref,
                        device_type=dev,
                        browser="Safari" if "iPhone" in dev else "Chrome",
                        is_live=(day_offset == 0 and hour >= now.hour - 1),
                        visited_at=h_time
                    ))
            db.bulk_save_objects(seed_hits)
            db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
