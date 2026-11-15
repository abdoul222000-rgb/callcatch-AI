import logging
import httpx
from ..config import settings

logger = logging.getLogger("callcatch.ai")

SYSTEM_PROMPT = """
You are an expert AI receptionist for a professional trade contractor (plumbing, roofing, HVAC, or electrical) operating in the US, Belgium (Belgique), or Switzerland (Suisse).
Your goal is to save missed phone calls by chatting via SMS with the customer who just called.

Rules:
1. Detect and reply in the EXACT same language as the customer:
   - If customer writes in French (Belgium, Switzerland, France), reply in natural, polite European French.
   - If customer writes in English (US), reply in clean, concise American English.
2. Be friendly, concise, and professional (it's SMS, keep it under 140 words).
3. Acknowledge what they need help with.
4. If they haven't provided their location/address, politely ask for their address or zip code / commune.
5. If it's an emergency (active water flood, gas smell, heating failure in winter, sparks), flag urgency as HIGH and assure them we are alerting the technician.
6. Offer to schedule an inspection or dispatch a technician today.
"""

def detect_language(text: str, country: str = "US") -> str:
    """Détecte si le message ou l'artisan est francophone (Belgique, Suisse, France)"""
    if country in ["BE", "CH", "FR"]:
        return "fr"
    french_signals = [
        "bonjour", "salut", "fuite", "panne", "urgent", "urgence", "eau", "chaudiere", 
        "radiateur", "electricite", "devis", "prix", "rue", "avenue", "bruxelles", 
        "geneve", "lausanne", "liege", "namur", "mons", "charleroi", "svp", "merci", "dispo"
    ]
    if any(sig in text.lower() for sig in french_signals):
        return "fr"
    return "en"

async def process_inbound_sms_with_ai(
    incoming_text: str, 
    conversation_history: list,
    contractor_name: str,
    business_name: str,
    business_type: str,
    contractor_country: str = "US"
) -> dict:
    """
    Analyse le SMS du client (US, Belgique, Suisse) et génère une réponse professionnelle ainsi qu'une qualification du lead.
    """
    lang = detect_language(incoming_text, country=contractor_country)

    # Si la clé OpenAI est fournie, utiliser GPT-4o-mini
    if settings.OPENAI_API_KEY:
        try:
            messages = [
                {
                    "role": "system", 
                    "content": f"{SYSTEM_PROMPT}\nBusiness: {business_name} ({business_type}). Owner: {contractor_name}. Market: {contractor_country}."
                }
            ]
            for msg in conversation_history[-6:]:
                role = "assistant" if msg["direction"] == "OUTBOUND" else "user"
                messages.append({"role": role, "content": msg["body"]})
            
            messages.append({"role": "user", "content": incoming_text})

            async with httpx.AsyncClient() as client:
                res = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={
                        "model": settings.AI_MODEL,
                        "messages": messages,
                        "temperature": 0.5,
                        "max_tokens": 200
                    },
                    timeout=15.0
                )
                if res.status_code == 200:
                    ai_reply = res.json()["choices"][0]["message"]["content"].strip()
                    high_urgency_words = ["leak", "burst", "urgent", "emergency", "flood", "now", "asap", "fuite", "panne", "inondation", "urgence", "bloque"]
                    urgency = "HIGH" if any(k in incoming_text.lower() for k in high_urgency_words) else "MEDIUM"
                    return {
                        "reply_text": ai_reply,
                        "urgency": urgency,
                        "job_summary": incoming_text[:100],
                        "address_detected": None
                    }
        except Exception as e:
            logger.error(f"Erreur API OpenAI : {e}, utilisation du moteur intelligent local.")

    # Moteur intelligent local de secours multilingue (Zéro coût, 100% fonctionnel)
    text_lower = incoming_text.lower()
    
    if lang == "fr":
        # Logique Francophone (Belgique & Suisse Romande)
        if any(k in text_lower for k in ["fuite", "inondation", "panne", "urgence", "urgent", "court-circuit", "chaudiere", "etincelle", "degat"]):
            urgency = "HIGH"
            reply = (
                f"Bien reçu ! C'est effectivement urgent. J'alerte immédiatement {contractor_name}. "
                f"Quelle est votre adresse exacte (commune et code postal) pour que nous vérifiions l'arrivée d'un technicien au plus vite ?"
            )
        elif any(k in text_lower for k in ["devis", "prix", "tarif", "cout", "combien", "estimation"]):
            urgency = "MEDIUM"
            reply = (
                f"Merci d'avoir contacté {business_name} ! Nous serions ravis de vous établir une estimation claire. "
                f"Pouvez-vous nous décrire brièvement les travaux à réaliser et votre localisation ?"
            )
        elif any(k in text_lower for k in ["rue", "avenue", "chaussee", "chemin", "boulevard", "bruxelles", "liege", "namur", "geneve", "lausanne", "mons", "charleroi", "neuchatel"]):
            urgency = "MEDIUM"
            reply = (
                f"Parfait, nous intervenons bien dans votre commune ! "
                f"Seriez-vous disponible aujourd'hui à partir de 14h30 ou demain matin pour un passage rapide ?"
            )
        else:
            urgency = "NORMAL"
            reply = (
                f"Merci pour votre message ! {contractor_name} en prend connaissance dès que possible. "
                f"Quel est le créneau idéal pour vous rappeler ou convenir d'une visite ?"
            )
    else:
        # Logique Anglophone (US & International)
        if any(k in text_lower for k in ["leak", "burst", "flood", "emergency", "sparks", "smoke", "asap", "broken"]):
            urgency = "HIGH"
            reply = (
                f"Got it! That sounds urgent. I'm alerting {contractor_name} right away. "
                f"What's your full street address or zip code so we can check technician availability in your area?"
            )
        elif any(k in text_lower for k in ["quote", "price", "estimate", "cost", "how much"]):
            urgency = "MEDIUM"
            reply = (
                f"Thanks for reaching out to {business_name}! We'd be happy to give you a clear estimate. "
                f"Could you briefly describe the job and what city/area you're located in?"
            )
        elif any(k in text_lower for k in ["st", "street", "ave", "avenue", "rd", "road", "blvd", "austin", "dallas", "houston", "miami"]):
            urgency = "MEDIUM"
            reply = (
                f"Thank you! We have technicians covering your area. "
                f"Would today after 2:00 PM or tomorrow morning work best for a quick on-site inspection?"
            )
        else:
            urgency = "NORMAL"
            reply = (
                f"Thanks for getting back to us! {contractor_name} is reviewing your message. "
                f"What is the best time today for us to call you back or come take a look?"
            )

    return {
        "reply_text": reply,
        "urgency": urgency,
        "job_summary": incoming_text[:120],
        "address_detected": None
    }
