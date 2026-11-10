import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8050))
    print("\n=======================================================")
    print(f"🚀 Démarrage de CallCatch AI (SaaS Marché USA) sur le port {port}...")
    print(f"📍 URL du Dashboard : http://localhost:{port}/dashboard")
    print("=======================================================\n")
    uvicorn.run("callcatch_ai.main:app", host="0.0.0.0", port=port, reload=False)

