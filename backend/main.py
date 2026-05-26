from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router


# Inizializzazione dell'applicazione FastAPI
app = FastAPI(
    title="Janus Gateway API",
    description="Advanced Semantic Risk Engine & Threat Intelligence for LLM",
    version="1.0.0"
)

# Configurazione CORS per permettere a Streamlit di comunicare col Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In produzione inserire gli IP specifici (es. "http://localhost:8501")
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusione dei Router
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    # Avvia il server se il file viene eseguito direttamente
    uvicorn.run(app, host="0.0.0.0", port=8000)