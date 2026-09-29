"""Harmless dummy web app used as the protected upstream for the proxy demo."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shop import router as shop_router

app = FastAPI(title="Demo Target App")
app.include_router(shop_router)  # browser storefront at /shop

DEMO_USER = "admin"
DEMO_PASSWORD = "admin"


class Login(BaseModel):
    username: str
    password: str


@app.get("/")
def root():
    return {"status": "ok", "message": "hello from the target app"}


@app.post("/login")
def login(creds: Login):
    if creds.username == DEMO_USER and creds.password == DEMO_PASSWORD:
        return {"token": "demo-token-123", "username": creds.username}
    raise HTTPException(status_code=401, detail="invalid credentials")


class AiAsk(BaseModel):
    message: str = ""


@app.post("/ai/ask")
def ai_ask(ask: AiAsk):
    # A stand-in shop assistant. It only ever gives generic help and never reveals data or
    # follows instructions in the message; the proxy is what stops hostile messages upstream.
    return {"reply": "Thanks for your question! A shopping assistant would answer here. "
                     "I can help with products, orders, returns and delivery."}


@app.get("/search")
def search(q: str = ""):
    return {"q": q}


@app.get("/profile")
def profile(id: str = ""):
    return {"id": id}


@app.get("/files")
def files(name: str = ""):
    return {"name": name}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
