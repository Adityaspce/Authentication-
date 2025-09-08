# backend/main.py
from fastapi import FastAPI
from app.routes import certificates, issuers, cert_route

app = FastAPI(title="Certificate Verification Backend")

# Register routes
app.include_router(certificates.router, prefix="/certificates", tags=["Certificates"])
app.include_router(issuers.router, prefix="/issuers", tags=["Issuers"])
app.include_router(cert_route.router, prefix="/api", tags=["Certificate Processing"])

@app.get("/")
def root():
    return {"message": "Backend running successfully!"}
