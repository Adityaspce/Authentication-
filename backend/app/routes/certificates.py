from fastapi import APIRouter, UploadFile
from app.services import ipfs_service

router = APIRouter()

@router.post("/upload")
async def upload_certificate(file: UploadFile):
    cid = await ipfs_service.upload_file(file)
    return {"cid": cid, "message": "Certificate uploaded to IPFS"}

@router.get("/fetch/{cid}")
async def fetch_certificate(cid: str):
    file_data = await ipfs_service.get_file(cid)
    return {"cid": cid, "size": len(file_data)}
