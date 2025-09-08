from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def get_issuers():
    return {"message": "Issuers endpoint working!"}
