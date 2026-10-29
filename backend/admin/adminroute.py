from fastapi import APIRouter, Depends
from backend.auth.authroute import requiredrole

router = APIRouter(prefix="/admin", tags=["Admin Portal"], dependencies=[Depends(requiredrole("admin"))])