from fastapi import APIRouter, Depends
from backend.auth.authroute import requiredrole

router = APIRouter(prefix="/client", tags=["Client Portal"], dependencies=[Depends(requiredrole("admin"))])