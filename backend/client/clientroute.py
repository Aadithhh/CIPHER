from fastapi import APIRouter, Depends
from auth.authroute import requiredrole

router = APIRouter(prefix="/client", tags=["Client Portal"], dependencies=[Depends(requiredrole("admin"))])