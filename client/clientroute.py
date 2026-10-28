from fastapi import APIRouter, Depends
from auth.authroute import requirerole

router = APIRouter(prefix="/client", tags=["Client Portal"], dependencies=[Depends(requiredrole("admin"))])