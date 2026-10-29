from fastapi import APIRouter, Depends
from auth.authroute import requiredrole

router = APIRouter(prefix="/admin", tags=["Admin Portal"], dependencies=[Depends(requiredrole("admin"))])