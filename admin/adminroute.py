from fastapi import APIRouter, Depends
from auth.authroute import require_role

router = APIRouter(prefix="/admin", tags=["Admin Portal"])