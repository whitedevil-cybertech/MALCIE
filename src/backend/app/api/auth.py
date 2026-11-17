from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    AuthenticatedUser,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.db import get_db
from app.models import User
from app.schemas import AuthResponse, UserLogin, UserRead, UserRegister

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, db: Session = Depends(get_db)) -> AuthResponse:
    email = payload.email.strip().lower()
    if not email or len(payload.password) < 10:
        raise HTTPException(
            status_code=400, detail="A valid email and 10-character password are required"
        )
    if payload.role not in {"viewer", "analyst"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="User already exists")
    user = User(email=email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return AuthResponse(access_token=create_access_token(user), user=user)


@router.post("/login", response_model=AuthResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> AuthResponse:
    user = db.scalar(select(User).where(User.email == payload.email.strip().lower()))
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return AuthResponse(access_token=create_access_token(user), user=user)


@router.get("/me", response_model=UserRead)
def current_user(
    user: AuthenticatedUser | None = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    if user is None or user.id is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    result = db.get(User, user.id)
    if result is None:
        raise HTTPException(status_code=401, detail="User not found")
    return result
