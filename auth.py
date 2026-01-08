from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database import SessionLocal
from models import User
from sqlalchemy.orm import Session
import hashlib

router = APIRouter(prefix="/auth", tags=["Auth"])

class UserIn(BaseModel):
    username: str
    password: str

def hash_pw(pw: str):
    return hashlib.sha256(pw.encode()).hexdigest()

@router.post("/register")
def register(data: UserIn):
    db: Session = SessionLocal()
    if db.query(User).filter_by(username=data.username).first():
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    user = User(username=data.username, password=hash_pw(data.password))
    db.add(user)
    db.commit()
    return {"ok": True, "msg": "Usuario registrado correctamente"}

@router.post("/login")
def login(data: UserIn):
    db: Session = SessionLocal()
    user = db.query(User).filter_by(username=data.username).first()
    if not user or user.password != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"ok": True, "msg": "Login exitoso", "user": user.username}
