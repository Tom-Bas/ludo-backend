from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database import SessionLocal
from models import User

router = APIRouter(prefix="/ranking", tags=["Ranking"])

@router.get("/")
def get_ranking():
    db = SessionLocal()
    users = db.query(User).order_by(User.points.desc()).limit(10).all()
    return [{"username": u.username, "points": u.points, "wins": u.wins} for u in users]

class ScoreIn(BaseModel):
    username: str
    points: int = 100

@router.post("/add_points")
def add_points(data: ScoreIn):
    db = SessionLocal()
    user = db.query(User).filter_by(username=data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    user.points += data.points
    user.wins += 1
    db.commit()
    return {"ok": True, "msg": "Puntos sumados"}
