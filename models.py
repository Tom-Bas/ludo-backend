from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_verified = Column(Integer, default=0)  # 0: No, 1: Yes (SQLite handles Booleans as Integers usually)
    verification_token = Column(String(100), nullable=True)
    scores = relationship("Score", back_populates="user", cascade="all, delete")

class Score(Base):
    __tablename__ = "scores"
    id = Column(Integer, primary_key=True, index=True)
    puntos = Column(Integer, nullable=False)
    fecha = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="scores")

class Level(Base):
    __tablename__ = "levels"
    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(50), nullable=False)
    puntos_requeridos = Column(Integer, nullable=False)
