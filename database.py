from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Datos de conexión a SQLite (Por defecto para desarrollo)
SQLALCHEMY_DATABASE_URL = "sqlite:///./ludo.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    pass # La creación de tablas ahora se maneja en el startup de main.py
