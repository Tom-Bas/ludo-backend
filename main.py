from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import SessionLocal, init_db, engine
from models import User, Score, Level, Base
from passlib.context import CryptContext
from typing import Optional, Annotated, List
from jose import jwt
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
from typing import Dict
import uuid

# --- Gestor de Conexiones Online (WebSockets) ---
class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[str, Dict[str, WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room_code: str, username: str):
        await websocket.accept()
        if room_code not in self.rooms:
            self.rooms[room_code] = {}
        self.rooms[room_code][username] = websocket

    def disconnect(self, room_code: str, username: str):
        if room_code in self.rooms:
            if username in self.rooms[room_code]:
                del self.rooms[room_code][username]
            if not self.rooms[room_code]:
                del self.rooms[room_code]

    async def broadcast(self, room_code: str, message: dict):
        if room_code in self.rooms:
            for connection in self.rooms[room_code].values():
                await connection.send_json(message)

manager = ConnectionManager()

# --- Configuración de JWT ---
SECRET_KEY = "Admin123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Inicialización de Base de Datos ---
Base.metadata.create_all(bind=engine)

app = FastAPI(title="LUDO Game Backend", version="1.0.0")

# --- Configuración de CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- OAuth2 Scheme ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/users/token")

# --- Modelos Pydantic ---
class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ScoreCreate(BaseModel):
    puntos: int

class ScoreResponse(BaseModel):
    id: int
    puntos: int
    fecha: datetime
    username: str

class LevelCreate(BaseModel):
    nombre: str
    puntos_requeridos: int

class LevelResponse(BaseModel):
    id: int
    nombre: str
    puntos_requeridos: int


# --- Dependencias de Base de Datos ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Reset DB (Debug) ---
@app.get("/api/v1/debug/reset-all-data")
def nuke_database():
    """PELIGRO: Borra toda la base de datos y la recrea."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return {"message": "♻️ Base de datos reiniciada. Todos los usuarios eliminados."}


# --- Evento de Inicio ---
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)


# --- JWT ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Obtener Usuario Actual ---
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

CurrentUser = Annotated[User, Depends(get_current_user)]


# --- Registro de Usuarios ---
@app.post("/api/v1/users/register", status_code=201)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está en uso")

    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="El email ya está registrado")

    if len(user_data.password) < 8:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 8 caracteres")

    hashed = pwd_context.hash(user_data.password)
    token = str(uuid.uuid4())
    
    user = User(
        username=user_data.username, 
        email=user_data.email, 
        hashed_password=hashed,
        is_verified=0,
        verification_token=token
    )
    db.add(user)
    db.commit()

    # Simulamos el envío de email imprimiendo en consola
    verify_link = f"https://ludo-backend-oq9o.onrender.com/api/v1/users/verify/{token}"
    print("\n" + "="*50)
    print(f"📧 EMAIL DE VERIFICACIÓN PARA: {user_data.email}")
    print(f"🔗 ENLACE: {verify_link}")
    print("="*50 + "\n")

    return {"success": True, "message": "Usuario registrado. Por favor verifica tu email."}


# --- Verificar Email ---
@app.get("/api/v1/users/verify/{token}")
async def verify_user(token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=404, detail="Token de verificación inválido")
    
    user.is_verified = 1
    user.verification_token = None
    db.commit()
    
    return {
        "success": True, 
        "message": "¡Email verificado con éxito! Ya puedes iniciar sesión en la app."
    }


# --- Login y Token ---
@app.post("/api/v1/users/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Iniciar sesión y devolver un token JWT."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.is_verified == 0:
        raise HTTPException(
            status_code=403,
            detail="Tu cuenta aún no ha sido verificada por email."
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}


# --- WebSocket para Juego Online (Modo Amigos) ---
@app.websocket("/ws/ludo/{room_code}/{username}")
async def ludo_websocket(websocket: WebSocket, room_code: str, username: str):
    await manager.connect(websocket, room_code, username)
    try:
        # Notificar a todos en la sala que alguien se unió
        await manager.broadcast(room_code, {
            "type": "USER_JOINED",
            "username": username,
            "players": list(manager.rooms[room_code].keys())
        })

        while True:
            # Recibir eventos de juego (tiros de dados, movimientos, etc)
            data = await websocket.receive_json()
            # Reenviar a todos los de la sala (incluyendo quién lo envió para sincronía)
            await manager.broadcast(room_code, data)
            
    except WebSocketDisconnect:
        manager.disconnect(room_code, username)
        await manager.broadcast(room_code, {
            "type": "USER_LEFT",
            "username": username,
            "players": list(manager.rooms[room_code].keys()) if room_code in manager.rooms else []
        })


# --- Puntajes ---
@app.post("/api/v1/scores/", response_model=ScoreResponse, status_code=201)
async def create_score_for_user(
    score_data: ScoreCreate,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    db_score = Score(puntos=score_data.puntos, user_id=current_user.id)
    db.add(db_score)
    db.commit()
    db.refresh(db_score)
    return ScoreResponse(
        id=db_score.id,
        puntos=db_score.puntos,
        fecha=db_score.fecha,
        username=current_user.username
    )


# --- Niveles ---
@app.get("/api/v1/levels/", response_model=List[LevelResponse])
async def get_levels(db: Session = Depends(get_db)):
    levels = db.query(Level).all()
    return levels


@app.post("/api/v1/levels/", response_model=LevelResponse, status_code=201)
async def create_level(level_data: LevelCreate, db: Session = Depends(get_db)):
    db_level = Level(nombre=level_data.nombre, puntos_requeridos=level_data.puntos_requeridos)
    db.add(db_level)
    db.commit()
    db.refresh(db_level)
    return db_level


# --- Raíz ---
@app.get("/")
def root():
    return {"message": "LUDO Game Backend API", "version": "1.0.0"}
