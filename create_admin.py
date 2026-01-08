from database import SessionLocal, init_db
from models import User
import getpass
from passlib.context import CryptContext

# Usamos el mismo contexto de hashing que la aplicación principal (main.py)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_admin():
    db = SessionLocal()

    print("=== CREAR USUARIO ADMINISTRADOR ===")

    username = input("Nombre de usuario (ej: master): ")
    password = getpass.getpass("Contraseña (mínimo 8 caracteres): ")

    if len(password) < 8:
        print("❌ La contraseña debe tener al menos 8 caracteres.")
        return

    # Hashear la contraseña con bcrypt, igual que en el registro normal
    hashed_pw = pwd_context.hash(password)

    # Crear usuario con el modelo correcto
    admin_user = User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=hashed_pw
    )

    db.add(admin_user)
    db.commit()
    db.close()

    print(f"✅ Usuario administrador '{username}' creado correctamente.")

if __name__ == "__main__":
    print("Inicializando la base de datos y creando tablas si no existen...")
    init_db()
    create_admin()
