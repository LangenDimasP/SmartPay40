from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin(username, password):
    with app.app_context():
        # Cek apakah username sudah ada
        if User.query.filter_by(username=username).first():
            print(f"Username '{username}' sudah digunakan!")
            return False
        
        # Buat user admin baru
        admin = User(
            username=username,
            password_hash=generate_password_hash(password),
            role='admin',
            is_active=True
        )
        
        try:
            db.session.add(admin)
            db.session.commit()
            print(f"Admin '{username}' berhasil dibuat!")
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Gagal membuat admin: {e}")
            return False

if __name__ == '__main__':
    username = input("Masukkan username admin baru: ")
    password = input("Masukkan password: ")
    create_admin(username, password)