from app import db, User

def create_default_users():
    users = [
        {
            "username": "dimas1",
            "password": "password123",
            "role": "admin",
            "kelas": None,
            "jurusan": None
        },
        {
            "username": "dimas2",
            "password": "password123",
            "role": "siswa",
            "kelas": "X",
            "jurusan": "RPL"
        },
        {
            "username": "dimas3",
            "password": "password123",
            "role": "penjual",
            "kelas": None,
            "jurusan": None
        }
    ]

    for user_data in users:
        if not User.query.filter_by(username=user_data["username"]).first():
            user = User(
                username=user_data["username"],
                role=user_data["role"],
                kelas=user_data["kelas"],
                jurusan=user_data["jurusan"]
            )
            user.set_password(user_data["password"])
            db.session.add(user)
            print(f"User {user.username} ({user.role}) ditambahkan.")
        else:
            print(f"User {user_data['username']} sudah ada, dilewati.")

    db.session.commit()
    print("Proses selesai.")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        create_default_users()