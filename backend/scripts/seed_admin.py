"""Creates the ONE admin account for this project.

    python backend/scripts/seed_admin.py

Reads ADMIN_SEED_USERNAME / ADMIN_SEED_PASSWORD from backend/.env (see
.env.example) -- never hardcode credentials into frontend source, and never
run this against a database whose admin you don't intend to (re)claim.

Idempotent: if the username already exists, this updates its password hash
and makes sure role='admin' rather than creating a second row -- there is
only ever supposed to be one admin account (Part 22 of the restructuring
brief this script was written for).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bcrypt

from app.core.config import settings
from app.db.repository import UserRepository
from app.db.session import SessionLocal


def main() -> None:
    username = settings.admin_seed_username
    password = settings.admin_seed_password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db = SessionLocal()
    try:
        repo = UserRepository(db)
        existing = repo.get_by_username(username)
        if existing is None:
            user = repo.create(username=username, password_hash=password_hash, role="admin")
            db.commit()
            print(f"Created admin account '{user.username}' (client_id={user.client_id}).")
        else:
            existing.password_hash = password_hash
            existing.role = "admin"
            db.commit()
            print(f"Admin account '{existing.username}' already existed; "
                 f"password/role refreshed.")

        print(f"Login at /login with username='{username}' and the password "
             f"from ADMIN_SEED_PASSWORD in backend/.env.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
