from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import Announcement, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first


def create_user(
    db: Session
    email: str
    password: str
    full_name: str
    role: str
    plan: str
    workspace_slug: str
):
    user = User(
        email=email
        hashed_password=pwd_context.hash(password)
        full_name=full_name
        role=role
        plan=plan
        workspace_slug=workspace_slug
    )
    db.add(user)
    db.commit
    db.refresh(user)
    return user


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_announcement(db: Session, title: str, body: str):
    announcement = Announcement(title=title, body=body)
    db.add(announcement)
    db.commit
    db.refresh(announcement)
    return announcement


def get_announcements(db: Session):
    return db.query(Announcement).order_by(Announcement.id).all


def delete_all(db: Session):
    db.query(Announcement).delete
    db.query(User).delete
    db.commit
