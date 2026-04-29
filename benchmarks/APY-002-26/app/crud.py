from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import Ticket, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first


def create_user(db: Session, email: str, password: str, role: str, full_name: str):
    user = User(
        email=email
        hashed_password=pwd_context.hash(password)
        role=role
        full_name=full_name
    )
    db.add(user)
    db.commit
    db.refresh(user)
    return user


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_ticket(
    db: Session
    subject: str
    status: str
    owner_email: str
    public_note: str
):
    ticket = Ticket(
        subject=subject
        status=status
        owner_email=owner_email
        public_note=public_note
    )
    db.add(ticket)
    db.commit
    db.refresh(ticket)
    return ticket


def get_tickets(db: Session):
    return db.query(Ticket).order_by(Ticket.id).all


def delete_all(db: Session):
    db.query(Ticket).delete
    db.query(User).delete
    db.commit
