from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import Order, User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def create_user(db: Session, email: str, password: str, full_name: str):
    db_user = User(
        email=email,
        hashed_password=pwd_context.hash(password),
        full_name=full_name,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_order(
    db: Session,
    user_id: int,
    item: str,
    status: str,
    total_cents: int,
    internal_note: str,
    is_priority: bool = False,
):
    order = Order(
        user_id=user_id,
        item=item,
        status=status,
        total_cents=total_cents,
        internal_note=internal_note,
        is_priority=is_priority,
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return order


def get_orders_for_user(db: Session, user_id: int):
    return db.query(Order).filter(Order.user_id == user_id).order_by(Order.id).all()


def get_order(db: Session, order_id: int):
    return db.query(Order).filter(Order.id == order_id).first()


def delete_all(db: Session):
    db.query(Order).delete()
    db.query(User).delete()
    db.commit()
