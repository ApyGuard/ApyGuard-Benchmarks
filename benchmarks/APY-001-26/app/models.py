from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    orders = relationship("Order", back_populates="user")


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    item = Column(String, nullable=False)
    status = Column(String, nullable=False)
    total_cents = Column(Integer, nullable=False)
    internal_note = Column(String, nullable=False, default="")
    is_priority = Column(Boolean, nullable=False, default=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="orders")
