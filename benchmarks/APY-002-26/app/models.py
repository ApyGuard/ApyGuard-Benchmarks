from sqlalchemy import Column, Integer, String, Text

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    full_name = Column(String, nullable=False)


class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    subject = Column(String, nullable=False)
    status = Column(String, nullable=False)
    owner_email = Column(String, nullable=False)
    public_note = Column(Text, nullable=False)
