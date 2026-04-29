from sqlalchemy import Column, Integer, String, Text

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    role = Column(String, nullable=False, default="member")
    plan = Column(String, nullable=False, default="starter")
    workspace_slug = Column(String, nullable=False, default="blue")


class Announcement(Base):
    __tablename__ = "announcements"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    body = Column(Text, nullable=False)
