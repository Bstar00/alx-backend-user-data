#!/usr/bin/env python3
"""
Module user
Table users with SQLAlchemy
"""
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()


class User(Base):
    """
        User class
        create a model User from sqlalchemy for a table name users
    """

    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250))
    reset_token = Column(String(250))
