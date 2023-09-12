#!/usr/bin/env python3
"""
Module auth
"""
import bcrypt
import uuid
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> str:
    """
        Hash a password
        Return the encrypted  password
    """
    return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
        Generate a new UUID
        Return the UUID generated
    """
    return str(uuid.uuid4())


class Auth:
    """
        Auth class
        create model to manage the Authentication
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
            Register a user with email and pass
            Return the User registered
        """
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            pass
        password = _hash_password(password)
        user = self._db.add_user(email=email, hashed_password=password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """
            Valid login with email and password
            Return true or false
        """
        try:
            user = self._db.find_user_by(email=email)
            password = bytes(password, 'utf-8')
            return bcrypt.checkpw(password, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
            Create a session id
            Return the session id created
        """
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=str(uuid.uuid4()))
            return user.session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> str:
        """
            Find user by session id
            Return session id
        """
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user
            except NoResultFound:
                pass
        return None

    def destroy_session(self, user_id: int) -> None:
        """
            Destroy a session active
            Return None
        """
        if user_id:
            self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
            Generate token to reset password
            Return token
        """
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, reset_token=str(uuid.uuid4()))
            return user.reset_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """
            Reset password
            Return None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=password)
            self._db.update_user(user.id, reset_token=None)
            return None
        except NoResultFound:
            raise ValueError
