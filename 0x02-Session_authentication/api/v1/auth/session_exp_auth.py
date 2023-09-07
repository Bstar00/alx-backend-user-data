#!/usr/bin/env python3
""" Auth module
"""
from api.v1.auth.session_auth import SessionAuth
import os
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """
    SessionExpAuth class
    """

    def __init__(self):
        """
        constructor
        """
        try:
            self.session_duration = int(os.getenv("SESSION_DURATION"))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """
        create_session function
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        value = {
            "user_id": user_id,
            "created_at": datetime.now()
        }
        self.user_id_by_session_id[session_id] = value
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        user_id_for_session_id function
        """
        if session_id is None:
            return None
        if session_id not in self.user_id_by_session_id:
            return None
        session_dict = self.user_id_by_session_id[session_id]
        user_id = session_dict.get('user_id')
        if self.session_duration <= 0:
            return user_id
        if 'created_at' not in session_dict:
            return None
        create_at = session_dict.get('created_at')
        create_at += timedelta(0, self.session_duration)
        if create_at < datetime.now():
            return None
        return user_id
