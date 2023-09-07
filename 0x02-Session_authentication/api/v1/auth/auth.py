#!/usr/bin/env python3
""" Auth module
"""
from flask import request
from typing import List, TypeVar
import os


class Auth():
    """
    Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require_auth function
        """
        if excluded_paths is None or excluded_paths == '':
            return True
        if path is not None:
            if path[len(path) - 1] is not '/':
                path += '/'
        if path is None:
            return True
        for item in excluded_paths:
            asterisk = item.find("*")
            if asterisk != -1 and len(path) >= len(item):
                pathcpy = path[: asterisk]
                if pathcpy == item[: asterisk]:
                    return False
            elif path == item:
                return False
        return True
        # if path is None or path not in excluded_paths:
        # return True
        # return False

    def authorization_header(self, request=None) -> str:
        """
        authorization_header function
        """
        if request is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        current_user function
        """
        return None

    def session_cookie(self, request=None):
        """
        session_cookie function
        """
        if request is None:
            return None
        name_var = os.getenv('SESSION_NAME')
        return request.cookies.get(name_var)
