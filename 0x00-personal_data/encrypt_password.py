#!/usr/bin/env python3
"""
Password Encryption and Validation using Bcrypt
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    password_bytes = bytes(password, 'utf-8')
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against its hashed version using bcrypt.

    Args:
        hashed_password (bytes): The hashed password
        to be checked against.
        password (str): The password to be validated.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    password_bytes = bytes(password, 'utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password)
