#!/usr/bin/env python3
"""
Regex-ing - A script for redacting sensitive information from logs.
"""
import re
import os
import logging
import mysql.connector
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """
    Custom log formatter to redact sensitive information.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter.
        :param fields: List of sensitive fields to be redacted.
        """
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """
        Custom format function to redact sensitive information.
        """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Redact sensitive information from the message.
    :param fields: List of sensitive fields to be redacted.
    :param redaction: String to use for redacted content.
    :param message: Original log message.
    :param separator: Separator used between fields in the log message.
    :return: Redacted log message.
    """
    for field in fields:
        message = re.sub(fr'{field}=.+?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """
    Create and configure a logger.
    :return: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    c_handler = logging.StreamHandler()
    c_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(c_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a connection to the database.
    :return: Database connection instance.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD")
    host = os.getenv("PERSONAL_DATA_DB_HOST")
    database = os.getenv("PERSONAL_DATA_DB_NAME")
    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )


def main():
    """
    Main function to retrieve sensitive data from the database and log it.
    """
    conn = get_db()
    users = conn.cursor()
    users.execute("SELECT CONCAT('name=', name, ';ssn=', ssn, ';ip=', ip, \
        ';user_agent', user_agent, ';') AS message FROM users;")
    logger = get_logger()

    for user in users:
        logger.log(logging.INFO, user[0])


if __name__ == "__main__":
    main()
