import os

import psycopg
from dotenv import load_dotenv


load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")


if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not configured in .env"
    )


def get_db_connection():

    try:

        connection = psycopg.connect(
            DATABASE_URL
        )

        return connection

    except Exception as e:

        raise RuntimeError(
            f"PostgreSQL connection failed: {e}"
        )