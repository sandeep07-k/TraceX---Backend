from pymongo import MongoClient
from app.config.settings import settings


client = MongoClient(
    settings.mongodb_uri
)

database = client[
    settings.database_name
]


def get_database():
    return database


def check_database_connection() -> bool:
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False