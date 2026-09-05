from app.database.connection import get_database


def get_cases_collection():
    return get_database()["cases"]


def get_analysis_collection():
    return get_database()["analyses"]