from datetime import datetime, timezone

from app.database.collections import (
    get_analysis_collection,
    get_cases_collection,
)


def generate_case_id() -> str:
    collection = get_cases_collection()

    year = datetime.now(
        timezone.utc
    ).year

    count = collection.count_documents(
        {
            "case_id": {
                "$regex": f"^TX-{year}-"
            }
        }
    )

    return (
        f"TX-{year}-{count + 1:04d}"
    )


def create_case(
    title: str = "Email Investigation",
) -> dict:

    now = datetime.now(
        timezone.utc
    )

    case = {
        "case_id": generate_case_id(),
        "title": title,
        "status": "OPEN",
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "created_at": now,
        "updated_at": now,
    }

    get_cases_collection().insert_one(
        case
    )

    return case


def save_analysis(
    case_id: str,
    analysis: dict,
) -> None:

    now = datetime.now(
        timezone.utc
    )

    get_analysis_collection().update_one(
        {
            "case_id": case_id
        },
        {
            "$set": {
                "case_id": case_id,
                "analysis": analysis,
                "updated_at": now,
            }
        },
        upsert=True,
    )

    risk = analysis.get(
        "risk",
        {}
    )

    get_cases_collection().update_one(
        {
            "case_id": case_id
        },
        {
            "$set": {
                "risk_score": risk.get(
                    "score",
                    0,
                ),
                "risk_level": risk.get(
                    "level",
                    "UNKNOWN",
                ),
                "updated_at": now,
            }
        },
    )


def get_case(
    case_id: str,
) -> dict | None:

    case = get_cases_collection().find_one(
        {
            "case_id": case_id
        },
        {
            "_id": 0
        },
    )

    if not case:
        return None

    analysis = (
        get_analysis_collection().find_one(
            {
                "case_id": case_id
            },
            {
                "_id": 0
            },
        )
    )

    result = case.copy()

    result["analysis"] = (
        analysis.get(
            "analysis",
            {}
        )
        if analysis
        else {}
    )

    return result


def list_cases(
    limit: int = 20,
) -> list[dict]:

    cursor = (
        get_cases_collection()
        .find(
            {},
            {
                "_id": 0
            },
        )
        .sort(
            "created_at",
            -1,
        )
        .limit(limit)
    )

    return list(cursor)