from fastapi import APIRouter, HTTPException

from app.schemas.report_schema import ReportResponse
from app.services.case.case_service import get_case
from app.services.report.report_generator import (
    generate_report,
)


router = APIRouter(
    prefix="/reports"
)


@router.post(
    "/{case_id}",
    response_model=ReportResponse,
)
def create_report(
    case_id: str,
):

    case = get_case(
        case_id
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    filename = (
        case.get("analysis", {})
        .get("source_filename")
        or "email.eml"
    )

    try:

        report_path = generate_report(
            case_id=case_id,
            analysis=case.get(
                "analysis",
                {},
            ),
            filename=filename,
        )

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Report generation failed: {exc}"
            ),
        ) from exc

    return {
        "success": True,
        "case_id": case_id,
        "filename": filename,
        "report_path": report_path,
        "message": "Forensic report generated successfully.",
    }