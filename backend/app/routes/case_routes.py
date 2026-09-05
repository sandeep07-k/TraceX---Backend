from fastapi import APIRouter, HTTPException, Query

from app.schemas.case_schema import (
    CaseCreate,
    CaseDetail,
    CaseResponse,
)

from app.services.case.case_service import (
    create_case,
    get_case,
    list_cases,
)


router = APIRouter(
    prefix="/cases"
)


@router.post(
    "",
    response_model=CaseResponse,
)
def create_new_case(
    payload: CaseCreate,
):

    return create_case(
        payload.title
    )


@router.get(
    "",
)
def get_all_cases(
    limit: int = Query(
        20,
        ge=1,
        le=100,
    )
):

    return list_cases(
        limit
    )


@router.get(
    "/{case_id}",
    response_model=CaseDetail,
)
def get_single_case(
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

    return case