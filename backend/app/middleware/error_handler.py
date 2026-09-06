import logging

from fastapi import Request
from fastapi.responses import JSONResponse


logger = logging.getLogger(
    "tracex"
)


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error.",
        },
    )