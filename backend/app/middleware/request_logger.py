import time
import logging

from fastapi import Request


logger = logging.getLogger(
    "tracex.requests"
)


async def request_logger(
    request: Request,
    call_next,
):

    start = time.perf_counter()

    response = await call_next(
        request
    )

    duration = (
        time.perf_counter()
        - start
    )

    logger.info(
        "%s %s -> %s (%.3fs)",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )

    return response