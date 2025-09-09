# api/addons/pagination.py
from __future__ import annotations
from math import ceil

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

def get_pagination_params(qs_params, default_page: int = DEFAULT_PAGE,
                          default_page_size: int = DEFAULT_PAGE_SIZE,
                          max_page_size: int = MAX_PAGE_SIZE) -> tuple[int, int]:
    def to_int(val, default):
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    page = max(1, to_int(qs_params.get("page"), default_page))
    page_size = to_int(qs_params.get("page_size"), default_page_size)
    if page_size <= 0:
        page_size = default_page_size
    if page_size > max_page_size:
        page_size = max_page_size
    return page, page_size


def paginate_queryset(qs, page: int, page_size: int):
    total = qs.count()
    total_pages = ceil(total / page_size) if page_size else 1
    if total_pages == 0:
        total_pages = 1

    offset = (page - 1) * page_size
    items = qs[offset: offset + page_size]

    meta = {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }
    return items, meta
