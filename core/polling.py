import time
from typing import Callable, Any, Optional


def poll_until(
    fetch_fn: Callable[[], Any],
    is_done_fn: Callable[[Any], bool],
    timeout_seconds: int = 30,
    interval_seconds: int = 2,
    on_tick: Optional[Callable[[Any], None]] = None,
) -> dict:
    start = time.time()
    last_data = None

    while time.time() - start < timeout_seconds:
        data = fetch_fn()
        last_data = data

        if on_tick:
            try:
                on_tick(data)
            except Exception:
                pass

        if is_done_fn(data):
            return {
                "ok": True,
                "data": data,
            }

        time.sleep(interval_seconds)

    return {
        "ok": False,
        "error": "timeout",
        "last_data": last_data,
    }