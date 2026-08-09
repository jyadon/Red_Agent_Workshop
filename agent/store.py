from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from agent.schemas import ThreadContext


ThreadKind = Literal[
    "verification", "command_approval", "rto"
]
ThreadStatus = Literal["idle", "running", "waiting_human", "completed", "failed"]


@dataclass
class ThreadState:
    thread_id: str
    kind: ThreadKind = "verification"
    title: str | None = None
    status: ThreadStatus = "idle"
    context: ThreadContext = field(default_factory=ThreadContext)
    interrupt: dict[str, Any] | None = None
    final_output: Any | None = None
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    event_seq: int = 0
    # False: auto-approve and resume tool-call interrupts server-side.
    # True: surface the interrupt to the UI and wait for user approval.
    require_approval: bool = False
    # Per-thread async lock serializing multi-field updates
    # (status + interrupt + final_output transitioned together); lazily initialized.
    _lock: asyncio.Lock | None = None

    @property
    def lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock


# Guards concurrent access to the THREADS dict itself. A threading.Lock is used
# because get_or_create_thread / append_event are called from synchronous code.
_THREADS_LOCK = threading.Lock()

THREADS: dict[str, ThreadState] = {}


def get_or_create_thread(thread_id: str, kind: ThreadKind = "verification") -> ThreadState:
    with _THREADS_LOCK:
        if thread_id not in THREADS:
            THREADS[thread_id] = ThreadState(thread_id=thread_id, kind=kind)
        return THREADS[thread_id]


def append_event(thread_id: str, event: dict[str, Any]) -> None:
    # Take the lock once so fetch + sequence numbering + append happen in a single
    # critical section (do not acquire another lock inside it).
    with _THREADS_LOCK:
        thread = THREADS.get(thread_id)
        if thread is None:
            thread = ThreadState(thread_id=thread_id)
            THREADS[thread_id] = thread
        thread.event_seq += 1
        event["seq"] = thread.event_seq
        thread.events.append(event)