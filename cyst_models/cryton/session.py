from typing import Optional
from netaddr import IPAddress

from cyst.api.network.session import Session


class MetasploitSession(Session):
    def __init__(self, owner: str, session_id: int, parent: Optional["MetasploitSession"] = None):
        self._owner = owner
        self._id = session_id
        self._parent = parent

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def id(self) -> str:
        return str(self._id)

    @property
    def parent(self) -> Optional[Session]:
        return self._parent

    @property
    def path(self) -> list[tuple[Optional[IPAddress], Optional[IPAddress]]]:
        return []

    @property
    def end(self) -> tuple[IPAddress, str]:
        return None

    @property
    def start(self) -> tuple[IPAddress, str]:
        return None

    @property
    def enabled(self) -> bool:
        return True
