from .cryton_action import CrytonAction
from cyst.api.logic.metadata import Metadata


class ExfiltrateData(CrytonAction):
    def __init__(self, message_id: int, metadata: Metadata, session: int, file: str):
        super().__init__(message_id, metadata)

        self._template = {
            "name": f"find-data-{message_id}",
            "step_type": "worker/execute",
            "is_init": True,
            "arguments": {
                "module": "mod_cmd",
                "module_arguments": {
                    "session_id": session,
                    "cmd": f"cat {file}"
                }
            }
        }
