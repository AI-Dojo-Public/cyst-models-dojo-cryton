from .cryton_action import CrytonAction
from cyst.api.logic.metadata import Metadata


class UpdateRouting(CrytonAction):
    def __init__(self, message_id: int, metadata: Metadata, session_id: int):
        super().__init__(message_id, metadata)

        self._template = {
            "name": f"update-routing-table-{message_id}",
            "step_type": "worker/execute",
            "is_init": True,
            "arguments": {
                "module": "mod_msf",
                "module_arguments": {
                    "module_type": "post",
                    "module": "multi/manage/autoroute",
                    "module_options": {
                        "CMD": "autoadd",
                        "SESSION": session_id
                    }
                }
            }
        }
