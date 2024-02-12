from .cryton_action import CrytonAction
from cyst.api.logic.metadata import Metadata


class FindServices(CrytonAction):
    def __init__(self, message_id: int, metadata: Metadata, target: str, ports: str):
        super().__init__(message_id, metadata)

        self._template = {
            "name": f"find-services-{message_id}",
            "step_type": "worker/execute",
            "is_init": True,
            "arguments": {
                "module": "mod_msf",
                "module_arguments": {
                    "module_type": "auxiliary",
                    "module": "scanner/portscan/tcp",
                    "module_options": {
                        "PORTS": ports,
                        "RHOSTS": target,
                        "THREADS": 10
                    }
                }
            }
        }
