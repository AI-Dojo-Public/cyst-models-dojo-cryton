from cyst.api.logic.metadata import Metadata
from cyst_models.cryton.actions.action import Action


class FindServices(Action):
    def __init__(self, message_id: int, metadata: Metadata, target: str, ports: str):
        template = {
            "name": f"find-services-{message_id}",
            "step_type": "worker/execute",
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
        super().__init__(message_id, metadata, template)
