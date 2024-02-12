from .cryton_action import CrytonAction
from cyst.api.logic.metadata import Metadata


class ScanNetwork(CrytonAction):
    def __init__(self, message_id: int, metadata: Metadata, target: str, session: int):
        super().__init__(message_id, metadata)

        self._template = {
            "name": f"scan-network-{message_id}",
            "step_type": "worker/execute",
            "is_init": True,
            "arguments": {
                "module": "mod_msf",
                "module_arguments": {
                    "module_type": "post",
                    "module": "multi/gather/ping_sweep",
                    "module_options": {
                        "SESSION": session,
                        "RHOSTS": target
                    }
                }
            }
        }

        # output
        # msf6 post(multi/gather/ping_sweep) > run
        #
        # [!] SESSION may not be compatible with this module:
        # [!]  * incompatible session platform: python
        # [*] Performing ping sweep for IP range 192.168.56.0/24
        # [+] 	192.168.56.1 host found
        # [+] 	192.168.56.2 host found
        # [+] 	192.168.56.99 host found
        # [*] Post module execution completed
