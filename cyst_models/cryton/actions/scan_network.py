from cyst_models.cryton.actions.action import Action


class ScanNetwork(Action):
    def __init__(self, message_id: int, target: str, session: int):
        template = {
            "name": f"scan-network-{message_id}",
            "step_type": "worker/execute",
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
        super().__init__(message_id, template)

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
