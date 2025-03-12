from cyst_models.cryton.actions.action import Action, ExternalResources

import re


class ScanNetwork(Action):
    def __init__(
        self, message_id: int, caller_id: str, external_resources: ExternalResources, target: str, session: str | int
    ):
        used_session = session if isinstance(session, int) else f'{{{{ {session} }}}}'
        template = {
            f"scan-network-{message_id}": {
                "module": "metasploit",
                "arguments": {
                    "module_name": "multi/gather/ping_sweep",
                    "datastore": {"SESSION": used_session, "RHOSTS": target},
                },
            }
        }
        super().__init__(message_id, template, caller_id, external_resources)

    @property
    def processed_output(self) -> list[str]:
        ips: list[str] = list()
        for line in self.output.split("\n"):
            if line.endswith("host found") and (x := re.search(r"(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})", line)):
                ips.append(x.groups()[0])

        return ips


# [!] SESSION may not be compatible with this module:
# [!]  * incompatible session platform: python
# [*] Performing ping sweep for IP range 192.168.56.0/24
# [+] 	192.168.56.1 host found
# [+] 	192.168.56.2 host found
# [+] 	192.168.56.99 host found
# [*] Post module execution completed

# RHOSTS => 10.0.1.2
# SESSION => 4
# [*] Performing ping sweep for IP range 10.0.1.2
# [+] 	10.0.1.2 host found
# [*] Post module execution completed
# w1qZfpSc3nLe8YH0WB3Y

# ['10.0.1.2']
