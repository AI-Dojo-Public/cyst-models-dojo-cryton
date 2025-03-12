from cyst_models.cryton.actions.action import Action, ExternalResources

import re


class UpdateRouting(Action):
    def __init__(self, message_id: int, caller_id: str, external_resources: ExternalResources, session: str | int):
        used_session = session if isinstance(session, int) else f'{{{{ {session} }}}}'
        template = {
            f"update-routing-table-{message_id}": {
                "module": "metasploit",
                "arguments": {
                    "module_name": "multi/manage/autoroute",
                    "datastore": {
                        "CMD": "autoadd",
                        "SESSION": used_session,
                    },
                },
            }
        }
        super().__init__(message_id, template, caller_id, external_resources)

    @property
    def processed_output(self):
        subnets: list[str] = list()
        for line in self.output.split("\n"):
            if line.startswith("[+]") and (x := re.search(r"(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/[\d.]+)", line)):
                subnets.append(x.groups()[0])

        return subnets


# CMD => autoadd
# SESSION => 4
# [*] Running module against 10.0.1.3
# [*] Searching for subnets to autoroute.
# [+] Route added to subnet 10.0.1.0/255.255.255.0 from host's routing table.
# [*] Post module execution completed
# sIEGOaadnboLxhT5cBsC

# ['10.0.1.0/255.255.255.0']
