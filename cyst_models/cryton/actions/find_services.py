import re

from cyst_models.cryton.actions.action import Action, ExternalResources


class FindServices(Action):
    def __init__(self, message_id: int, caller_id: str, external_resources: ExternalResources, target: str, ports: str):
        template = {
            "name": f"find-services-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "metasploit",
                "module_arguments": {
                    "module_name": "scanner/portscan/tcp",
                    "datastore": {"PORTS": ports, "RHOSTS": target, "THREADS": 10},
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)

    @property
    def processed_output(self):
        out = super().processed_output

        services: dict[str, list[int]] = dict()
        for line in self.output.split("\n"):
            if line.startswith("[+]") and (x := re.search(r"(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}):(\d+)", line)):
                if not services.get(x.groups()[0]):
                    services[x.groups()[0]] = list()
                services[x.groups()[0]].append(int(x.groups()[-1]))
        out["services"] = services

        return out


# PORTS => 22
# RHOSTS => 10.0.1.2
# THREADS => 10
# [+] 10.0.1.2:             - 10.0.1.2:22 - TCP OPEN
# [*] 10.0.1.2:             - Scanned 1 of 1 hosts (100% complete)
# [*] Auxiliary module execution completed
# REzKiDoAyiGcWfYwBMWi

# {'10.0.1.2': [22]}
