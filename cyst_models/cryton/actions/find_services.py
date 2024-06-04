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
