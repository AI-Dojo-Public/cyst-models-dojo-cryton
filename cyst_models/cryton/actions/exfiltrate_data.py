from cyst_models.cryton.actions.action import Action, ExternalResources


class ExfiltrateData(Action):
    def __init__(
        self,
        message_id: int,
        caller_id: str,
        external_resources: ExternalResources,
        session: int,
        file: str,
    ):
        template = {
            "name": f"exfiltrate-data-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "command",
                "module_arguments": {
                    "session_id": session,
                    "command": f"cat {file}",
                    "timeout": 60,
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)
