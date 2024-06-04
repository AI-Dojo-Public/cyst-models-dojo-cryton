from cyst_models.cryton.actions.action import Action, ExternalResources


class ExecuteCommand(Action):
    def __init__(
        self,
        message_id: int,
        caller_id: str,
        external_resources: ExternalResources,
        session: int,
        command: str,
    ):
        template = {
            "name": f"execute-command-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "command",
                "module_arguments": {
                    "session_id": session,
                    "command": command,
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)
