from cyst_models.cryton.actions.action import Action


class ExecuteCommand(Action):
    def __init__(self, message_id: int, session: int, command: str):
        template = {
            "name": f"execute-command-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "mod_cmd",
                "module_arguments": {
                    "session_id": session,
                    "cmd": command
                }
            }
        }
        super().__init__(message_id, template)
