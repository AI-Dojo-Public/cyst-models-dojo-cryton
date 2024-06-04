from cyst_models.cryton.actions.action import Action, ExternalResources


class FindData(Action):
    def __init__(
        self,
        message_id: int,
        caller_id: str,
        external_resources: ExternalResources,
        session: int,
        directory: str,
    ):
        template = {
            "name": f"find-data-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "command",
                "module_arguments": {
                    "session_id": session,
                    "command": f'find {directory} | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"',
                    "timeout": 60,
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)
