from cyst_models.cryton.actions.action import Action, ExternalResources


class UpdateRouting(Action):
    def __init__(self, message_id: int, caller_id: str, external_resources: ExternalResources, session_id: int):
        template = {
            "name": f"update-routing-table-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "metasploit",
                "module_arguments": {
                    "module_name": "multi/manage/autoroute",
                    "datastore": {
                        "CMD": "autoadd",
                        "SESSION": session_id,
                    },
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)
