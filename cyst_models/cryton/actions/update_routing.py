from cyst.api.logic.metadata import Metadata
from cyst_models.cryton.actions.action import Action


class UpdateRouting(Action):
    def __init__(self, message_id: int, metadata: Metadata, session_id: int):
        template = {
            "name": f"update-routing-table-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "mod_msf",
                "module_arguments": {
                    "module_type": "post",
                    "module": "multi/manage/autoroute",
                    "module_options": {
                        "CMD": "autoadd",
                        "SESSION": session_id
                    }
                }
            }
        }
        super().__init__(message_id, metadata, template)
