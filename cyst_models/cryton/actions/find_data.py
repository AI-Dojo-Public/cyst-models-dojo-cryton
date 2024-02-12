from cyst.api.logic.metadata import Metadata
from cyst_models.cryton.actions.action import Action


class FindData(Action):
    def __init__(self, message_id: int, metadata: Metadata, session: int, directory: str):
        template = {
            "name": f"find-data-{message_id}",
            "step_type": "worker/execute",
            "arguments": {
                "module": "mod_cmd",
                "module_arguments": {
                    "session_id": session,
                    "cmd": f'find {directory} | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"'
                }
            }
        }
        super().__init__(message_id, metadata, template)
