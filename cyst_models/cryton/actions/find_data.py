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
                    "command": f'find {directory}',
                    "timeout": 60,
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)

    @property
    def processed_output(self):
        out = super().processed_output

        files: list[str] = list()
        for line in self.output.split("\n"):
            files.append(line)

        out["files"] = files

        return out


# /home/developer/
# /home/developer/.bash_logout
# /home/developer/.bashrc

# ['/home/developer/', '/home/developer/.bash_logout', '/home/developer/.bashrc']
