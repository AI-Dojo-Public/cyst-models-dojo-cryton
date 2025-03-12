from cyst_models.cryton.actions.action import Action, ExternalResources


class ExecuteCommand(Action):
    def __init__(
        self,
        message_id: int,
        caller_id: str,
        external_resources: ExternalResources,
        session: str | int,
        command: str,
    ):
        used_session = session if isinstance(session, int) else f'{{{{ {session} }}}}'
        template = {
            f"execute-command-{message_id}": {
                "module": "command",
                "arguments": {
                    "session_id": used_session,
                    "command": command,
                },
            },
        }
        super().__init__(message_id, template, caller_id, external_resources)

    @property
    def processed_output(self) -> str:
        return self.output


# /usr/bin/mysqldump

# {'output': '/usr/bin/mysqldump\n'}
