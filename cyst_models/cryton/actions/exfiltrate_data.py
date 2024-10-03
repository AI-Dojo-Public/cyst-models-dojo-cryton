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

    @property
    def processed_output(self):
        out = super().processed_output
        out["output"] = out["output"].removesuffix("\n")  # This is primarily for commands stored in the output

        return out


# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
# sys:x:3:3:sys:/dev:/usr/sbin/nologin
# sync:x:4:65534:sync:/bin:/bin/sync
# games:x:5:60:games:/usr/games:/usr/sbin/nologin
# man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
# lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
# mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
# news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
# uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
# proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
# www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
# backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
# list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
# irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
# _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
# nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
# employee:x:1000:1000::/home/employee:/bin/bash
# systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
# systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
# messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
# sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
# developer:x:1001:1001::/home/developer:/bin/bash


# git push
# tail -f var/logs/error
# nano +22,5 functions.sh
# source project-env/bin/activate
# history
# mysqldump -u cdri -h wordpress_db_node --password=cdri --no-tablespaces cdri

# {'output': 'root:x:0:0:root:/root:/bin/bash\n'}
