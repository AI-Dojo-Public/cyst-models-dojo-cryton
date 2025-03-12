import sys
from copy import deepcopy
from typing import Optional, Union, Any

from cyst.api.logic.action import Action
from cyst.api.environment.message import Status, StatusOrigin, StatusValue, Response
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.logic.exploit import Exploit
from cyst.api.network.session import Session
from cyst.api.environment.platform_specification import PlatformType, PlatformSpecification
from cyst_services.scripted_actor.main import ScriptedActorControl
from cyst.api.environment.environment import Environment
from cyst.api.host.service import ActiveService

from demo_firehole_infrastructure import (
    all_config_items,
    node_wordpress,
    node_database,
    node_vsftpd,
    node_workstation,
    exploit_wordpress,
    exploit_mysql,
    exploit_vsftpd,
    exploit_smb
)


class Scenario:
    def __init__(self, platform: PlatformSpecification):
        self.environment = Environment.create(platform)
        self.attacker: ScriptedActorControl | None = None
        self.actions: dict[str, Action] = dict()

    def configure(self):
        self.environment = self.environment.configure(*all_config_items)
        self.environment.control.init()
        self.environment.control.add_pause_on_response("node_attacker.scripted_attacker")
        attacker_service = self.environment.configuration.general.get_object_by_id(
            "node_attacker.scripted_attacker", ActiveService
        )
        self.attacker = self.environment.configuration.service.get_service_interface(
            attacker_service, ScriptedActorControl
        )
        self.actions = {action.id: action for action in self.environment.resources.action_store.get_prefixed("dojo")}

    def display_actions(self) -> None:
        action_name_len = max([len(action.id) for action in self.actions.values()])
        action_description_len = max([len(action.description) for action in self.actions.values()])

        print(f"\n{'-' * 50}\nAvailable actions:")
        for action in self.actions.values():
            print(
                f"{' ' * (action_name_len - len(action.id))}{action.id}: "
                f"{action.description}{' ' * (action_description_len - len(action.description))} "
                f"{list(action.parameters.keys())}"
            )

    def finish(self):
        print(f"\n{'-' * 50}\nScenario finished!")
        self.environment.control.commit()

    def _build_action(self, action_id: str, action_parameters: Optional[dict[str, Any]]) -> Action:
        action = deepcopy(self.actions[action_id])
        if action_parameters:
            for k, v in action_parameters.items():
                action.parameters[k].value = v

        return action

    def execute_action(
        self,
        action_id: str,
        target: str,
        ok_statuses: list[Status],
        action_parameters: dict[str, Any] = None,
        service: str = "",
        session: Session = None,
        auth: Union[Authorization, AuthenticationToken] = None,
        exploit: Exploit = None,
    ) -> Response:
        print(f"\n{'-' * 50}\n{action_id}\nParameters: {action_parameters}\nOutput:\n")
        action = self._build_action(action_id, action_parameters)
        if exploit:
            action.set_exploit(exploit)
        self.attacker.execute_action(target, service, action, session, auth)
        result, state = self.environment.control.run()
        response = self.attacker.get_last_response()
        print(response.content)

        if response.status not in ok_statuses:
            raise RuntimeError(f"Action failed with {response.status}.")

        return response

    def run(self):
        action_response = self.execute_action(
            "dojo:exploit_server",
            str(node_wordpress.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            service="wordpress",
            exploit=self.environment.resources.exploit_store.get_exploit(exploit_wordpress.id)[0],
        )

        action_response = self.execute_action(
            "dojo:execute_command",
            str(node_wordpress.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="wordpress",
            action_parameters={"command": "whoami"},
        )

        action_response = self.execute_action(
            "dojo:exploit_server",
            str(node_database.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="mysql",
            exploit=self.environment.resources.exploit_store.get_exploit(exploit_mysql.id)[0],
        )

        action_response = self.execute_action(
            "dojo:exploit_server",
            str(node_workstation.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="samba",
            exploit=self.environment.resources.exploit_store.get_exploit(exploit_smb.id)[0],
        )

        action_response = self.execute_action(
            "dojo:execute_command",
            str(node_workstation.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="samba",
            action_parameters={"command": "whoami"},
        )

        action_response = self.execute_action(
            "dojo:exploit_server",
            str(node_vsftpd.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="vsftpd",
            exploit=self.environment.resources.exploit_store.get_exploit(exploit_vsftpd.id)[0],
        )

        action_response = self.execute_action(
            "dojo:execute_command",
            str(node_vsftpd.interfaces[0].ip),
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
            service="vsftpd",
            action_parameters={"command": "whoami"},
        )


def main():
    try:
        env = sys.argv[1]
    except IndexError:
        print("Choose 'real' or 'simu'. -> demo_2023.py simu")
        exit(1)

    try:
        debug = sys.argv[2]
    except IndexError:
        debug = ""

    if env == "real":
        platform = PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton")
    else:
        platform = PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST")

    scenario = Scenario(platform)
    try:
        scenario.configure()
        scenario.display_actions()
        scenario.run()
    except Exception as ex:
        print(str(ex))
        if debug:
            input("Press enter to stop the scenario... ")
        raise ex
    finally:
        scenario.finish()


if __name__ == "__main__":
    main()
