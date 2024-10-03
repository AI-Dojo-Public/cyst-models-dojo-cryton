from copy import deepcopy
from typing import Optional, Union, Any

from cyst.api.logic.action import Action
from cyst.api.host.service import ActiveService
from cyst.api.environment.message import Status, StatusOrigin, StatusValue, Response
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.network.session import Session

from cyst_services.scripted_actor.main import ScriptedActorControl
from cyst.api.environment.environment import Environment

from demo_2023_infrastructure import all_config_items


class Scenario:
    def __init__(self):
        self.environment = Environment.create("docker+cryton").configure(*all_config_items)
        self.environment.control.init()
        self.environment.control.add_pause_on_response("attacker_node.scripted_attacker")
        attacker_service = self.environment.configuration.general.get_object_by_id(
            "attacker_node.scripted_attacker", ActiveService
        )
        self.attacker: ScriptedActorControl = self.environment.configuration.service.get_service_interface(
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
        ok_statuses: list[Status],
        action_parameters: dict[str, Any] = None,
        target: str = "192.168.1.100",  # TODO: remove the default once the session/target translation is solved/created
        service: str = "",
        session: Session = None,
        auth: Union[Authorization, AuthenticationToken] = None,
    ) -> Response:
        print(f"\n{'-' * 50}\n{action_id}\nParameters: {action_parameters}\nOutput:\n")
        action = self._build_action(action_id, action_parameters)
        self.attacker.execute_action(target, service, action, session, auth)
        result, state = self.environment.control.run()
        response = self.attacker.get_last_response()
        print(response.content)

        if response.status not in ok_statuses:
            raise RuntimeError("Failed to open the session")

        return response

    def run(self):
        # ------------------------------------
        # Phishing
        # ------------------------------------

        # Get the initial session from phishing
        action_response = scenario.execute_action(
            "dojo:wait_for_session", [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)]
        )

        # Upgrade session
        action_response = scenario.execute_action(
            "dojo:upgrade_session",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            session=action_response.session,
        )

        # Update MSF's routing table
        action_response = scenario.execute_action(
            "dojo:update_routing",
            [
                Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            ],
            session=action_response.session,
        )

        # ------------------------------------
        # Information gathering
        # ------------------------------------

        # Scan new network
        action_response = scenario.execute_action(
            "dojo:scan_network",
            [Status(StatusOrigin.NETWORK, StatusValue.SUCCESS)],
            {"to_network": "192.168.2.10"},  # 192.168.2.10/24 scans the whole subnet
            session=action_response.session,
        )

        # ------------------------------------
        # Access the dev account
        # ------------------------------------

        # Scan the hosts for ssh service
        action_response = scenario.execute_action(
            "dojo:find_services",
            [Status(StatusOrigin.NETWORK, StatusValue.SUCCESS)],
            {
                "to_network": "192.168.2.10",
                "services": "22",
            },  # 192.168.2.10/24 scans the whole subnet
            session=action_response.session,
        )

        # Bruteforce the ssh service
        action_response = scenario.execute_action(
            "dojo:exploit_server",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {"to_host": "192.168.2.10", "service": "ssh"},
            session=action_response.session,
        )

        # ------------------------------------
        # Gather information from the dev account
        # ------------------------------------

        # Home directory listing
        action_response = scenario.execute_action(
            "dojo:find_data",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {"to_host": "192.168.2.10", "directory": "~/"},
            session=action_response.session,
        )

        # Check for users
        action_response = scenario.execute_action(
            "dojo:exfiltrate_data",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {"to_host": "192.168.2.10", "data": "/etc/passwd"},
            session=action_response.session,
        )

        # Check for mysqldump
        action_response = scenario.execute_action(
            "dojo:execute_command",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {"to_host": "192.168.2.10", "command": "which mysqldump"},
            session=action_response.session,
        )

        # Check bash history
        action_response = scenario.execute_action(
            "dojo:exfiltrate_data",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {"to_host": "192.168.2.10", "data": "~/.bash_history"},
            session=action_response.session,
        )

        # ------------------------------------
        # Get data from DB
        # ------------------------------------

        # Get data from DB
        action_response = scenario.execute_action(
            "dojo:execute_command",
            [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
            {
                "to_host": "192.168.2.10",
                "command": action_response.content["output"],
            },
            session=action_response.session,
        )


# TODO: add defaults to action's parameters
if __name__ == "__main__":
    scenario = Scenario()
    scenario.display_actions()

    try:
        scenario.run()
    except:
        pass

    scenario.finish()
