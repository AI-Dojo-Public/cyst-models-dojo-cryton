from typing import Tuple, Callable, Union, List, Optional
from netaddr import IPAddress

from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.message import Request, Response, Status, StatusOrigin, StatusValue
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.action import ActionDescription, ActionType, ActionParameter, ActionParameterType, Action, ExecutionEnvironment, ExecutionEnvironmentType
from cyst.api.logic.behavioral_model import BehavioralModel, BehavioralModelDescription
from cyst.api.logic.composite_action import CompositeActionManager
from cyst.api.network.node import Node
from cyst.api.network.session import Session
from .cryton_utils import Cryton

from .wait_for_session import WaitForSession
from .update_routing import UpdateRouting
from .scan_network import ScanNetwork
from .find_services import FindServices
from .exploit_server import ExploitServer
from .find_data import FindData
from .execute_command import ExecuteCommand
from .exfiltrate_data import ExfiltrateData


class MetasploitSession(Session):
    def __init__(self, owner: str, session_id: int, parent: Optional['MetasploitSession'] = None):
        self._owner = owner
        self._id = session_id
        self._parent = parent

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def id(self) -> str:
        return str(self._id)

    @property
    def parent(self) -> Optional[Session]:
        return self._parent

    @property
    def path(self) -> List[Tuple[Optional[IPAddress], Optional[IPAddress]]]:
        return []

    @property
    def end(self) -> Tuple[IPAddress, str]:
        return None

    @property
    def start(self) -> Tuple[IPAddress, str]:
        return None

    @property
    def enabled(self) -> bool:
        return True


class CrytonModel(BehavioralModel):  # TODO: make sure the actions have correct parameters
    def __init__(self, configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                 policy: EnvironmentPolicy, messaging: EnvironmentMessaging,
                 composite_action_manager: CompositeActionManager) -> None:
        self._configuration = configuration
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging
        self._cam = composite_action_manager
        self.cryton_proxy: Optional[Cryton] = None

        self._action_store.add(
            ActionDescription(
                "emulation:wait_for_session",
                ActionType.DIRECT,
                "Wait for the session to establish",
                [],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:update_routing",
                ActionType.DIRECT,
                "Update routing table",
                [],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:scan_network",
                ActionType.DIRECT,
                "Scan the target network",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",  # 192.168.1.0/24
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:find_services",
                ActionType.DIRECT,
                "Scan the target for services",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",  # 192.168.1.0/24 192.168.1.1
                        configuration.action.create_action_parameter_domain_any()
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "services",  # 1,3-10
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:exploit_server",
                ActionType.DIRECT,
                "Exploit the target service",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any()
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "service",
                        configuration.action.create_action_parameter_domain_options(
                            "ftp",
                            ["ftp"]
                        )
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:find_data",
                ActionType.DIRECT,
                "Show a tree-like structure of the desired directory",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any()
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "directory",  # default is /
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:execute_command",
                ActionType.DIRECT,
                "Execute a command on a remote host",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any()
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "command",  # default is whoami
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

        self._action_store.add(
            ActionDescription(
                "emulation:exfiltrate_data",
                ActionType.DIRECT,
                "Get data from a file",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any()
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "data",  # file path
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")
            )
        )

    async def action_flow(self, message: Request) -> Tuple[int, Response]:
        raise RuntimeError("`emulation` namespace does not support composite actions")

    def action_effect(self, message: Request, node: Node) -> Tuple[int, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request, Node], Tuple[int, Response]] = getattr(
            self, "process_" + action_name, self.process_default
        )
        return fn(message, node)

    def action_components(self, message: Union[Request, Response]) -> List[Action]:
        return []

    def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `emulation` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(
            message, status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session
        )

    def process_wait_for_session(self, message: Request, node: Node) -> Tuple[int, Response]:
        action = WaitForSession(message.id, message.metadata)
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=MetasploitSession(message.src_service, action.session_id),
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=None,
            content=action.output
        )

    def process_update_routing(self, message: Request, node: Node) -> Tuple[int, Response]:
        action = UpdateRouting(message.id, message.metadata, int(message.session.id))
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_scan_network(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_network, technique (default is SYN)
        target = message.action.parameters["to_network"].value

        action = ScanNetwork(message.id, message.metadata, target, int(message.session.id))
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_find_services(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_network, which_service (default is all)
        target = message.action.parameters["to_network"].value
        ports = message.action.parameters["services"].value

        action = FindServices(message.id, message.metadata, target, ports)
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_exploit_server(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, service (default is an unspecified port, choose something common)
        target = message.action.parameters["to_host"].value
        service = message.action.parameters["service"].value

        action = ExploitServer(message.id, message.metadata, target, service)
        action.execute(self.cryton_proxy)

        if action.is_success():
            if service in ["ssh"]:
                new_session = MetasploitSession(message.src_service, action.session_id)
            else:
                new_session = message.session

            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=new_session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_find_data(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, directory (default is all)
        target = message.action.parameters["to_host"].value
        directory = message.action.parameters["directory"].value

        action = FindData(message.id, message.metadata, int(message.session.id), directory)
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_execute_command(self, message: Request, node: Node) -> Tuple[int, Response]:
        target = message.action.parameters["to_host"].value
        command = message.action.parameters["command"].value

        action = ExecuteCommand(message.id, message.metadata, int(message.session.id), command)
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )

    def process_exfiltrate_data(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, data
        target = message.action.parameters["to_host"].value
        file = message.action.parameters["data"].value

        action = ExfiltrateData(message.id, message.metadata, int(message.session.id), file)
        action.execute(self.cryton_proxy)

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output
        )


def create_cryton_model(
        configuration: EnvironmentConfiguration,
        resources: EnvironmentResources,
        policy: EnvironmentPolicy,
        messaging: EnvironmentMessaging,
        composite_action_manager: CompositeActionManager
) -> BehavioralModel:
    return CrytonModel(configuration, resources, policy, messaging, composite_action_manager)


behavioral_model_description = BehavioralModelDescription(
    "emulation",
    "Perform simulated actions in the emulated environment through Cryton Proxy",
    create_cryton_model
)
