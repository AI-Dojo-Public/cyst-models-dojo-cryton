from typing import Tuple, Callable, Union, List, Coroutine, Any

from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.message import (
    Request,
    Response,
    Status,
    StatusOrigin,
    StatusValue,
)
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.logic.action import (
    ActionDescription,
    ActionType,
    ActionParameter,
    ActionParameterType,
    Action,
)
from cyst.api.environment.platform_specification import (
    PlatformSpecification,
    PlatformType,
)
from cyst.api.logic.behavioral_model import BehavioralModel, BehavioralModelDescription
from cyst.api.logic.composite_action import CompositeActionManager
from cyst.api.network.node import Node

from cyst_models.cryton.session import MetasploitSession
from cyst_models.cryton.actions import *


class CrytonModel(BehavioralModel):  # TODO: make sure the actions have correct parameters
    def __init__(
        self,
        configuration: EnvironmentConfiguration,
        resources: EnvironmentResources,
        policy: EnvironmentPolicy,
        messaging: EnvironmentMessaging,
        composite_action_manager: CompositeActionManager,
    ) -> None:
        self._configuration = configuration
        self._external = resources.external
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging
        self._cam = composite_action_manager

        # TODO: create action description in the action it self? would resolve the first todo here
        self._action_store.add(
            ActionDescription(
                "dojo:wait_for_session",
                ActionType.DIRECT,
                "Wait for the session to establish",
                [],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:upgrade_session",
                ActionType.DIRECT,
                "Wait for the session to establish",
                [],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:update_routing",
                ActionType.DIRECT,
                "Update routing table",
                [],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:scan_network",
                ActionType.DIRECT,
                "Scan the target network",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",  # 192.168.1.0/24
                        configuration.action.create_action_parameter_domain_any(),
                    )
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:find_services",
                ActionType.DIRECT,
                "Scan the target for services",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",  # 192.168.1.0/24 192.168.1.1
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "services",  # 1,3-10
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:exploit_server",
                ActionType.DIRECT,
                "Exploit the target service",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "service",
                        configuration.action.create_action_parameter_domain_options("ftp", ["ftp"]),
                    ),
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:find_data",
                ActionType.DIRECT,
                "Show a tree-like structure of the desired directory",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "directory",  # default is /
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:execute_command",
                ActionType.DIRECT,
                "Execute a command on a remote host",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "command",  # default is whoami
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:exfiltrate_data",
                ActionType.DIRECT,
                "Get data from a file",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_host",  # 192.168.1.1
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "data",  # file path
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

    async def action_flow(self, message: Request) -> Tuple[int, Response]:
        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request], Coroutine[Any, Any, Tuple[int, Response]]] = getattr(
            self, "process_" + action_name, self.process_default
        )
        return await fn(message)

    async def action_effect(self, message: Request, node: Node) -> Tuple[int, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request], Coroutine[Any, Any, Tuple[int, Response]]] = getattr(
            self, "process_" + action_name, self.process_default
        )
        return await fn(message, node)

    def action_components(self, message: Union[Request, Response]) -> List[Action]:
        return []

    def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `dojo` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR),
            session=message.session,
        )

    async def process_wait_for_session(self, message: Request, node: Node) -> Tuple[int, Response]:
        action = SessionListener(message.id, message.platform_specific["caller_id"], self._external)
        await action.execute()

        if not action.is_success():
            return 1, self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.output,
            )

        return 1, self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.output,
            MetasploitSession(message.src_service, action.session_id),
        )

    async def process_upgrade_session(self, message: Request, node: Node) -> Tuple[int, Response]:
        # TODO: unable to access resource twice/or two resources
        action = UpgradeSession(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
            str(message.src_ip),
        )
        await action.execute()

        if not action.is_success():
            return 1, self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.output,
            )

        return 1, self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.output,
            MetasploitSession(message.src_service, action.session_id),
        )

    async def process_update_routing(self, message: Request, node: Node) -> Tuple[int, Response]:
        action = UpdateRouting(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
        )
        await action.execute()

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_scan_network(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_network, technique (default is SYN)
        target = message.action.parameters["to_network"].value

        action = ScanNetwork(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            target,
            int(message.session.id),
        )
        await action.execute()

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_find_services(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_network, which_service (default is all)
        target = message.action.parameters["to_network"].value
        ports = message.action.parameters["services"].value

        action = FindServices(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            target,
            ports,
        )
        await action.execute()

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_exploit_server(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, service (default is an unspecified port, choose something common)
        target = message.action.parameters["to_host"].value
        service = message.action.parameters["service"].value

        action = ExploitServer(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            target,
            service,
        )
        await action.execute()

        if action.is_success():
            if service in ["ssh"]:
                new_session = MetasploitSession(message.src_service, action.session_id)
            else:
                new_session = message.session

            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=new_session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_find_data(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, directory (default is all)
        target = message.action.parameters["to_host"].value
        directory = message.action.parameters["directory"].value

        action = FindData(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
            directory,
        )
        await action.execute()

        # TODO: `if not action.is_success():` instead (also update others)
        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_execute_command(self, message: Request, node: Node) -> Tuple[int, Response]:
        target = message.action.parameters["to_host"].value
        command = message.action.parameters["command"].value

        action = ExecuteCommand(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
            command,
        )
        await action.execute()

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )

    async def process_exfiltrate_data(self, message: Request, node: Node) -> Tuple[int, Response]:
        # parameters: from_host, to_host, data
        target = message.action.parameters["to_host"].value
        file = message.action.parameters["data"].value

        action = ExfiltrateData(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
            file,
        )
        await action.execute()

        if action.is_success():
            return 1, self._messaging.create_response(
                message,
                status=Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                session=message.session,
                content=action.output,
            )

        return 1, self._messaging.create_response(
            message,
            status=Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            session=message.session,
            content=action.output,
        )


def create_cryton_model(
    configuration: EnvironmentConfiguration,
    resources: EnvironmentResources,
    policy: EnvironmentPolicy,
    messaging: EnvironmentMessaging,
    composite_action_manager: CompositeActionManager,
) -> BehavioralModel:
    return CrytonModel(configuration, resources, policy, messaging, composite_action_manager)


behavioral_model_description = BehavioralModelDescription(
    "dojo",
    "Perform simulated actions in the emulated environment through Cryton Proxy",
    create_cryton_model,
    PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
)
