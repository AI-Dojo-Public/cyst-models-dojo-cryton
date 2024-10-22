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
from cyst.api.utils.duration import Duration, msecs
from netaddr.ip import IPNetwork, IPAddress

from cyst_models.cryton.session import MetasploitSession
from cyst_models.cryton.actions import *


class CrytonModel(BehavioralModel):
    mapping_service_port = {
        "ssh": 22,
        "vsftpd": 21,
        "mysql": 3306,
        "wordpress": 80,
    }
    mapping_port_service = dict([(v, k) for k, v in mapping_service_port.items()])

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

        self._action_store.add(
            ActionDescription(
                "dojo:phishing",
                ActionType.COMPOSITE,
                "Establish session from phishing",
                [],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:wait_for_session",
                ActionType.DIRECT,
                "Start session listener and wait for the session",
                [],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:upgrade_session",
                ActionType.DIRECT,
                "Upgrade session to Meterpreter",
                [],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:update_routing",
                ActionType.DIRECT,
                "Update routing table",
                [],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:scan_network",
                ActionType.COMPOSITE,
                "Scan the target network",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",
                        configuration.action.create_action_parameter_domain_any(),
                    )
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:find_services",
                ActionType.COMPOSITE,
                "Scan the target for services",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "to_network",
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                    ActionParameter(
                        ActionParameterType.NONE,
                        "services",
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
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
                        "service",
                        configuration.action.create_action_parameter_domain_options("ftp", ["ftp", "ssh"]),
                    ),
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
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
                        "directory",  # default is /
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:execute_command",
                ActionType.COMPOSITE,
                "Execute a command on a remote host",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "command",  # default is whoami
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:exfiltrate_data",
                ActionType.DIRECT,
                "Get data from a file",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "path",
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
            )
        )

    async def action_flow(self, message: Request) -> Tuple[Duration, Response]:
        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request], Coroutine[Any, Any, Tuple[Duration, Response]]] = getattr(
            self, "process_" + action_name, self.process_default
        )
        return await fn(message)

    async def action_effect(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn: Callable[[Request, Node], Coroutine[Any, Any, Tuple[Duration, Response]]] = getattr(
            self, "process_" + action_name, self.process_default
        )
        return await fn(message, node)

    def action_components(self, message: Union[Request, Response]) -> List[Action]:
        return []

    def process_default(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        print("Could not evaluate message. Tag in `dojo` namespace unknown. " + str(message))
        return msecs(0), self._messaging.create_response(
            message,
            Status(StatusOrigin.SYSTEM, StatusValue.ERROR),
            session=message.session,
        )

    async def process_phishing(self, message: Request) -> Tuple[Duration, Response]:
        action = self._action_store.get("dojo:direct:wait_for_session")
        request = self._messaging.create_request(message.dst_ip, message.dst_service, action, original_request=message)
        response: Response = await self._cam.call_action(request, 0)

        action = self._action_store.get("dojo:direct:upgrade_session")
        request = self._messaging.create_request(
            message.dst_ip, message.dst_service, action, response.session, original_request=message
        )
        response: Response = await self._cam.call_action(request, 0)

        action = self._action_store.get("dojo:direct:update_routing")
        request = self._messaging.create_request(
            message.dst_ip, message.dst_service, action, response.session, original_request=message
        )
        response: Response = await self._cam.call_action(request, 0)

        return msecs(0), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), response.content, response.session
        )

    async def process_direct_wait_for_session(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        action = SessionListener(message.id, message.platform_specific["caller_id"], self._external)
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            MetasploitSession(message.src_service, action.session_id),
        )

    async def process_direct_upgrade_session(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        action = UpgradeSession(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            int(message.session.id),
            str(message.src_ip),
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            MetasploitSession(message.src_service, action.session_id),
        )

    async def process_direct_update_routing(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        action = UpdateRouting(
            message.id, message.platform_specific["caller_id"], self._external, int(message.session.id)
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.NETWORK, StatusValue.SUCCESS),
            [IPNetwork(network) for network in action.processed_output],
            message.session,
        )

    async def process_scan_network(self, message: Request) -> Tuple[Duration, Response]:
        target = message.action.parameters["to_network"].value

        action = ScanNetwork(
            message.id, message.platform_specific["caller_id"], self._external, str(target), int(message.session.id)
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message, Status(StatusOrigin.NETWORK, StatusValue.FAILURE), action.processed_output, message.session
            )

        content = [IPAddress(address) for address in action.processed_output]
        return msecs(action.execution_time), self._messaging.create_response(
            message, Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), content, message.session
        )

    async def process_find_services(self, message: Request) -> Tuple[Duration, Response]:
        target = message.action.parameters["to_network"].value
        services = message.action.parameters["services"].value
        ports = await self._services_to_ports(services)
        parsed_ports = ",".join([str(port) for port in ports])

        action = FindServices(
            message.id, message.platform_specific["caller_id"], self._external, str(target), parsed_ports
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        content = dict()
        for address, open_ports in action.processed_output.items():
            content[IPAddress(address)] = await self._ports_to_services(open_ports)

        return msecs(action.execution_time), self._messaging.create_response(
            message, Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), content, message.session
        )

    @classmethod
    async def _services_to_ports(cls, services: list[str]) -> list[int]:
        return [cls.mapping_service_port[service] for service in services]

    @classmethod
    async def _ports_to_services(cls, ports: list[int]) -> list[str]:
        return [cls.mapping_port_service[port] for port in ports]

    async def process_exploit_server(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        action = ExploitServer(
            message.id, message.platform_specific["caller_id"], self._external, str(message.dst_ip), message.dst_service
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        if message.dst_service in ["ssh"]:
            new_session = MetasploitSession(message.src_service, action.session_id)
        else:
            new_session = message.session

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            new_session,
        )

    async def process_find_data(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        directory = message.action.parameters["directory"].value

        action = FindData(
            message.id, message.platform_specific["caller_id"], self._external, int(message.session.id), directory
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            message.session,
        )

    async def process_execute_command(self, message: Request) -> Tuple[Duration, Response]:
        command = message.action.parameters["command"].value

        action = ExecuteCommand(
            message.id, message.platform_specific["caller_id"], self._external, int(message.session.id), command
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            message.session,
        )

    async def process_direct_exfiltrate_data(self, message: Request, _: Node) -> Tuple[Duration, Response]:
        file_path = message.action.parameters["path"].value

        action = ExfiltrateData(
            message.id, message.platform_specific["caller_id"], self._external, int(message.session.id), file_path
        )
        await action.execute()

        if not action.is_success():
            return msecs(action.execution_time), self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        return msecs(action.execution_time), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            message.session,
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
    PlatformSpecification(PlatformType.REAL_TIME, "docker+cryton"),
)
