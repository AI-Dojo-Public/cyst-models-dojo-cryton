from typing import Tuple, Callable, Union, List, Coroutine, Any, Iterable
from copy import deepcopy
from cyst.api.logic.access import AccessLevel
from netaddr import IPNetwork
import asyncio
import random

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


class SimulationModel(BehavioralModel):
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:create_session",
                ActionType.DIRECT,
                "Create session to the target",
                [],
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:update_routing",
                ActionType.DIRECT,
                "Update routing table",
                [],
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:exploit_server",
                ActionType.DIRECT,
                "Exploit the target service",
                [],
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:scan_host",
                ActionType.DIRECT,
                "Scan host",
                [],
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
            )
        )

        self._action_store.add(
            ActionDescription(
                "dojo:direct:execute_command",
                ActionType.DIRECT,
                "Execute command",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "command",
                        configuration.action.create_action_parameter_domain_any(),
                    ),
                ],
                [
                    PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"),
                    PlatformSpecification(PlatformType.REAL_TIME, "CYST"),
                ],
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

    def process_default(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        print("Could not evaluate message. Tag in `dojo` namespace unknown. " + str(message))
        return msecs(0), self._messaging.create_response(
            message, Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session
        )

    async def process_phishing(self, message: Request) -> Tuple[Duration, Response]:
        action = self._action_store.get("dojo:direct:create_session")
        action.set_exploit(self._exploit_store.get_exploit("phishing_exploit")[0])
        request = self._messaging.create_request(message.dst_ip, message.dst_service, action, original_request=message)
        response: Response = await self._cam.call_action(request, 0)

        action = self._action_store.get("dojo:direct:update_routing")
        request = self._messaging.create_request(
            message.dst_ip, message.dst_service, action, response.session, original_request=message
        )
        response: Response = await self._cam.call_action(request, 0)

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), response.content, response.session
        )

    async def process_direct_create_session(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        if not message.action.exploit:
            return msecs(1), self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE))
        is_exploitable, reason = self._exploit_store.evaluate_exploit(message.action.exploit, message, node)
        if not is_exploitable:
            return msecs(1), self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE))

        session = self._configuration.network.create_session_from_message(message)
        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), session=session
        )

    async def process_direct_update_routing(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        if not message.session:
            return msecs(1), self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE))

        content = [node.interfaces[0].net]
        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), content, message.session, message.auth
        )

    async def process_scan_network(self, message: Request) -> Tuple[Duration, Response]:
        target = message.action.parameters["to_network"].value
        targets = target.iter_hosts() if isinstance(target, IPNetwork) else [target]

        results = await self._scan_multiple(targets, message)
        running_hosts = [result.src_ip if result.status.value == StatusValue.SUCCESS else ... for result in results]

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), running_hosts, message.session, message.auth
        )

    async def process_find_services(self, message: Request) -> Tuple[Duration, Response]:
        target = message.action.parameters["to_network"].value
        services = message.action.parameters["services"].value

        targets = target.iter_hosts() if isinstance(target, IPNetwork) else [target]
        results = await self._scan_multiple(targets, message)
        running_services: dict[str, list[str]] = dict()
        for result in results:
            if result.status.value == StatusValue.SUCCESS:
                running_services[result.src_ip] = list(
                    filter(lambda service: service in services, [c[0] for c in result.content])
                )

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.NETWORK, StatusValue.SUCCESS), running_services, message.session, message.auth
        )

    async def _scan_multiple(self, targets: Iterable, message: Request):
        tasks = set()
        for ip in targets:
            action = self._action_store.get("dojo:direct:scan_host")
            request = self._messaging.create_request(ip, "", action, original_request=message)
            tasks.add(self._cam.call_action(request, 0))

        return await asyncio.gather(*tasks)

    async def process_exploit_server(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        if not message.action.exploit:
            return msecs(1), self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE))
        is_exploitable, reason = self._exploit_store.evaluate_exploit(message.action.exploit, message, node)
        if not is_exploitable:
            return msecs(1), self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE))

        # Sanity check
        error = ""
        if message.dst_service not in node.services:
            error = f"Service {message.dst_service} not present at a node"
        elif node.services[message.dst_service].passive_service.local:
            error = f"Service {message.dst_service} is local."

        if error:
            return msecs(1), self._messaging.create_response(
                message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, message.session, message.auth
            )

        if message.dst_service in ["ssh"]:
            auth = self._configuration.access.create_authorization(
                "user", AccessLevel.ELEVATED, "asd", services=["ssh"]
            )
            new_session = self._configuration.network.create_session_from_message(message)
            content = [{"username": "user", "password": "pass"}]
            return msecs(random.randint(1, 10)), self._messaging.create_response(
                message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), content, new_session, auth
            )
        else:
            new_session = self._configuration.network.create_session_from_message(message)
            return msecs(1), self._messaging.create_response(
                message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "", new_session
            )

    async def process_find_data(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        directory = message.action.parameters["directory"].value

        result = []
        for data in self._configuration.service.private_data(node.services[message.auth.services[0]].passive_service):
            if data.id.startswith(directory):
                result.append(data.id)

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), result, message.session
        )

    async def process_execute_command(self, message: Request) -> Tuple[Duration, Response]:
        command = message.action.parameters["command"].value

        match command:
            case "mysqldump -u user -h 192.168.3.11 --password=pass --no-tablespaces table":
                auth = self._configuration.access.create_authorization(
                    "user", AccessLevel.ELEVATED, "dsa", services=["mysql"]
                )
                action = deepcopy(self._action_store.get("dojo:direct:exfiltrate_data"))
                action.parameters["path"].value = "db"
                request = self._messaging.create_request(
                    "192.168.3.11", "mysql", action, session=message.session, auth=auth, original_request=message
                )
                result = await self._cam.call_action(request, 0)
                content = result.content
            case _:
                action = deepcopy(self._action_store.get("dojo:direct:execute_command"))
                action.parameters["command"].value = command
                request = self._messaging.create_request(
                    message.dst_ip,
                    message.dst_service,
                    action,
                    session=message.session,
                    auth=message.auth,
                    original_request=message,
                )
                result = await self._cam.call_action(request, 0)
                content = result.content

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), content, message.session
        )

    async def process_direct_execute_command(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        command = message.action.parameters["command"].value

        match command:
            case "which mysqldump":
                content = "/usr/bin/mysqldump"
            case _:
                content = "ERROR"

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), content, message.session
        )

    async def process_direct_exfiltrate_data(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        file = message.action.parameters["path"].value

        for data in self._configuration.service.private_data(node.services[message.auth.services[0]].passive_service):
            if data.id == file:
                return msecs(1), self._messaging.create_response(
                    message,
                    Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                    data.description,
                    message.session,
                    message.auth,
                )

        return msecs(1), self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
            "File doesn't exist.",
            message.session,
            message.auth,
        )

    async def process_direct_scan_host(self, message: Request, node: Node) -> Tuple[Duration, Response]:
        services = []
        for service in node.services.values():
            if service.passive_service:
                services.append((service.name, service.passive_service.version))

        return msecs(1), self._messaging.create_response(
            message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), services, message.session, message.auth
        )


def create_simulation_model(
    configuration: EnvironmentConfiguration,
    resources: EnvironmentResources,
    policy: EnvironmentPolicy,
    messaging: EnvironmentMessaging,
    composite_action_manager: CompositeActionManager,
) -> BehavioralModel:
    return SimulationModel(configuration, resources, policy, messaging, composite_action_manager)


behavioral_model_description = BehavioralModelDescription(
    "dojo",
    "Perform simulated actions",
    create_simulation_model,
    [PlatformSpecification(PlatformType.SIMULATED_TIME, "CYST"), PlatformSpecification(PlatformType.REAL_TIME, "CYST")],
)
