from typing import Optional, Any, Union
from netaddr import IPAddress

from cyst.api.environment.environment import Environment
from cyst.api.environment.message import Request, Message, Response, Status
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources, ActionStore, ExploitStore, Clock, Statistics
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.logic.action import Action, ExecutionEnvironment, ExecutionEnvironmentType
from cyst.api.logic.behavioral_model import BehavioralModel
from cyst.api.network.session import Session

from cyst.core.environment.message import MessageImpl, Metadata
from .cryton_utils import Cryton


class CrytonProxy(EnvironmentMessaging, EnvironmentResources):
    def __init__(self, environment: Environment, cryton_host: str, cryton_port: int):
        self._env = environment
        self._messaging = environment.messaging
        self._resources = environment.resources
        self._policy = environment.policy
        self._configuration = environment.configuration

        self.services = []
        self.agents: dict[int, int] = {}
        self._behavioral_models: dict[str, BehavioralModel] = environment._behavioral_models

        self._agent_counter = 0
        self.cryton = Cryton(cryton_host, cryton_port)
        self._behavioral_models["emulation"].cryton_proxy = self.cryton

    def open_session(self, request: Request):
        raise RuntimeError("Not implemented")

    def register_service(self, node_name, service_name, attacker_service):
        self.services.append(
            {"node_name": node_name, "service_name": service_name, "attacker_service": attacker_service}
        )

    def _add_agent(self, service_id: int):
        self._agent_counter += 1
        self.cryton.initialize_agent(self._agent_counter)
        self.agents[service_id] = self._agent_counter

    def send_message(self, message: Message, delay: int = 0) -> None:
        request = message.cast_to(Request)
        m = MessageImpl.cast_from(message)
        service_id = hash((m.origin.id, m.src_service))
        meta = Metadata()

        if service_id not in self.agents.keys():
            self._add_agent(service_id)
            meta.auxiliary["is_init"] = True

        meta.auxiliary["agent_id"] = self.agents[service_id]
        request.set_metadata(meta)

        print(f"\n{'-'*50}\nAttacker executed action {request.action.id} on target {request.dst_ip}.")

        for service in self.services:
            if service["service_name"] == request.src_service:
                time, response = self._behavioral_models[request.action.namespace].action_effect(request, None)
                service["attacker_service"].process_message(response)

    def create_request(
            self,
            dst_ip: Union[str, IPAddress],
            dst_service: str = "",
            action: Optional[Action] = None,
            session: Optional[Session] = None,
            auth: Optional[Union[Authorization, AuthenticationToken]] = None,
            original_request: Optional[Request] = None
    ) -> Request:
        if not self.action_store.get(action.id, ExecutionEnvironment(ExecutionEnvironmentType.EMULATION, "CRYTON")):
            raise RuntimeError

        return self._messaging.create_request(dst_ip, dst_service, action, session, auth)

    def create_response(
            self,
            request: Request, status: Status, content: Optional[Any] = None,
            session: Optional[Session] = None,
            auth: Optional[Union[Authorization, AuthenticationTarget]] = None,
            original_response: Optional[Response] = None
    ) -> Response:
        return self._messaging.create_response(request, status, content, session, auth)

    @property
    def action_store(self) -> ActionStore:
        return self._resources.action_store

    @property
    def exploit_store(self) -> ExploitStore:
        return self._resources.exploit_store

    @property
    def clock(self) -> Clock:
        return self._resources.clock

    @property
    def statistics(self) -> Statistics:
        return self._resources.statistics
