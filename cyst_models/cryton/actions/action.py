import copy
from abc import ABC
from typing import Optional
from netaddr import IPAddress

from cyst_models.cryton.proxy import Proxy


class Action(ABC):
    def __init__(self, message_id: int, template: dict):
        self._message_id = message_id
        self._template = template
        self._report: Optional[dict] = None

    @property
    def report(self) -> dict:
        if not self._report:
            raise RuntimeError(self._message_id, "Cannot retrieve output before the action finishes.")
        return self._report

    @property
    def output(self) -> str:
        return self.report["output"]

    @property
    def serialized_output(self) -> dict:
        return self.report["serialized_output"]

    @property
    def session_id(self) -> int:
        return self.serialized_output["session_id"]

    def is_success(self) -> bool:
        if self.report["result"] == "OK":
            return True
        return False

    def execute(self, proxy: Proxy, src_ip: IPAddress) -> None:
        """
        Runs the Cryton action in the correct context.
        :param proxy: Cryton proxy used for the execution
        :param src_ip: Worker's address
        :return: None
        """
        try:
            agent_id = proxy.find_agent_id(str(src_ip))
            is_init = False
        except KeyError:
            proxy.initialize_agent(str(src_ip))
            agent_id = proxy.find_agent_id(str(src_ip))
            is_init = True

        template = copy.deepcopy(self._template)
        template["is_init"] = is_init
        self._report = proxy.execute_action(self._template, agent_id)
