import copy
from abc import ABC
from typing import Optional

from cyst.api.logic.metadata import Metadata
from cyst_models.cryton.proxy import Proxy


class Action(ABC):
    def __init__(self, message_id: int, metadata: Metadata, template: dict):
        self._message_id = message_id
        self._metadata = metadata
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

    def execute(self, proxy: Proxy) -> None:
        """
        Runs the Cryton action in the correct context.
        :param proxy: Cryton proxy used for the execution
        :return: None
        """
        template = copy.deepcopy(self._template)
        template["is_init"] = self._metadata.auxiliary.get("is_init", False)
        self._report = proxy.execute_action(self._template, self._metadata.auxiliary["agent_id"])
