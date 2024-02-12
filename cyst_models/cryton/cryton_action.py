import copy
from abc import ABC
from .cryton_utils import Cryton
from typing import Optional
from cyst.api.logic.metadata import Metadata


class CrytonAction(ABC):
    def __init__(self, message_id: int, metadata: Metadata):
        self._message_id = message_id
        self._metadata = metadata
        self._report: Optional[dict] = None
        self._template: Optional[dict] = None

    @property
    def report(self) -> dict:
        if not self._report:
            raise RuntimeError(self._template["name"], "Output cannot be delivered before the action execution.")
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

    def execute(self, cryton_proxy: Cryton) -> None:
        """
        Runs the Cryton action in the correct plan.
        :param cryton_proxy: Cryton proxy object
        :return: None
        """
        template = copy.deepcopy(self._template)
        template["is_init"] = self._metadata.auxiliary.get("is_init", False)
        self._report = cryton_proxy.execute_action(self._template, self._metadata.auxiliary["agent_id"])
