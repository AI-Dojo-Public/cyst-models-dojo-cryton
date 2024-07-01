import copy
from abc import ABC
from typing import Optional, Union, Any

from cyst.api.environment.external import ExternalResources


class Action(ABC):
    def __init__(
        self,
        message_id: int,
        template: dict,
        caller_id: str,
        external_resources: ExternalResources,
    ):
        self._message_id = message_id
        self._template = template
        self._caller_id = caller_id
        self._external_resources = external_resources
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
    def serialized_output(self) -> Union[dict, list]:
        return self.report["serialized_output"]

    @property
    def session_id(self) -> int:
        return self.serialized_output["session_id"]

    def is_success(self) -> bool:
        if self.report["result"] == "ok":
            return True
        return False

    @property
    def processed_output(self) -> Any:
        out = {"output": self.output}
        out.update(self.serialized_output)

        return out

    async def execute(self) -> None:
        """
        Runs Cryton action in the correct context using resource.
        :return: None
        """
        resource = self._external_resources.create_resource("cryton://")
        self._report = await self._external_resources.fetch_async(
            resource,
            {
                "template": copy.deepcopy(self._template),
                "node_id": self._caller_id.split(".")[0],
            },
        )
