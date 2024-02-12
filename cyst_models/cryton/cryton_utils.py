import copy
from typing import Optional
import requests
import yaml
import time


def get_request(api_url: str, json: dict = None) -> requests.Response:
    try:
        return requests.get(api_url, json=json)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Unable to connect to {api_url}")
    except requests.exceptions.HTTPError:
        raise RuntimeError
    except requests.exceptions.Timeout:
        raise RuntimeError(f"{api_url} request timed out")


def post_request(api_url: str, data: dict = None, files: dict = None) -> requests.Response:
    try:
        return requests.post(api_url, data=data, files=files)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"Unable to connect to {api_url}")
    except requests.exceptions.HTTPError:
        raise RuntimeError
    except requests.exceptions.Timeout:
        raise RuntimeError(f"{api_url} request timed out")


class Cryton:
    TEMPLATE = {
        "plan": {
            "name": "Dynamic plan equivalent",
            "owner": "CYST",
            "dynamic": True,
            "stages": [
                {
                    "name": "Global stage",
                    "trigger_type": "delta",
                    "trigger_args": {
                        "seconds": 0
                    },
                    "steps": []
                }
            ]
        }
    }

    def __init__(self, cryton_core_ip: str, cryton_core_port: int):
        self.api_root = f"http://{cryton_core_ip}:{cryton_core_port}/api/"
        self._stage_id: Optional[int] = None
        self._stage_execution_id: Optional[int] = None
        self._agents: dict[int, dict] = {}

    def check_connection(self):
        get_request(self.api_root)
        print("Cryton service is reachable.")

    def _create_worker(self, name: str, description: str) -> int:
        response = post_request(
            f"{self.api_root}workers/",
            data={"name": name, "description": description}
        )

        if response.status_code == 201:
            return response.json()["id"]
        else:
            response = get_request(f"{self.api_root}workers/?name={name}")
            for w in response.json():
                if w["name"] == name:
                    return w["id"]

        raise RuntimeError(f"Unable to set/get Worker with name `{name}`.")

    def _healthcheck_worker(self, worker_id: int):
        response = post_request(f"{self.api_root}workers/{worker_id}/healthcheck/")
        if "UP" in response.json()["detail"]:
            return True

        return False

    def _create_template(self, template: dict) -> int:
        return post_request(f"{self.api_root}templates/", files={"file": yaml.dump(template)}).json()["id"]

    def _create_plan(self, template_id: int) -> int:
        return post_request(f"{self.api_root}plans/", {"template_id": template_id}).json()["id"]

    def _create_stage(self, template: dict, plan_id: int) -> int:
        return post_request(self.api_root + "stages/", {"plan_id": plan_id}, {"file": yaml.dump(template)}).json()["id"]

    def _get_stage_id(self, plan_id: int) -> int:
        return get_request(f"{self.api_root}stages/?plan_model_id={plan_id}").json()[0]["id"]

    def _create_run(self, plan_id: int, worker_ids: list[int]) -> int:
        return post_request(f"{self.api_root}runs/", {"plan_id": plan_id, "worker_ids": worker_ids}).json()["id"]

    def _execute_run(self, run_id: int):
        if post_request(f"{self.api_root}runs/{run_id}/execute/", data={"run_id": run_id}).status_code != 200:
            raise RuntimeError(f"Unable to execute run {run_id}.")

    def _create_step(self, step: dict, stage_id: int) -> int:
        return post_request(f"{self.api_root}steps/", {"stage_id": stage_id}, {"file": yaml.dump(step)}).json()["id"]

    def _execute_step(self, step_id: int, stage_execution_id: int) -> int:
        return post_request(
            f"{self.api_root}steps/{step_id}/execute/",
            {"stage_execution_id": stage_execution_id}
        ).json()["execution_id"]

    def _wait_for_step(self, step_execution_id: int):
        while get_request(f"{self.api_root}step_executions/{step_execution_id}/").json()["state"] != "FINISHED":
            time.sleep(3)

    def _get_step_report(self, cryton_step_ex_id: int) -> dict:
        return get_request(api_url=f"{self.api_root}step_executions/{cryton_step_ex_id}/report/").json()

    def _get_run_report(self, run_id: int) -> dict:
        return get_request(api_url=f"{self.api_root}runs/{run_id}/report/").json()

    def initialize_agent(self, agent_id: int):
        worker_id = self._create_worker(
            f"cyst-agent-{agent_id}",
            "Agent used for running action in the emulation environment."
        )
        if not self._healthcheck_worker(worker_id):
            raise RuntimeError(f"Unable to initialize agent with ID {agent_id}.")

        template = copy.deepcopy(self.TEMPLATE)
        template["plan"]["name"] = f"Plan for CYST Worker {agent_id}"

        template_id = self._create_template(template)
        plan_id = self._create_plan(template_id)
        stage_id = self._get_stage_id(plan_id)
        run_id = self._create_run(plan_id, worker_ids=[worker_id])
        stage_execution_id = self._get_run_report(run_id)["detail"]["plan_executions"][0]["stage_executions"][0]["id"]
        self._execute_run(run_id)

        self._agents[agent_id] = {
            "worker_id": worker_id,
            "plan_id": plan_id,
            "run_id": run_id,
            "stage_id": stage_id,
            "stage_execution_id": stage_execution_id
        }

    def execute_action(self, step_template: dict, agent_id: int) -> dict:
        agent = self._agents[agent_id]
        step_id = self._create_step(step_template, agent["stage_id"])
        step_execution_id = self._execute_step(step_id, agent["stage_execution_id"])
        self._wait_for_step(step_execution_id)
        return self._get_step_report(step_execution_id)
