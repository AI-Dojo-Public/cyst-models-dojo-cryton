import unittest
from typing import Optional

from cyst.api.environment.environment import Environment, EnvironmentMode
from cyst.api.environment.message import Status, StatusOrigin, StatusValue
from cyst_services.scripted_actor.main import ScriptedActorControl

from importlib_metadata import entry_points
from typing import Optional, Any, Union
from cyst.core.environment.proxy import EnvironmentProxy

from cyst.api.host.service import ActiveService

from cyst_services.scripted_actor.main import ScriptedActorControl, ScriptedActor
from cyst.api.environment.message import StatusOrigin, StatusValue, Status, StatusDetail


class TestBasicScan(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = Environment.create(mode=EnvironmentMode.EMULATION_CRYTON)
        ep = EnvironmentProxy(cls._env, 'attacker_node', 'scripted_actor')

        attacker_service: Optional[ActiveService] = None

        plugins = entry_points(group="cyst.services")
        for p in plugins:
            service_description = p.load()

            if service_description.name == "scripted_actor":
                attacker_service = service_description.creation_fn(ep, cls._env, None)

                break

        if not attacker_service:
            exit(1)

        cls._env.register_service(node_name="attacker_node", service_name="scripted_actor", attacker_service=attacker_service)
        cls._attacker: ScriptedActorControl = cls._env.configuration.service.get_service_interface(attacker_service, ScriptedActorControl)
        cls._env.control.add_pause_on_response("attacker_node.scripted_actor")

    def test_1_basic_scan(self) -> None:

        # -----------------------------------------------------------------------------
        # Basic scan
        # -----------------------------------------------------------------------------

        agent_action_list = self.attacker._resources.action_store.get_prefixed("emul")
        actions = {}
        for action in agent_action_list:
            actions[action.id] = action

        a = actions["emul:scan"]
        self.attacker.execute_action('127.0.0.1', "", a)
        self.env.control.run()
        response = self.attacker.get_last_response()

        self.assertEqual(response.status, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "Bad StatusValue")