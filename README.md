This repository contains a namespace package CrytonProxy for use with CYST Core.

CYST documentation can be found [here](https://muni.cz/go/cyst/).

## Installation
Once you've created Python environment for CYST and installed `cyst-core`, enter the environment
```shell
source path/to/cyst-core/venv/bin/activate
```

and install this module.
```shell
pip install -e path/to/cyst-models-dojo-cryton/
```

## Implementing a new action
Each action
- should derive from the `cyst_models.cryton.actions.action.Action` class
- must be registered in action store (`cyst_models.cryton.CrytonModel.action_store`)
- must implement process evaluation (`cyst_models.cryton.CrytonModel.process_<action_name>`)

### Create action
Let's say we want to create an action that executes commands only on the Cryton Worker's host. You will use the same template as you would in Cryton.  
Create a new Python file (for example `local_command_execution.py`) in `cyst_models/cryton/actions/` with the following content:
```python
from cyst_models.cryton.actions.action import Action, ExternalResources


class LocalCommandExecution(Action):
    def __init__(
        self,
        message_id: int,
        caller_id: str,
        external_resources: ExternalResources,
        command: str,
    ):
        template = {
            f"execute-command-locally-{message_id}": {
                "module": "command",
                "arguments": {
                    "command": command
                },
            }
        }
        super().__init__(message_id, template, caller_id, external_resources)

```

As you can see, in the example we defined a *template* we want to use, and require a *message_id* and a *command* that will be used in the template.

Additionally, add your action to the `cyst_models/cryton/actions/__init__.py` file:
```python
from cyst_models.cryton.actions.local_command_execution import LocalCommandExecution

```

### Register action
To use the action, we have to register it to our model's action store. Add the following code to the `cyst_models.cryton.CrytonModel.__init__` method:
```python
        self._action_store.add(
            ActionDescription(
                "dojo:local_command_execution",
                ActionType.DIRECT,
                "Execute command on the Worker host",
                [
                    ActionParameter(
                        ActionParameterType.NONE,
                        "command",
                        configuration.action.create_action_parameter_domain_any()
                    )
                ],
                PlatformSpecification(PlatformType.EMULATION, "docker+cryton"),
            )
        )

```

This tells the model that action with ID `dojo:local_command_execution` exists and takes one parameter `command`.

### Add action evaluation
To actually make the action do something, we have to create a method that will execute and evaluate it.
```python
    async def process_local_command_execution(self, message: Request, node: Node) -> Tuple[int, Response]:
        command = message.action.parameters["command"].value

        action = LocalCommandExecution(
            message.id,
            message.platform_specific["caller_id"],
            self._external,
            command
        )
        
        await action.execute()

        if not action.is_success():
            return 1, self._messaging.create_response(
                message,
                Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                action.processed_output,
                message.session,
            )

        return 1, self._messaging.create_response(
            message,
            Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
            action.processed_output,
            message.session,
        )

```
