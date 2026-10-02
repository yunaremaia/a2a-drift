"""A2A method request-schema validation.

The JSON-RPC 2.0 transport tells us nothing about what belongs *inside*
``params`` — that is the A2A layer's job. A conformance tool that only checks
the envelope will happily send ``tasks/get`` with no task id and report the
endpoint's perfectly correct ``-32602`` reply as proof of compliance.

Field names come from the A2A JSON-RPC payloads, not from guesswork:

- ``TaskIdParams`` (``tasks/get``, ``tasks/cancel``) requires ``id: string``.
- ``MessageSendParams`` requires ``message``, and ``Message`` requires
  ``messageId``, ``role`` (``"user"`` or ``"agent"``) and a non-empty ``parts``.

A schema built from invented names is worse than no schema: it reports working
endpoints as broken, and a tool that cries wolf gets ignored.
"""

from typing import Any, Optional

# Methods whose payload is TaskIdParams: a task identifier and optional metadata.
TASK_ID_METHODS = ("tasks/get", "tasks/cancel")

# Every method this package has a schema for. A method outside this set is
# never reported on: probe() sends any JSON-RPC method name, and inventing
# requirements for one would be a guess dressed up as a finding.
SCHEMA_METHODS = TASK_ID_METHODS + ("message/send",)

# MessageSendParams.message, in the order the spec lists them, so the findings
# read in the same order as the payload they are about.
MESSAGE_FIELDS = ("messageId", "role", "parts")

# Message.role is a closed enum in the spec, not an arbitrary string.
MESSAGE_ROLES = ("user", "agent")


def _validate_task_id(method: str, params: dict[str, Any]) -> list[str]:
    """Check a TaskIdParams payload: one required, non-empty ``id``."""
    if "id" not in params:
        return [f"params.id is required by method '{method}'"]

    task_id = params["id"]
    if not isinstance(task_id, str) or not task_id:
        return [f"params.id must be a non-empty string, got {task_id!r}"]

    return []


def _validate_message_send(method: str, params: dict[str, Any]) -> list[str]:
    """Check a MessageSendParams payload and the Message it must carry."""
    if "message" not in params:
        return [f"params.message is required by method '{method}'"]

    message = params["message"]
    if not isinstance(message, dict):
        return [f"params.message must be a JSON object, got {type(message).__name__}"]

    errors = []
    for field in MESSAGE_FIELDS:
        if field not in message:
            errors.append(f"params.message.{field} is required by method '{method}'")

    # Check values only for fields that are present. A missing 'role' is
    # already reported above, and a second finding would say the same thing
    # twice in different words.
    if "role" in message and message["role"] not in MESSAGE_ROLES:
        errors.append(
            f"params.message.role must be 'user' or 'agent', got {message['role']!r}"
        )

    if "parts" in message and (
        not isinstance(message["parts"], list) or not message["parts"]
    ):
        errors.append("params.message.parts must be a non-empty array")

    return errors


def validate_method_request(method: str, params: Optional[object]) -> list[str]:
    """Return one message per schema violation in a method's request params.

    An empty list means the request satisfies the method's schema. Only the
    methods in :data:`SCHEMA_METHODS` are checked; anything else returns empty.
    """
    if method not in SCHEMA_METHODS:
        return []

    # Normalise before validating: --params '[1, 2]' parses to a list, and
    # reporting every field as missing would be true and useless.
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return [f"params must be a JSON object, got {type(params).__name__}"]

    if method == "message/send":
        return _validate_message_send(method, params)
    return _validate_task_id(method, params)
