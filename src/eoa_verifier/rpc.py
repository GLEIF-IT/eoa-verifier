"""Yield for one JSON-RPC response on a caller-owned native HIO client."""

import json


def request_rpc(client, *, request_id, method, params, tymth, timeout, tock):
    """Send one JSON-RPC request on a caller-owned HIO client and return its result.

    The caller schedules and closes the client and allows only one outstanding
    request on it. Yield tock seconds while waiting, using tymth() as the HIO clock.
    timeout is seconds for this call, not an overall association deadline.
    Raise TimeoutError on expiry and ValueError for bad HTTP/envelope/JSON data.
    The request ID must match; method-specific result checks belong to the caller.
    Cancellation leaves client cleanup to its owner.
    """
    client.request(
        method="POST",
        data={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
    )
    deadline = tymth() + timeout
    while not client.responses:
        if tymth() >= deadline:
            raise TimeoutError(f"{method} timed out")
        yield tock
    response = client.responses.popleft()
    if response["status"] != 200:
        raise ValueError(f"{method} HTTP status {response['status']}")
    payload = json.loads(response["body"])
    if (
        not isinstance(payload, dict)
        or payload.get("id") != request_id
        or "error" in payload
        or "result" not in payload
    ):
        raise ValueError(f"{method} returned an invalid RPC response")
    return payload["result"]
