"""Yield for one JSON-RPC response on a caller-owned native HIO client."""

import json


def request_rpc(client, *, request_id, method, params, tymth, timeout, tock):
    """Bound the wait and reject mismatched, failed, or unusable responses."""
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
    if payload.get("id") != request_id or "error" in payload:
        raise ValueError(f"{method} returned an invalid RPC response")
    return payload["result"]
