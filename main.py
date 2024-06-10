#!/usr/bin/env python

import asyncio
import websockets
import json
from urllib.parse import urlparse

from event import EncryptedDirectMessage, Event
from key import PrivateKey

################################################################################
# Configuration                                                                #
################################################################################

# Paste your connection string here:
nwc_connection_str = "nostr+walletconnect://69effe7b49a6dd5cf525bd0905917a5005ffe480b58eeb8e861418cf3ae760d9?relay=wss://relay.getalby.com/v1&secret=6bb472f045e4d30e678da466a3fad2f150003c1fbd4d396da42b471ffdd23620&lud16=onthedeklein@getalby.com"

# Change these as needed to trigger call a different method with different parameters.
# TODO: Move this to cli params
nwc_method = "get_balance"
nwc_params = {}

################################################################################


nwc_connection_uri = urlparse(nwc_connection_str)
query = dict([part.split("=") for part in nwc_connection_uri.query.split("&")])
relay = query["relay"]
secret = query["secret"]
lud16 = query["lud16"]
wallet_pubkey = nwc_connection_uri.hostname
private_key = PrivateKey(bytes.fromhex(secret))


async def run():
    async with websockets.connect(relay, ssl=True) as websocket:
        print("Connected to", relay)

        resp = await send_nwc_message(websocket, nwc_method, nwc_params)

        print(f"Received: {json.dumps(resp, indent=2)}")


async def send_nwc_message(
    websocket: websockets.WebSocketClientProtocol, method, params
):
    event = EncryptedDirectMessage(
        kind=23194,
        recipient_pubkey=wallet_pubkey,
        cleartext_content=json.dumps({"method": method, "params": params}),
    )
    private_key.encrypt_dm(event)
    private_key.sign_event(event)
    await websocket.send(event.to_message())
    await websocket.send(
        json.dumps(
            [
                "REQ",
                f"resp-{event.id}",
                {"authors": [wallet_pubkey], "kinds": [23195], "#e": [event.id]},
            ]
        )
    )
    attempts = 0
    while attempts < 5:
        resp = json.loads(await websocket.recv())
        # print(f"Received: {json.dumps(resp, indent=2)}")
        if resp[0] == "EVENT":
            break
        attempts += 1
    resp_event = Event.from_message(resp)
    if not resp_event.verify():
        raise Exception("Failed to verify response event")
    decrypted_content = private_key.decrypt_message(
        resp_event.content, resp_event.public_key
    )
    return json.loads(decrypted_content)


if __name__ == "__main__":
    asyncio.run(run())
