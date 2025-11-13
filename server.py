# hphe_server_ws.py
#
# Hybrid PHE - PH Server side over WebSocket
# This server talks to a Service Provider client via JSON messages.
#
# Protocol (message "type"):
#   - "get_public_params" -> respond with "public_params"
#   - "enrollment_step2"  -> respond with "enrollment_step2_resp"
#   - "decryption_step2"  -> respond with "decryption_step2_resp"
#
# Run:
#   python hphe_server_ws.py
#
# Then run: hphe_client_ws.py in another process.

import asyncio
import secrets
import hashlib
import json

import websockets


# ---------- Group and hash utilities (must match client side) ----------

P = 2**255 - 19  # prime modulus for multiplicative group
Q = P           # exponent group Z_q
G = 2           # generator


def int_to_bytes(x: int) -> bytes:
    if x < 0:
        raise ValueError("int_to_bytes only supports non-negative integers")
    length = (x.bit_length() + 7) // 8 or 1
    return x.to_bytes(length, "big")


def H_to_Zq(data: bytes) -> int:
    """Hash {0,1}* to Z_q using SHA-256."""
    h = hashlib.sha256(data).digest()
    v = int.from_bytes(h, "big") % Q
    if v == 0:
        v = 1
    return v


def H_group_elem(elem: int) -> int:
    """Hash a group element to Z_q."""
    return H_to_Zq(int_to_bytes(elem))


def modinv(a: int, mod: int) -> int:
    """Modular inverse in Z_mod."""
    if a % mod == 0:
        raise ZeroDivisionError("No modular inverse for 0")
    return pow(a, -1, mod)


# ---------- PH Server core logic ----------

class PHServer:
    def __init__(self, ks: int | None = None):
        """
        ks: secret key in Z_q; PKs = g^ks mod p is public key
        """
        self.ks = ks or secrets.randbelow(Q - 1) + 1
        self.PKs = pow(G, self.ks, P)

    def get_public_params(self) -> dict:
        """Return public parameters to the client."""
        return {
            "p": P,
            "q": Q,
            "g": G,
            "PKs": self.PKs,
        }

    def handle_enrollment_step2(self, msg: dict) -> dict:
        """
        EP2: receive Kc, return Kcs = Kc^ks.
        Message in:  { "Kc": int }
        Message out: { "Kcs": int }
        """
        Kc = int(msg["Kc"])
        Kcs = pow(Kc, self.ks, P)
        return {"Kcs": Kcs}

    def handle_decryption_step2(self, msg: dict) -> dict:
        """
        DP2: receive {Xc, Yc, E, Euc}, return {Ys, Xs, ws}.
        """
        Xc = int(msg["Xc"])
        Yc = int(msg["Yc"])
        E = int(msg["E"])
        Euc = int(msg["Euc"])

        # Recover uc using E and ks
        shared = pow(E, self.ks, P)   # = PKs^{ec}
        mask = H_group_elem(shared) % Q
        uc = Euc ^ mask
        if uc == 0:
            uc = 1

        # Pick random ms in Z_q*
        ms = secrets.randbelow(Q - 1) + 1

        # Compute Ys, Xs, ws as in the protocol
        exponent_Y = (self.ks * ms * modinv(uc, Q)) % Q
        Ys = pow(Yc, exponent_Y, P)

        exponent_X = (ms * modinv(self.ks, Q)) % Q
        Xs = pow(Xc, exponent_X, P)

        ws = (ms * (self.ks - 1)) % Q

        return {
            "Ys": Ys,
            "Xs": Xs,
            "ws": ws,
        }


# ---------- WebSocket server handler ----------

async def handle_connection(websocket):
    server = PHServer()
    print("[Server] New client connected")

    # Loop to handle multiple requests from the same client
    async for message in websocket:
        try:
            req = json.loads(message)
        except json.JSONDecodeError:
            print("[Server] Received invalid JSON")
            continue

        msg_type = req.get("type")
        resp: dict

        if msg_type == "get_public_params":
            resp = {
                "type": "public_params",
                "params": server.get_public_params(),
            }

        elif msg_type == "enrollment_step2":
            # expects: { "type": "...", "Kc": ... }
            result = server.handle_enrollment_step2(req)
            resp = {
                "type": "enrollment_step2_resp",
                "Kcs": result["Kcs"],
            }

        elif msg_type == "decryption_step2":
            # expects: { "type": "...", "Xc":..., "Yc":..., "E":..., "Euc":... }
            result = server.handle_decryption_step2(req)
            resp = {
                "type": "decryption_step2_resp",
                "Ys": result["Ys"],
                "Xs": result["Xs"],
                "ws": result["ws"],
            }

        else:
            print(f"[Server] Unknown message type: {msg_type}")
            resp = {
                "type": "error",
                "error": "Unknown message type",
            }

        await websocket.send(json.dumps(resp))

    print("[Server] Client disconnected")


async def main():
    host = "localhost"
    port = 8765
    print(f"[Server] Starting WebSocket server at ws://{host}:{port}")
    async with websockets.serve(handle_connection, host, port):
        print("[Server] Server is running, waiting for clients...")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
