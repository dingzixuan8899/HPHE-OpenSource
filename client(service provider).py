# hphe_client_ws.py
#
# Hybrid PHE - Service Provider side over WebSocket
#
# This client connects to the PH server via WebSocket and runs:
#   1) Enrollment + Encryption
#   2) Decryption with correct password
#   3) Decryption with wrong password
#
# Run:
#   python hphe_client_ws.py
#
# Note: The server hphe_server_ws.py must be running first.

import asyncio
import secrets
import hashlib
import json
from dataclasses import dataclass

import websockets

# ---------- Group and hash utilities (must match server side) ----------

P = 2**255 - 19
Q = P
G = 2


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
    if a % mod == 0:
        raise ZeroDivisionError("No modular inverse for 0")
    return pow(a, -1, mod)


def k_to_symmetric_key(k_elem: int, key_len: int = 32) -> bytes:
    """
    Derive a symmetric key from a group element k_elem.
    For demo purposes, this is just SHA-256(k_elem) truncated.
    """
    h = hashlib.sha256(int_to_bytes(k_elem)).digest()
    if key_len <= len(h):
        return h[:key_len]
    return (h * ((key_len + len(h) - 1) // len(h)))[:key_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class EnrollmentRecord:
    """
    Enrollment record T = {Kcs, Qc, E, Euc, rc}.
    In a real system you would also bind this to a user ID.
    """
    Kcs: int
    Qc: int
    E: int
    Euc: int
    rc: int


class ServiceProvider:
    def __init__(self, kc: int | None = None, server_pub_params: dict | None = None):
        """
        kc: client-side secret key
        server_pub_params: public parameters from server (contains PKs, p, q, g)
        """
        self.kc = kc or secrets.randbelow(Q - 1) + 1

        if server_pub_params is None:
            raise ValueError("server_pub_params must be provided")
        self.PKs = int(server_pub_params["PKs"])
        assert server_pub_params["p"] == P
        assert server_pub_params["q"] == Q
        assert server_pub_params["g"] == G

    # ===== Enrollment + Encryption over WebSocket =====

    async def enroll_and_encrypt(self, username: str, password: str, websocket) -> tuple[EnrollmentRecord, bytes, bytes]:
        """
        Enrollment/Encryption phase over WebSocket.
        1) Locally generate k, qc, dc, Kc, Qc, E, Euc.
        2) Send Kc to server (enrollment_step2), receive Kcs.
        3) Use k to derive a symmetric key and encrypt a demo "file".
        """
        # Step EP1: generate random values
        rc = secrets.randbelow(Q - 1) + 1
        uc = secrets.randbelow(Q - 1) + 1
        ec = secrets.randbelow(Q - 1) + 1
        k = secrets.randbelow(P - 2) + 2  # master group element

        # qc = H(username || password || rc)
        data = username.encode("utf-8") + b"|" + password.encode("utf-8") + b"|" + int_to_bytes(rc)
        qc = H_to_Zq(data)

        # dc = qc^2 * kc mod q
        dc = (qc * qc * self.kc) % Q

        # Kc = k^{dc}
        Kc = pow(k, dc, P)

        # E = g^{ec}
        E = pow(G, ec, P)

        # Qc = k^{uc * qc}
        exponent_Q = (uc * qc) % Q
        Qc = pow(k, exponent_Q, P)

        # Euc = uc XOR H(PKs^{ec})
        shared = pow(self.PKs, ec, P)
        mask = H_group_elem(shared) % Q
        Euc = uc ^ mask

        # Send EP2 to server
        req = {
            "type": "enrollment_step2",
            "Kc": Kc,
        }
        await websocket.send(json.dumps(req))
        resp_raw = await websocket.recv()
        resp = json.loads(resp_raw)

        if resp.get("type") != "enrollment_step2_resp":
            raise RuntimeError("Unexpected response type in enrollment_step2")

        Kcs = int(resp["Kcs"])

        # Build enrollment record
        T = EnrollmentRecord(Kcs=Kcs, Qc=Qc, E=E, Euc=Euc, rc=rc)

        # Derive symmetric key from k
        sym_key = k_to_symmetric_key(k)

        # Simple demo "encryption": XOR with hash(sym_key || "file1")
        plaintext = b"example file content for HPHE WebSocket demo"
        keystream = hashlib.sha256(sym_key + b"file1").digest()
        ciphertext = xor_bytes(plaintext, keystream[:len(plaintext)])

        return T, sym_key, ciphertext

    # ===== Decryption over WebSocket =====

    async def decrypt(self, username: str, password: str, T: EnrollmentRecord, ciphertext: bytes, websocket) -> tuple[bool, bytes | None]:
        """
        Decryption phase over WebSocket.
        Uses T and user-provided (username, password) to recover k
        and then decrypt the ciphertext.
        """
        Kcs = T.Kcs
        Qc = T.Qc
        E = T.E
        Euc = T.Euc
        rc = T.rc

        # DP1: local randomness
        tc = secrets.randbelow(Q - 1) + 1
        nc = secrets.randbelow(Q - 1) + 1

        # q'_c = H(username' || password' || rc)
        data = username.encode("utf-8") + b"|" + password.encode("utf-8") + b"|" + int_to_bytes(rc)
        q_prime = H_to_Zq(data)

        # d'_c = q'_c * kc
        d_prime = (q_prime * self.kc) % Q
        if d_prime == 0:
            d_prime = 1

        # Xc = Kcs^{tc}
        Xc = pow(Kcs, tc, P)

        # Yc = Qc^{nc * d'_c}
        exponent_Yc = (nc * d_prime) % Q
        Yc = pow(Qc, exponent_Yc, P)

        # Send DP2 to server
        req = {
            "type": "decryption_step2",
            "Xc": Xc,
            "Yc": Yc,
            "E": E,
            "Euc": Euc,
        }
        await websocket.send(json.dumps(req))
        resp_raw = await websocket.recv()
        resp = json.loads(resp_raw)

        if resp.get("type") != "decryption_step2_resp":
            raise RuntimeError("Unexpected response type in decryption_step2")

        Ys = int(resp["Ys"])
        Xs = int(resp["Xs"])
        ws = int(resp["ws"])

        # DP3: remove tc, nc to get Zsc
        Ysc = pow(Ys, modinv(nc, Q), P)
        Xsc = pow(Xs, modinv(tc, Q), P)
        Zsc = (Ysc * modinv(Xsc, P)) % P

        # Recover k from Zsc
        exponent = (d_prime * q_prime * ws) % Q
        if exponent == 0:
            return False, None

        inv_exponent = modinv(exponent, Q)
        k_recovered = pow(Zsc, inv_exponent, P)

        # Derive symmetric key and decrypt
        sym_key = k_to_symmetric_key(k_recovered)
        keystream = hashlib.sha256(sym_key + b"file1").digest()
        plaintext = xor_bytes(ciphertext, keystream[:len(ciphertext)])

        # In a real system, you would verify correctness using MAC or file format.
        # Here we just return success.
        return True, plaintext


# ---------- Client main (demo) ----------

async def main():
    uri = "ws://localhost:8765"
    print(f"[Client] Connecting to {uri} ...")
    async with websockets.connect(uri) as websocket:
        print("[Client] Connected to server")

        # 1) Ask for public parameters
        req = {"type": "get_public_params"}
        await websocket.send(json.dumps(req))
        resp_raw = await websocket.recv()
        resp = json.loads(resp_raw)

        if resp.get("type") != "public_params":
            raise RuntimeError("Unexpected response type for public_params")

        pub_params = resp["params"]
        print("[Client] Received public parameters from server")

        # 2) Initialize Service Provider with server public params
        sp = ServiceProvider(server_pub_params=pub_params)

        username = "alice"
        password = "correct horse battery staple"

        # 3) Enrollment + Encryption over WebSocket
        print("[Client] Starting enrollment and encryption ...")
        T, sym_key, ciphertext = await sp.enroll_and_encrypt(username, password, websocket)
        print("[Client] Enrollment finished")
        print("[Client] Ciphertext (hex) =", ciphertext.hex())

        # 4) Decrypt with correct password
        print("[Client] Decryption with correct password ...")
        ok, plaintext = await sp.decrypt(username, password, T, ciphertext, websocket)
        print("[Client] Decryption success:", ok)
        if ok and plaintext is not None:
            print("[Client] Plaintext =", plaintext)

        # 5) Decrypt with wrong password
        print("[Client] Decryption with wrong password ...")
        ok2, plaintext2 = await sp.decrypt(username, "wrong password", T, ciphertext, websocket)
        print("[Client] Decryption success:", ok2)
        if ok2 and plaintext2 is not None:
            print("[Client] Plaintext with wrong password =", plaintext2)


if __name__ == "__main__":
    asyncio.run(main())
