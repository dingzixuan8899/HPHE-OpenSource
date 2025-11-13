"""
Hybrid Password Hardening Encryption (HPHE) - Python demo (fixed rotation)

Implements (without PPRF):
- Setup & KGen
- Enrollment/Encryption phase (Fig. 3)
- Decryption phase (Fig. 4)
- Server key rotation phase (Fig. 5)

Group:
- 2048-bit safe-prime DH subgroup of order q (p = 2q + 1)

Crypto primitives:
- Hash: SHA-256
- Symmetric: AES-256-GCM (PyCryptodome)
"""

from dataclasses import dataclass
from typing import List, Tuple
import secrets
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ===========================================================
#   Group Parameters (RFC 3526 MODP 2048-bit)
# ===========================================================

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
Q = (P - 1) // 2  # subgroup order
G0 = 2
G = pow(G0, 2, P)  # generator of subgroup of order Q

GROUP_BYTE_LEN = (P.bit_length() + 7) // 8


# ===========================================================
#   Utilities
# ===========================================================

def random_scalar() -> int:
    """Sample random scalar in [1, Q-1]."""
    return secrets.randbelow(Q - 1) + 1


def int_to_bytes(x: int, length: int = None) -> bytes:
    """Encode integer to big-endian bytes (minimal length if not specified)."""
    if length is None:
        if x == 0:
            length = 1
        else:
            length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (left-pad shorter one with zeros)."""
    if len(a) < len(b):
        a = a.rjust(len(b), b"\x00")
    elif len(b) < len(a):
        b = b.rjust(len(a), b"\x00")
    return bytes(x ^ y for x, y in zip(a, b))


def modinv(a: int, m: int) -> int:
    """Modular inverse via extended Euclidean algorithm."""
    a = a % m
    if a == 0:
        raise ValueError("No modular inverse for 0")
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m


# ===========================================================
#   AES-GCM + Key Derivation (replacing PPRF)
# ===========================================================

def derive_file_key(master_k: int, file_index: int) -> bytes:
    """
    Simple per-file KDF: key_i = SHA256( bytes(k) || index ).
    This replaces PPRF in the paper by a standard hash-based KDF.
    """
    material = int_to_bytes(master_k) + file_index.to_bytes(4, "big")
    return hashlib.sha256(material).digest()  # 32 bytes = AES-256 key


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ===========================================================
#   Data Structures
# ===========================================================

@dataclass
class EnrollmentRecord:
    Kcs: int    # k^{dc * ks}
    Qc: int     # k^{uc * qc}
    E: int      # g^{ec}
    Euc: bytes  # uc XOR (PKs^{ec})
    rc: int     # salt


@dataclass
class EncryptedFile:
    index: int
    nonce: bytes
    tag: bytes
    ciphertext: bytes


# ===========================================================
#   Server
# ===========================================================

class HPHEServer:
    def __init__(self):
        # server key pair (ks, PKs = g^{ks})
        self.ks = random_scalar()
        while self.ks == 1:
            self.ks = random_scalar()
        self.PKs = pow(G, self.ks, P)

    # -------- Enrollment: EP2 --------
    def enrollment_step(self, Kc: int) -> int:
        """
        Enrollment step on server:
        Input:  Kc = k^{dc}
        Output: Kcs = Kc^{ks} = k^{dc * ks}
        """
        return pow(Kc, self.ks, P)

    # -------- Decryption: DP2 --------
    def decryption_step(self, Xc: int, Yc: int, Euc: bytes, E: int) -> Tuple[int, int, int]:
        """
        Decryption step on server:
        Input:  Xc = Kcs^{tc}, Yc = Qc^{nc * d'_c}, Euc, E = g^{ec}
        Output: Ys, Xs, ws
        """
        # Recover uc from Euc = uc XOR PKs^{ec} where PKs^{ec} = E^{ks}
        mask = pow(E, self.ks, P)  # E^{ks}
        mask_bytes = int_to_bytes(mask, GROUP_BYTE_LEN)
        uc_bytes = xor_bytes(Euc, mask_bytes)
        uc = bytes_to_int(uc_bytes) % Q
        if uc == 0:
            raise ValueError("Recovered uc == 0, abort session")

        ms = random_scalar()
        uc_inv = modinv(uc, Q)
        ks_inv = modinv(self.ks, Q)

        # Ys = Yc^{ks * ms * uc^{-1}}
        exp_Y = (self.ks * ms * uc_inv) % Q
        Ys = pow(Yc, exp_Y, P)

        # Xs = Xc^{ms * ks^{-1}}
        exp_X = (ms * ks_inv) % Q
        Xs = pow(Xc, exp_X, P)

        ws = (ms * (self.ks - 1)) % Q

        return Ys, Xs, ws

    # -------- Server key rotation (per user record) --------
    def rotate_user_state(self, record: EnrollmentRecord) -> EnrollmentRecord:
        """
        Rotate server key (ks -> ks') and update user state to remain consistent.

        Given old state:
            Kcs = k^{dc * ks}
            Euc = uc XOR E^{ks}
        we want new state:
            Kcs' = k^{dc * ks'}
            Euc' = uc XOR E^{ks'}

        We can do this without knowing k, dc, ec, uc:
        - Use group math to update Kcs
        - Use XOR + E^{ks_old} to recover uc, then XOR with E^{ks_new}
        """
        old_ks = self.ks
        old_PKs = self.PKs
        old_ks_inv = modinv(old_ks, Q)

        # 1) generate new server key pair
        new_ks = random_scalar()
        while new_ks == 1:
            new_ks = random_scalar()
        new_PKs = pow(G, new_ks, P)

        # 2) update Kcs: Kcs' = Kcs^{ks' * ks^{-1}}
        factor = (new_ks * old_ks_inv) % Q
        Kcs_prime = pow(record.Kcs, factor, P)

        # 3) update Euc:
        #    uc = Euc XOR (E^{old_ks})   (because E^{old_ks} = PKs_old^{ec})
        mask_old = pow(record.E, old_ks, P)
        mask_old_bytes = int_to_bytes(mask_old, GROUP_BYTE_LEN)
        uc_bytes = xor_bytes(record.Euc, mask_old_bytes)

        #    Euc' = uc XOR (E^{new_ks})
        mask_new = pow(record.E, new_ks, P)
        mask_new_bytes = int_to_bytes(mask_new, GROUP_BYTE_LEN)
        Euc_prime = xor_bytes(uc_bytes, mask_new_bytes)

        # 4) commit new server key
        self.ks = new_ks
        self.PKs = new_PKs

        # 5) return updated record (Qc, E, rc unchanged)
        return EnrollmentRecord(
            Kcs=Kcs_prime,
            Qc=record.Qc,
            E=record.E,
            Euc=Euc_prime,
            rc=record.rc,
        )


# ===========================================================
#   Client (Service Provider)
# ===========================================================

class HPHEClient:
    def __init__(self, server: HPHEServer):
        # service provider secret key kc
        self.kc = random_scalar()
        self.server = server

    @staticmethod
    def _hash_q(un: str, pw: str, rc: int) -> int:
        """
        qc = H(un || ":" || pw || ":" || rc) mod q
        H: SHA-256
        """
        h = hashlib.sha256()
        h.update(un.encode("utf-8"))
        h.update(b":")
        h.update(pw.encode("utf-8"))
        h.update(b":")
        # NOTE: use automatic length to avoid OverflowError
        h.update(int_to_bytes(rc))
        return bytes_to_int(h.digest()) % Q

    # -------- Enrollment + Encryption (EP1, EP2, EP3) --------
    def enroll_and_encrypt(
        self,
        username: str,
        password: str,
        files: List[bytes],
    ) -> Tuple[EnrollmentRecord, List[EncryptedFile], int]:
        """
        Enrollment + encrypt multiple files.
        Returns:
            record: EnrollmentRecord
            enc_files: encrypted files
            k_true: master key (group element) for debugging / testing only
        """
        # salts and secrets
        rc = random_scalar()
        uc = random_scalar()
        ec = random_scalar()

        # master key k = g^alpha
        alpha = random_scalar()
        k = pow(G, alpha, P)

        qc = self._hash_q(username, password, rc)
        dc = (pow(qc, 2, Q) * self.kc) % Q

        Kc = pow(k, dc, P)               # k^{dc}
        Qc = pow(k, (uc * qc) % Q, P)    # k^{uc * qc}
        E = pow(G, ec, P)                # g^{ec}

        PKs = self.server.PKs
        mask = pow(PKs, ec, P)           # PKs^{ec} = E^{ks}
        mask_bytes = int_to_bytes(mask, GROUP_BYTE_LEN)
        uc_bytes = int_to_bytes(uc, GROUP_BYTE_LEN)
        Euc = xor_bytes(uc_bytes, mask_bytes)

        # send Kc, get Kcs = k^{dc * ks}
        Kcs = self.server.enrollment_step(Kc)

        record = EnrollmentRecord(
            Kcs=Kcs,
            Qc=Qc,
            E=E,
            Euc=Euc,
            rc=rc,
        )

        # encrypt files with AES-GCM using keys derived from k
        enc_files: List[EncryptedFile] = []
        for idx, plaintext in enumerate(files):
            key = derive_file_key(k, idx)
            nonce, tag, ct = aes_gcm_encrypt(key, plaintext)
            enc_files.append(
                EncryptedFile(
                    index=idx,
                    nonce=nonce,
                    tag=tag,
                    ciphertext=ct,
                )
            )

        return record, enc_files, k

    # -------- Decryption (DP1, DP3) --------
    def decrypt(
        self,
        username: str,
        password: str,
        record: EnrollmentRecord,
        enc_files: List[EncryptedFile],
    ) -> List[bytes]:
        """
        Decryption phase:
        - Interact with server to recover master key k (if pw correct)
        - Decrypt all files with derived AES keys.
        """
        Kcs, Qc, E, Euc, rc = record.Kcs, record.Qc, record.E, record.Euc, record.rc

        # DP1: client chooses random t_c, n_c and computes Xc, Yc
        tc = random_scalar()
        nc = random_scalar()

        qc_prime = self._hash_q(username, password, rc)
        d_c_prime = (qc_prime * self.kc) % Q

        Xc = pow(Kcs, tc, P)                  # Xc = Kcs^{tc}
        Yc = pow(Qc, (nc * d_c_prime) % Q, P) # Yc = Qc^{nc * d'_c}

        # DP2: server side
        Ys, Xs, ws = self.server.decryption_step(Xc, Yc, Euc, E)

        # DP3: remove tc, nc and extract k
        Ysc = pow(Ys, modinv(nc, Q), P)  # Ysc = Ys^{nc^{-1}}
        Xsc = pow(Xs, modinv(tc, Q), P)  # Xsc = Xs^{tc^{-1}}

        Xsc_inv = pow(Xsc, P - 2, P)
        Zsc = (Ysc * Xsc_inv) % P

        denom = ((d_c_prime * qc_prime) % Q * ws) % Q
        if denom == 0:
            raise ValueError("Decryption failed: invalid exponent")
        denom_inv = modinv(denom, Q)

        k_recovered = pow(Zsc, denom_inv, P)

        # decrypt files
        plaintexts: List[bytes] = []
        for ef in enc_files:
            key = derive_file_key(k_recovered, ef.index)
            try:
                pt = aes_gcm_decrypt(key, ef.nonce, ef.tag, ef.ciphertext)
            except ValueError:
                # AES-GCM tag check failed: wrong pw or corrupted data
                raise ValueError("Incorrect username/password or corrupted ciphertext")
            plaintexts.append(pt)

        return plaintexts


# ===========================================================
#   Local Test
# ===========================================================

if __name__ == "__main__":
    server = HPHEServer()
    client = HPHEClient(server)

    username = "alice"
    password = "CorrectHorseBatteryStaple"
    wrong_pw = "wrong-password"

    files = [
        b"HPHE file #1 -- test message",
        b"HPHE file #2 -- encryption demo",
    ]

    print("[*] Enrollment + Encryption...")
    record, enc_files, k_true = client.enroll_and_encrypt(username, password, files)
    print("    Master key k =", hex(k_true)[:40], "...")

    print("[*] Decrypt with correct password...")
    pts = client.decrypt(username, password, record, enc_files)
    for i, pt in enumerate(pts):
        print(f"    File {i}:", pt)

    print("[*] Decrypt with WRONG password...")
    try:
        client.decrypt(username, wrong_pw, record, enc_files)
    except Exception as e:
        print("    Expected failure:", e)

    print("[*] Server key rotation (per user record)...")
    record2 = server.rotate_user_state(record)

    print("[*] Decrypt after server key rotation...")
    pts2 = client.decrypt(username, password, record2, enc_files)
    for i, pt in enumerate(pts2):
        print(f"    File {i} after rotation:", pt)
