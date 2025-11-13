
"""
Hash-based Puncturable Pseudorandom Function (PPRF) implementation.

- Tree structure: GGM + hash-based diffusion chain.
- H_t uses SHA-512, outputs 512 bits, split into two 256-bit child keys.
- Supports:
    * evaluate(x): compute F_k(x)
    * puncture(x): puncture point x
    * puncture_many(S): puncture all points in S
- Internal state only stores the punctured key state (prefix -> node_key),
  and no longer keeps the original master key.
"""

import os
import hashlib
from typing import Dict, Iterable, Optional


class HashBasedPPRF:
    """Hash-based Puncturable PRF.

    Args:
        depth: leaf depth d, supporting domain {0, ..., 2^d - 1}
        master_key: λ-bit master key (32 bytes). If None, os.urandom() is used.

    Security parameter:
        λ = 256 bits, corresponds to half of SHA-512 output.
    """

    LAMBDA_BITS = 256
    LAMBDA_BYTES = LAMBDA_BITS // 8  # 32 bytes

    def __init__(self, depth: int, master_key: Optional[bytes] = None):
        if depth <= 0:
            raise ValueError("depth must be positive")
        self.depth = depth

        if master_key is None:
            master_key = os.urandom(self.LAMBDA_BYTES)
        if len(master_key) != self.LAMBDA_BYTES:
            raise ValueError(f"master_key must be {self.LAMBDA_BYTES} bytes")

        # Punctured key state:
        #   mapping: binary prefix "" / "0" / "01"... -> λ-bit node key (bytes)
        # Initial state: root prefix "" -> master_key
        self._nodes: Dict[str, bytes] = {"": master_key}

    # ---------- Utilities ----------

    @staticmethod
    def _int_to_bits(x: int, length: int) -> str:
        """Convert integer x into a fixed-length binary string."""
        if x < 0:
            raise ValueError("x must be non-negative")
        max_val = 1 << length
        if x >= max_val:
            raise ValueError(f"x must be < {max_val} for depth={length}")
        return format(x, f"0{length}b")

    @staticmethod
    def _bits_to_int(bits: str) -> int:
        return int(bits, 2)

    @classmethod
    def _expand(cls, node_key: bytes) -> (bytes, bytes):
        """One expansion step of the diffusion hash chain.

        Given λ-bit node_key:
            digest = SHA-512(b"PPRF" || node_key)

        Split into:
            left  = digest[:λ/8]  (child for bit=0)
            right = digest[λ/8:]  (child for bit=1)
        """
        digest = hashlib.sha512(b"PPRF" + node_key).digest()
        assert len(digest) == 64  # 512 bits
        left = digest[:cls.LAMBDA_BYTES]
        right = digest[cls.LAMBDA_BYTES:2 * cls.LAMBDA_BYTES]
        return left, right

    def _find_covering_prefix(self, bits: str) -> Optional[str]:
        """Find the longest prefix p in the state that covers leaf bits."""
        best = None
        best_len = -1
        for p in self._nodes.keys():
            if bits.startswith(p) and len(p) > best_len:
                best = p
                best_len = len(p)
        return best

    # ---------- Public API ----------

    def evaluate(self, x: int) -> bytes:
        """Evaluate F_k*(x).

        Raises KeyError if x has been punctured.
        """
        bits = self._int_to_bits(x, self.depth)
        p = self._find_covering_prefix(bits)
        if p is None:
            raise KeyError("point is punctured")

        key = self._nodes[p]

        # Extend from prefix p down to leaf
        for b in bits[len(p):]:
            left, right = self._expand(key)
            key = left if b == "0" else right
        return key

    def puncture(self, x: int) -> None:
        """Puncture point x.

        Algorithm:
          1. Find prefix p in state covering x and get its node key.
          2. Remove p.
          3. Walk down the path toward x:
                - expand into (left, right)
                - insert sibling branch into state
                - continue walking down the path branch
          4. Do NOT store the final leaf key → x becomes punctured.
        """
        bits = self._int_to_bits(x, self.depth)
        p = self._find_covering_prefix(bits)
        if p is None:
            return  # already punctured

        node_key = self._nodes.pop(p)

        prefix = p
        key = node_key

        # Walk from depth len(p) to depth=self.depth
        for i in range(len(p), self.depth):
            bit = bits[i]
            left, right = self._expand(key)

            if bit == "0":
                sibling_prefix = prefix + "1"
                sibling_key = right
                prefix = prefix + "0"
                key = left
            else:
                sibling_prefix = prefix + "0"
                sibling_key = left
                prefix = prefix + "1"
                key = right

            self._nodes.setdefault(sibling_prefix, sibling_key)

        # Final prefix == bits: do NOT store → punctured!

    def puncture_many(self, xs: Iterable[int]) -> None:
        """Puncture every point in S."""
        for x in xs:
            self.puncture(x)

    def is_punctured(self, x: int) -> bool:
        """Return True if x has been punctured."""
        bits = self._int_to_bits(x, self.depth)
        return self._find_covering_prefix(bits) is None

    def export_state(self) -> Dict[str, str]:
        """Export current punctured key state for serialization.

        Returns:
            { prefix (str such as '010'): node_key_hex (str) }
        """
        return {p: k.hex() for p, k in self._nodes.items()}

    @classmethod
    def from_state(cls, depth: int, state: Dict[str, str]) -> "HashBasedPPRF":
        """Reconstruct an instance from an exported state."""
        obj = cls.__new__(cls)
        obj.depth = depth
        obj._nodes = {p: bytes.fromhex(h) for p, h in state.items()}
        return obj


# ------------------- Demo -------------------

def _demo():
    print("Hash-based PPRF")
    depth = 4  # supports leaf domain 0..15
    pprf = HashBasedPPRF(depth)

    # Evaluate several points
    v3 = pprf.evaluate(3)
    v7 = pprf.evaluate(7)
    print("F(3) =", v3.hex())
    print("F(7) =", v7.hex())

    # Puncture point 7
    pprf.puncture(7)
    print("After puncturing 7:")
    print("punctured(7):", pprf.is_punctured(7))
    print("F(3) still works:", pprf.evaluate(3).hex())

    # Attempting to evaluate a punctured point
    try:
        pprf.evaluate(7)
    except KeyError:
        print("F(7) is no longer available (punctured).")

    # Export/import state test
    state = pprf.export_state()
    restored = HashBasedPPRF.from_state(depth, state)
    assert restored.evaluate(3) == pprf.evaluate(3)
    assert restored.is_punctured(7)
    print("State export/import OK.")


if __name__ == "__main__":
    _demo()
