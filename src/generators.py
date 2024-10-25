import hashlib
from secp import PublicKey

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

q = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)

def hash_to_curve(message: bytes) -> PublicKey:
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            # will error if point does not lie on curve
            return PublicKey(b"\x02" + _hash, raw=True)
        except Exception:
            counter += 1
    # it should never reach this point
    raise ValueError("No valid point found")

# Generators <W, W_, X0, X1, Gv, A, G, H, Gs> drawn with NUMS
W, W_, X0, X1, Gv, A, G, H, Gs = (
    hash_to_curve(b"W"),
    hash_to_curve(b"W_"),
    hash_to_curve(b"X0"),
    hash_to_curve(b"X1"),
    hash_to_curve(b"Gv"),
    hash_to_curve(b"Ga"),
    hash_to_curve(b"G"),
    hash_to_curve(b"H"),
    hash_to_curve(b"Gs"),
)