import hashlib
from secp import GroupElement, ELEMENT_ZERO

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

def hash_to_curve(message: bytes) -> GroupElement:
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            # will error if point does not lie on curve
            return GroupElement(b"\x02" + _hash)
        except Exception:
            counter += 1
    # it should never reach this point
    raise ValueError("No valid point found")

# Generators drawn with NUMS
W, W_, X0, X1, G_mac, Gz_attribute, Gz_script, G_amount, G_script, G_blind, G_serial = (
    hash_to_curve(b"W"),
    hash_to_curve(b"W_"),
    hash_to_curve(b"X0"),
    hash_to_curve(b"X1"),
    hash_to_curve(b"G_mac"),
    hash_to_curve(b"Gz_attribute"),
    hash_to_curve(b"Gz_script"),
    hash_to_curve(b"G_amount"),
    hash_to_curve(b"G_script"),
    hash_to_curve(b"G_blind"),
    hash_to_curve(b"G_serial"),
)

# Point at infinity
O = GroupElement(ELEMENT_ZERO)
