from secp256k1 import PrivateKey, PublicKey

# Constant scalar 0
SCALAR_ZERO = b"\x00"*32
# Constant point to infinity
ELEMENT_ZERO = b"\x02" + b"\x00" * 32

# Order of the curve
q = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)

class Scalar(PrivateKey):

    def __init__(self, data: bytes | None = None):
        if data and data == SCALAR_ZERO:
            self.is_zero = True
        else:
            self.is_zero = False
            super().__init__(data, raw=True)

    def __add__(self, scalar2):
        if isinstance(scalar2, Scalar):
            if scalar2.is_zero:
                return Scalar(self.to_bytes())
            elif self.is_zero:
                return Scalar(scalar2.to_bytes())
            else:
                new_scalar = self.tweak_add(scalar2.to_bytes())
                return Scalar(new_scalar)
        else:
            raise TypeError(f"Cannot add {scalar2.__class__} and Scalar")
    
    def __neg__(self):
        if self.is_zero:
            return Scalar(SCALAR_ZERO)
        s = int.from_bytes(self.to_bytes(), "big")
        s_ = q - s
        return Scalar(s_.to_bytes(32, "big"))

    def __sub__(self, scalar2):
        if isinstance(scalar2, Scalar):
            if scalar2.is_zero:
                return Scalar(self.to_bytes())
            elif self.is_zero:
                return -scalar2
            else:
                new_scalar = self.tweak_add((-scalar2).to_bytes())
                return Scalar(new_scalar)
        else:
            raise TypeError(f"Cannot subtract {scalar2.__class__} and Scalar")

    def __mul__(self, obj):
        if isinstance(obj, Scalar):
            if self.is_zero or obj.is_zero:
                return Scalar(SCALAR_ZERO)
            else:
                new_scalar = self.tweak_mul(obj.to_bytes())
                return Scalar(new_scalar)
        elif isinstance(obj, GroupElement):
            return obj.__mul__(self)
        else:
            raise TypeError(f"Cannot multiply {scalar2.__class__} and Scalar")
    
    def __eq__(self, scalar2):
        if isinstance(scalar2, Scalar):
            return self.to_bytes() == scalar2.to_bytes()
        else:
            raise TypeError(f"Cannot compare {scalar2.__class__} and Scalar")
    
    def to_bytes(self):
        return self.private_key if not self.is_zero else SCALAR_ZERO

# We extend the public key to define some operations on points
# Picked from https://github.com/WTRMQDev/secp256k1-zkp-py/blob/master/secp256k1_zkp/__init__.py
class GroupElement(PublicKey):

    def __init__(self, data: bytes | None = None):
        if data and data == ELEMENT_ZERO:
            self.is_zero = True
        else:
            self.is_zero = False
            super().__init__(data, raw=True)

    def __add__(self, pubkey2):
        if isinstance(pubkey2, GroupElement):
            if pubkey2.is_zero and not self.is_zero:
                return GroupElement(self.serialize(True))
            elif self.is_zero:
                return GroupElement(pubkey2.serialize(True))
            else:
                new_pub = GroupElement()
                new_pub.combine([self.public_key, pubkey2.public_key])
                return new_pub
        else:
            raise TypeError("Cant add pubkey and %s" % pubkey2.__class__)

    def __neg__(self):
        if self.is_zero:
            return GroupElement(ELEMENT_ZERO)
        serialized = self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        # flip odd/even byte
        first_byte = {b"\x03": b"\x02", b"\x02": b"\x03"}[first_byte]
        return GroupElement(first_byte + remainder)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, GroupElement):
            if pubkey2.is_zero and not self.is_zero:
                return GroupElement(self.serialize(True))
            elif self.is_zero:
                return -pubkey2
            else:
                return self + (-pubkey2)  # type: ignore
        else:
            raise TypeError("Can't add element and %s" % pubkey2.__class__)

    def __mul__(self, scalar):
        if isinstance(scalar, Scalar):
            if scalar.is_zero or self.is_zero:
                return GroupElement(ELEMENT_ZERO)
            result = self.tweak_mul(scalar.to_bytes())
            return GroupElement(result.serialize(True))
        else:
            raise TypeError(f"Can't multiply GroupElement with {scalar.__class__}")

    def __eq__(self, el2):
        if isinstance(el2, GroupElement):
            seq1 = self.to_data()
            seq2 = el2.to_data()  # type: ignore
            return seq1 == seq2
        else:
            raise TypeError("Can't compare pubkey and %s" % pubkey2.__class__)

    def serialize(self, compressed = True):
        if self.is_zero:
            return ELEMENT_ZERO
        else:
            return super().serialize(compressed=compressed)

    def to_data(self):
        if self.is_zero:
            return b"\x00" * 64
        assert self.public_key
        return [self.public_key.data[i] for i in range(64)]