from secp import PrivateKey, PublicKey
from typing import List, Optional, Dict, Tuple
import generators

# There is some terrible boilerplate here but
# couldn't make pydantic work (skill issue)

class ZKP:
    s: List[bytes]
    c: bytes

    def __init__(self, **kwargs):
        self.s = kwargs.get('s')
        self.c = kwargs.get('c')

# NOTE: Make separate classes for Private and Public stuff
class Attribute:
    r: Optional[PrivateKey]
    a: Optional[PrivateKey]
    Ma: PublicKey

    def __init__(self, **kwargs):
        self.r = kwargs.get('r', None)
        self.a = kwargs.get('a', None)
        self.Ma = kwargs.get('Ma')

    def lose_secrets(self):
        return Attribute(Ma=self.Ma)

    def get_serial(self) -> PublicKey:
        assert self.r is not None, "Serial preimage unknown"
        return generators.Gs.mult(self.r)

    def tweak_amount(self, delta: int):
        d = PrivateKey(abs(delta).to_bytes(32, 'big'), raw=True)
        D = generators.G.mult(d) if delta >= 0 else -G.mult(d)
        return Attribute(
            Ma=self.Ma+D,
            r=self.r,
            a=self.a, # add to this as well
        )

class RandomizedCredentials:
    z: Optional[PrivateKey]
    z0: Optional[PrivateKey]
    Ca: PublicKey
    Cx0: PublicKey
    Cx1: PublicKey
    Cv: PublicKey

    def __init__(self, **kwargs):
        self.z = kwargs.get('z', None)
        self.z0 = kwargs.get('z0', None)
        self.Ca = kwargs.get('Ca')
        self.Cx0 = kwargs.get('Cx0')
        self.Cx1 = kwargs.get('Cx1')
        self.Cv = kwargs.get('Cv')

    def lose_secrets(self):
        return RandomizedCredentials(
            Ca=self.Ca,
            Cx0=self.Cx0,
            Cx1=self.Cx1,
            Cv=self.Cv,
        )

class MAC:
    t: PrivateKey
    V: PublicKey

    def __init__(self, **kwargs):
        self.t = kwargs.get('t')
        self.V = kwargs.get('V')

class Equation:
    value: Optional[PublicKey]
    construction: List[Tuple[PublicKey, int]]

    def __init__(self, **kwargs):
        self.value = kwargs.get('value')
        self.construction = kwargs.get('construction')

Statement = List[Equation]

class RangeZKP(ZKP):
    B: List[PublicKey]
    width: int

    def __init__(self, **kwargs):
        self.B = kwargs.get("B")
        self.width = kwargs.get("width")
        super().__init__(**kwargs)