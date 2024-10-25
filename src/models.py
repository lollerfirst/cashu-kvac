from secp import PrivateKey, PublicKey
from typing import List, Optional, Dict

# There is some terrible boilerplate here but
# couldn't make pydantic work (skill issue)

class ZKP:
    s: List[bytes]
    c: bytes

    def __init__(self, **kwargs):
        self.w = kwargs.get('w')
        self.c = kwargs.get('c')

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

class CommitmentSet:
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
        return CommitmentSet(
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

class Statement:
    value: PublicKey
    construction: Dict[PublicKey, int]

    def __init__(self, **kwargs):
        self.value = kwargs.get('value')
        self.construction = kwargs.get('construction')