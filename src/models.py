from secp import PrivateKey, PublicKey
from typing import List, Optional, Dict, Tuple
import generators
from generators import hash_to_curve

from dataclasses import dataclass

RANGE_LIMIT = 1 << 51

@dataclass
class ZKP:
    s: List[bytes]
    c: bytes

# NOTE: Make separate classes for Private and Public stuff
@dataclass
class Attribute:
    r: Optional[PrivateKey] = None
    a: Optional[PrivateKey] = None

    @classmethod
    def create(
        cls,
        amount: int,
        blinding_factor: Optional[bytes] = None,
    ):
        """
        Creates an attribute worth the given amount.

        This function takes as input an amount and returns an attribute that represents the given amount.

        Parameters:
            amount (int): The amount
            blinding_factor (Optional[bytes]): Optionally a blinding_factor derived from a BIP32 derivation path

        Returns:
            Attribute: The created attribute.

        Raises:
            Exception: If the amount is not within the valid range.
        """
        if not 0 <= amount < RANGE_LIMIT:
            raise Exception("how about no?")
        
        # NOTE: It seems like we would also have to remember the amount it was for.
        # Not ideal for recovery.
        a = PrivateKey(amount.to_bytes(32, 'big'), raw=True)
        r = (
            PrivateKey(blinding_factor, raw=True) if blinding_factor
            else PrivateKey()
        )

        return cls(r, a)
    
    @property
    def Ma(self):
        assert self.r and self.a
        return generators.H.mult(self.r) + generators.G.mult(self.a)

    @property
    def serial(self) -> PublicKey:
        assert self.r, "Serial preimage unknown"
        return generators.Gs.mult(self.r)

    @classmethod
    def tweak_amount(cls, Ma: PublicKey, delta: int):
        d = PrivateKey(abs(delta).to_bytes(32, 'big'), raw=True)
        D = generators.G.mult(d) if delta >= 0 else -G.mult(d)
        return Ma+D

@dataclass
class RandomizedCredentials:
    Ca: PublicKey
    Cx0: PublicKey
    Cx1: PublicKey
    Cv: PublicKey
    z: Optional[PrivateKey] = None
    z0: Optional[PrivateKey] = None

    def lose_secrets(self):
        return RandomizedCredentials(
            Ca=self.Ca,
            Cx0=self.Cx0,
            Cx1=self.Cx1,
            Cv=self.Cv,
        )

@dataclass
class MAC:
    t: PrivateKey
    V: PublicKey

    @classmethod
    def generate(
        cls,
        attribute: Attribute,
        sk: List[PrivateKey]
    ):
        """
        Generates a MAC for a given attribute and secret key.

        This function takes as input an attribute and a secret key, and returns a MAC that can be used to authenticate the attribute.

        Parameters:
            attribute (Attribute): The attribute.
            sk (List[PrivateKey]): The secret key.

        Returns:
            MAC: The generated MAC.
        """
        t = PrivateKey()
        Ma = attribute.Ma
        U = hash_to_curve(bytes.fromhex(t.serialize()))
        V = (
            generators.W.mult(sk[0])
            + U.mult(sk[2])
            + U.mult(sk[3]).mult(t)
            + Ma.mult(sk[4]) # + Ms.mult(sk[5])
        )
        return cls(t=t, V=V)

@dataclass
class Equation:
    value: Optional[PublicKey]
    construction: List[Tuple[PublicKey, int]]

Statement = List[Equation]

@dataclass
class RangeZKP(ZKP):
    B: List[PublicKey]
    width: int