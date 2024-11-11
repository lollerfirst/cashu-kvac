from secp import GroupElement, Scalar
from typing import List, Optional, Dict, Tuple
from generators import *

from dataclasses import dataclass

RANGE_LIMIT = 1 << 51

@dataclass
class MintPrivateKey:
    w: Scalar
    w_: Scalar
    x0: Scalar
    x1: Scalar
    ya: Scalar
    yf: Scalar

    @property
    def sk(self):
        return [
            self.w,
            self.w_,
            self.x0,
            self.x1,
            self.ya,
            #self.yf,
        ]

    @property
    def Cw(self):
        return W*self.w + W_*self.w_

    @property
    def I(self):
        return G_mac - (
            X0*self.x0
            + X1*self.x1
            + G_rand*self.ya  # satoshis
            #+ generators.F*self.yf  # script
        )

@dataclass
class ZKP:
    s: List[bytes]
    c: bytes

@dataclass
class Attribute:
    r: Optional[Scalar] = None
    a: Optional[Scalar] = None

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
        
        a = Scalar(amount.to_bytes(32, 'big'))
        r = (
            Scalar(blinding_factor) if blinding_factor
            else Scalar()
        )

        return cls(r, a)
    
    @property
    def Ma(self):
        assert self.r and self.a
        return self.r * G_blind + self.a * G_amount

    @property
    def serial(self) -> GroupElement:
        assert self.r, "Serial preimage unknown"
        return self.r * G_serial

    @classmethod
    def tweak_amount(cls, Ma: GroupElement, delta: int):
        d = Scalar(abs(delta).to_bytes(32, 'big'))
        D = d * G_amount if delta >= 0 else -d * G_amount
        return Ma+D

@dataclass
class RandomizedCredentials:
    Ca: GroupElement
    Cx0: GroupElement
    Cx1: GroupElement
    Cv: GroupElement
    z: Optional[Scalar] = None
    z0: Optional[Scalar] = None

    def lose_secrets(self):
        return RandomizedCredentials(
            Ca=self.Ca,
            Cx0=self.Cx0,
            Cx1=self.Cx1,
            Cv=self.Cv,
        )

@dataclass
class MAC:
    t: Scalar
    V: GroupElement

    @classmethod
    def generate(
        cls,
        attribute: GroupElement,
        privkey: MintPrivateKey,
        t: Optional[Scalar] = None,
    ):
        """
        Generates a MAC for a given attribute and secret key.

        This function takes as input an attribute and a secret key, and returns a MAC that can be used to authenticate the attribute.

        Parameters:
            attribute (GroupElement): The attribute.
            privkey (MintPrivateKey): The mint's secret parameters.
            t (Optional[Scalar])

        Returns:
            MAC: The generated MAC.
        """
        if not t:
            t = Scalar()
        sk = privkey.sk
        Ma = attribute
        U = hash_to_curve(t.to_bytes())
        V = (
            sk[0] * W
            + sk[2] * U
            + sk[3] * t * U
            + sk[4] * Ma 
            #+ sk[5] * Ms
        )
        return cls(t=t, V=V)

@dataclass
class Equation:
    value: Optional[GroupElement]
    construction: List[GroupElement]

Statement = List[Equation]

@dataclass
class RangeZKP(ZKP):
    B: List[GroupElement]