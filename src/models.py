from .secp import GroupElement, Scalar
from typing import List, Optional, Dict, Tuple
from .generators import *

from dataclasses import dataclass

RANGE_LIMIT = 1 << 51

@dataclass
class MintPrivateKey:
    w: Scalar
    w_: Scalar
    x0: Scalar
    x1: Scalar
    ya: Scalar
    ys: Scalar

    _I: Optional[GroupElement] = None
    _Cw: Optional[GroupElement] = None

    @property
    def sk(self):
        return [
            self.w,
            self.w_,
            self.x0,
            self.x1,
            self.ya,
            self.ys,
        ]

    @property
    def Cw(self):
        if not self._Cw:
            self._Cw = W*self.w + W_*self.w_
        return self._Cw

    @property
    def I(self):
        if not self._I:
            self._I = Gz_mac - (
                X0*self.x0
                + X1*self.x1
                + Gz_attribute*self.ya  # amount
                + Gz_script*self.ys     # script
            )
        return self._I

@dataclass
class ZKP:
    s: List[bytes]
    c: bytes

@dataclass
class ScriptAttribute:
    r: Optional[Scalar] = None
    s: Optional[Scalar] = None

    _Ms: Optional[GroupElement] = None

    @classmethod
    def create(
        cls,
        script: bytes,
        blinding_factor: Optional[bytes] = None,
    ):
        """
        Creates a script attribute that encodes the hash of a given script.

        This function takes as input an array of bytes and returns an attribute.

        Parameters:
            script (bytes): The script
            blinding_factor (Optional[bytes]): Optionally a blinding_factor derived from a BIP32 derivation path

        Returns:
            ScriptAttribute: The created attribute.
        """        
        s = Scalar(hashlib.sha256(script).digest())
        r = (
            Scalar(blinding_factor) if blinding_factor
            else Scalar()
        )

        return cls(r, s)
    
    @property
    def Ms(self):
        assert self.r and self.s
        if not self._Ms:
            self._Ms = self.r * G_blind + self.s * G_amount
        return self._Ms

    @property
    def serial(self) -> GroupElement:
        assert self.r, "Serial preimage unknown"
        return self.r * G_serial

@dataclass
class AmountAttribute:
    r: Optional[Scalar] = None
    a: Optional[Scalar] = None

    _Ma: Optional[GroupElement] = None

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
            AmountAttribute: The created attribute.
        """
        
        a = Scalar(amount.to_bytes(32, 'big'))
        r = (
            Scalar(blinding_factor) if blinding_factor
            else Scalar()
        )

        return cls(r, a)
    
    @property
    def Ma(self):
        assert self.r and self.a
        if not self._Ma:
            self._Ma = self.r * G_blind + self.a * G_amount
        return self._Ma

    @classmethod
    def tweak_amount(cls, Ma: GroupElement, delta: int) -> GroupElement:
        d = Scalar(abs(delta).to_bytes(32, 'big'))
        D = d * G_amount if delta >= 0 else -d * G_amount
        return Ma+D

@dataclass
class RandomizedCredentials:
    Ca: GroupElement
    Cs: GroupElement
    Cx0: GroupElement
    Cx1: GroupElement
    Cv: GroupElement

@dataclass
class MAC:
    t: Scalar
    V: GroupElement

    @classmethod
    def generate(
        cls,
        privkey: MintPrivateKey,
        attribute: GroupElement,
        script: Optional[GroupElement] = None,
        t: Optional[Scalar] = None,
    ):
        """
        Generates a MAC for a given attribute and secret key.

        This function takes as input an attribute and a secret key, and returns a MAC that can be used to authenticate the attribute.

        Parameters:
            privkey (MintPrivateKey): The mint's secret parameters.
            attribute (GroupElement): The amount attribute.
            script (GroupElement): The script attribute.
            t (Optional[Scalar])
             
        Returns:
            MAC: The generated MAC.
        """
        if not t:
            t = Scalar()
        sk = privkey.sk
        Ma = attribute
        Ms = script if script else O
        U = hash_to_curve(t.to_bytes())
        V = (
            sk[0] * W
            + sk[2] * U
            + sk[3] * t * U
            + sk[4] * Ma 
            + sk[5] * Ms
        )
        return cls(t=t, V=V)

@dataclass
class Equation:
    value: Optional[GroupElement]
    construction: List[List[GroupElement]]

@dataclass
class Statement:
    domain_separator: bytes
    equations: List[Equation]

@dataclass
class RangeZKP(ZKP):
    B: List[GroupElement]