from secp import PrivateKey, PublicKey
from models import ZKP, Attribute, CommitmentSet, MAC, Statement
import hashlib

from typing import Tuple, List, Optional
from enum import Enum

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
RANGE_LIMIT = 1 << 51

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

# Mint's secret key <w, w_, x0, x1, ya>
w, w_, x0, x1, ya = [PrivateKey() for _ in range(5)]
sk = (w, w_, x0, x1, ya)

# Mint iparams <Cw, I> 
Cw = W.mult(w) + W_.mult(w_)
I = Gv + -(X0.mult(x0) + X1.mult(x1) + A.mult(ya))
iparams = (Cw, I)

class LinearRelationMode(Enum):
    PROVE = 0
    VERIFY = 1

    @property
    def isProve(self):
        return self == LinearRelationMode.PROVE
    
    @property
    def isVerify(self):
        return self == LinearRelationMode.VERIFY

class LinearRelationProverVerifier:
    random_terms: List[PrivateKey]  # k1, k2, ...
    challenge_preimage: bytes
    secrets: List[PrivateKey]
    responses: List[PrivateKey]
    c: PrivateKey
    mode: LinearRelationMode

    def __init__(self,
        mode: LinearRelationMode,
        secrets: Optional[List[PrivateKey]] = None,
        proof: Optional[ZKP] = None,
    ):
        match mode:
            case LinearRelationMode.PROVE:
                assert secrets is not None, "mode is PROVE but no secrets provided"
                self.secrets = secrets
                self.random_terms = [PrivateKey() for _ in secrets]
            case LinearRelationMode.VERIFY:
                assert proof is not None, "mode is VERIFY but no ZKP provided"
                self.responses = [PrivateKey(s, raw=True) for s in proof.s]
                self.c = PrivateKey(proof.c, raw=True)
            case _:
                raise Exception("unrecognized mode")

        self.challenge_preimage = b""
        self.mode = mode

    def add_statement(self, statement: Statement):
        R = G
        V = statement.value

        if self.mode.isProve:
            for P, index in statement.construction.items():
                assert 0 <= index < len(self.random_terms), f"index {index} not within range"
                R += P.mult(self.random_terms[index])
        elif self.mode.isVerify:
            for P, index in statement.construction.items():
                assert 0 <= index < len(self.responses), f"index {index} not within range"
                R += P.mult(self.witnesses[index])
            R += -V.mult(self.c)

        R += -G
        # NOTE: No domain separation?
        self.challenge_preimage += V.serialize(True) + R.serialize(True)
    
    def prove(self,
        add_to_challenge: Optional[List[PublicKey]] = None
    ) -> ZKP:
        assert self.mode.isProve, "mode is not PROVE!"

        if add_to_challenge is not None:
            for E in add_to_challenge:
                self.challenge_preimage += E.serialize(True)

        c = PrivateKey(
            hashlib.sha256(self.challenge_preimage).digest(),
            raw=True
        )
        s = [k.tweak_add(
            c.tweak_mul(
                s.private_key
            )
        ) for k, s in zip(self.random_terms, self.secrets)]
        
        return ZKP(s=s, c=c.private_key)

    def verify(self,
        add_to_challenge: Optional[List[PublicKey]] = None
    ) -> bool:
        assert self.mode.isVerify, "mode is not VERIFY!"

        if add_to_challenge is not None:
            for E in add_to_challenge:
                self.challenge_preimage += E.serialize(True)

        c_ = PrivateKey(
            hashlib.sha256(self.challenge_preimage).digest(),
            raw=True
        )

        return self.c.private_key == c_.private_key

def prove_iparams(
    sk: List[PrivateKey],
    attribute: Attribute,
    mac: MAC,
) -> ZKP:
    '''
        Computes a proof that (t, V) was generated with correct iparameters <Cw, I> and
        the attribute Ma
    '''

    Ma = attribute.Ma
    V = mac.V
    t = mac.t
    U = hash_to_curve(t.private_key)

    # Derive params from secret key
    Cw = W.mult(sk[0]) + W_.mult(sk[1])
    I = Gv + -(X0.mult(sk[2]) + X1.mult(sk[3]) + A.mult(sk[4]))

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=sk,
    )
    prover.add_statement(Statement(         # Cw = w*W  + w_*W_
        value=Cw,
        construction={
            W: 0,
            W_: 1,
        },
    ))
    prover.add_statement(Statement(         # I = Gv - x0*X0 - x1*X1 - ya*A 
        value=(-I)+Gv,
        construction={
            X0: 2,
            X1: 3,
            A: 4
        }
    ))
    prover.add_statement(Statement(         # V = w*W + x0*U + x1*t*U + ya*Ma
        value=V,
        construction={
            W: 0,
            U: 2,
            U.mult(t): 3,
            Ma: 4,
        }
    ))

    return prover.prove()

def verify_iparams(
    attribute: Attribute,
    mac: MAC,
    iparams: Tuple[PublicKey, PublicKey],
    proof: ZKP,
) -> bool:
    '''
        Verifies that (t, V) is a credential generated from Ma and <Cw, I>
    '''
    Cw, I = iparams
    Ma = attribute.Ma
    t = mac.t
    V = mac.V
    U = hash_to_curve(t.private_key)

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement(Statement(         # Cw = w*W  + w_*W_
        value=Cw,
        construction={
            W: 0,
            W_: 1,
        },
    ))
    verifier.add_statement(Statement(         # I = Gv - x0*X0 - x1*X1 - ya*A 
        value=(-I)+Gv,
        construction={
            X0: 2,
            X1: 3,
            A: 4
        }
    ))
    verifier.add_statement(Statement(         # V = w*W + x0*U + x1*t*U + ya*Ma
        value=V,
        construction={
            W: 0,
            U: 2,
            U.mult(t): 3,
            Ma: 4,
        }
    ))

    return verifier.verify()

def generate_MAC(
    attribute: Attribute,
    sk: List[PrivateKey]
) -> MAC:
    '''
        Generates a credential for a given attribute
    '''
    t = PrivateKey()
    Ma = attribute.Ma
    U = hash_to_curve(bytes.fromhex(t.serialize()))
    V = W.mult(sk[0]) + U.mult(sk[2]) + U.mult(sk[3]).mult(t) + Ma.mult(sk[4])
    return MAC(t=t, V=V)

def create_attribute(
    amount: int
) -> Attribute:
    '''
        Creates an attribute worth `amount`
    '''
    if not 0 <= amount < RANGE_LIMIT:
        raise Exception("how about no?")
    
    # NOTE: It seems like we would also have to remember the amount it was for.
    # Not ideal for recovery.
    a = PrivateKey(amount.to_bytes(32, 'big'), raw=True)
    r = PrivateKey()

    return Attribute(
        r=r,
        a=a,
        Ma=H.mult(r) + G.mult(a)
    )

def randomize_commitment(
    attribute: Attribute,
    mac: MAC
) -> CommitmentSet:
    t = mac.t
    V = mac.V
    Ma = attribute.Ma
    U = hash_to_curve(t.private_key)
    z = PrivateKey()

    z_num = int.from_bytes(z.private_key, 'big')
    t_num = int.from_bytes(t.private_key, 'big')
    z0_num = q - ((z_num*t_num) % q)                        # z0 = -tz (mod q)
    z0 = PrivateKey(z0_num.to_bytes(32, 'big'), raw=True)     

    Ca = A.mult(z) + Ma
    Cx0 = X0.mult(z) + U
    Cx1 = X1.mult(z) + U.mult(t)
    Cv = Gv.mult(z) + V

    return CommitmentSet(z=z, z0=z0, Ca=Ca, Cx0=Cx0, Cx1=Cx1, Cv=Cv)


def prove_MAC_and_serial(
    iparams: Tuple[PublicKey, PublicKey],
    commitments: CommitmentSet,
    mac: MAC,
    attribute: Attribute,
) -> ZKP:

    Ca, Cx0, Cx1 = (
        commitments.Ca, 
        commitments.Cx0,
        commitments.Cx1
    )
    _, I = iparams
    S = Gs.mult(attribute.r)
    Z = I.mult(commitments.z)

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[
            commitments.z,
            commitments.z0,
            mac.t,
            attribute.r,
            attribute.a
        ]
    )
    # MAC
    prover.add_statement(Statement(         # Z = z*I
        value=Z,
        construction={
            I: 0
        }
    ))
    prover.add_statement(Statement(         # Cx1 = t*Cx0 + (-tz)*X0 + z*X1
        value=Cx1,
        construction={
            Cx0: 2,
            X0: 1,
            X1: 0,
        }
    ))
    # Serial
    prover.add_statement(Statement(         # S = r*Gs
        value=S,
        construction={
            Gs: 3,
        }
    ))
    prover.add_statement(Statement(         # Ca = z*A + r*H + a*G
        value=Ca,
        construction={
            A: 0,
            H: 3,
            G: 4,
        }
    ))

    return prover.prove()

def verify_MAC_and_serial(
    sk: List[PrivateKey],
    commitments: CommitmentSet,
    S: PublicKey,
    proof: ZKP,
) -> bool:
    w, w_, x0, x1, ya = sk[:5]
    Ca, Cx0, Cx1, Cv = (
        commitments.Ca,
        commitments.Cx0,
        commitments.Cx1,
        commitments.Cv,
    )
    I = Gv + -(X0.mult(x0) + X1.mult(x1) + A.mult(ya))
    Z = Cv + -(W.mult(w) + Cx0.mult(x0) + Cx1.mult(x1) + Ca.mult(ya))

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    # MAC
    verifier.add_statement(Statement(         # Z = z*I
        value=Z,
        construction={
            I: 0
        }
    ))
    verifier.add_statement(Statement(         # Cx1 = t*Cx0 + (-tz)*X0 + z*X1
        value=Cx1,
        construction={
            Cx0: 2,
            X0: 1,
            X1: 0,
        }
    ))
    # Serial
    verifier.add_statement(Statement(         # S = r*Gs
        value=S,
        construction={
            Gs: 3,
        }
    ))
    verifier.add_statement(Statement(         # Ca = z*A + r*H + a*G
        value=Ca,
        construction={
            A: 0,
            H: 3,
            G: 4,
        }
    ))
    
    return verifier.verify()

def get_serial(attribute: Attribute):
    return Gs.mult(attribute.r)

def prove_balance(
    commitment_sets: List[CommitmentSet],
    old_attributes: List[Attribute],                   
    new_attributes: List[Attribute],
) -> ZKP:

    z = [comm.z for comm in commitment_sets]
    r = [att.r for att in old_attributes]
    r_ = [att.r for att in new_attributes]

    z_sum = z[0]
    for zz in z[1:]:
        z_sum = PrivateKey(z_sum.tweak_add(zz.private_key), raw=True)
    r_sum = r[0]
    for rr in r[1:]:
        r_sum = PrivateKey(r_sum.tweak_add(rr.private_key), raw=True)
    r_sum_ = r_[0]
    for rr_ in r_[1:]:
        r_sum_ = PrivateKey(r_sum_.tweak_add(rr_.private_key), raw=True)

    B = A.mult(z_sum) + H.mult(r_sum) + -H.mult(r_sum_)

    delta_r_num = (int.from_bytes(r_sum.private_key, 'big')
        - int.from_bytes(r_sum_.private_key, 'big')) % q
    delta_r = PrivateKey(delta_r_num.to_bytes(32, 'big'), raw=True)

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[z_sum, delta_r]
    )
    prover.add_statement(Statement(             # B = z*A + 𝚫r*H
        value=B,
        construction={
            A: 0,
            H: 1,
        }
    ))

    return prover.prove()

def verify_balance(
    commitments: List[CommitmentSet],
    attributes: List[Attribute],
    balance_proof: ZKP,
    delta_amount: int,
) -> bool:
    delta_a = PrivateKey(abs(delta_amount).to_bytes(32, 'big'), raw=True)
    B = -G.mult(delta_a) if delta_amount >= 0 else G.mult(delta_a)
    for comm in commitments:
        B += comm.Ca
    for att in attributes:
        B += -att.Ma

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=balance_proof,
    )
    verifier.add_statement(Statement(             # B = z*A + 𝚫r*H
        value=B,
        construction={
            A: 0,
            H: 1,
        }
    ))

    return verifier.verify()

'''
def prove_range(
    r: PrivateKey,
    a: PrivateKey
) -> Tuple[List[bytes], bytes]:
    Ma = 
'''