from secp import PrivateKey, PublicKey
from models import ZKP, Attribute, CommitmentSet, MAC
import hashlib

from typing import Tuple, List

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
    k = [PrivateKey() for _ in range(5)]

    # Build commitments
    R1 = W.mult(k[0]) + W_.mult(k[1])                                       # R1 = r1W + r2W_
    R2 = X0.mult(k[2]) + X1.mult(k[3]) + A.mult(k[4])                       # R2 = r3X0 + r4X1 + r5A
    R3 = W.mult(k[0]) + U.mult(k[2]) + U.mult(k[3]).mult(t) + Ma.mult(k[4]) # R3 = r1W + r3U + tr4U + r5Ma

    ## DEBUG
    print("Proof generation:")
    print(f"{R1.serialize().hex() = }")
    print(f"{R2.serialize().hex() = }")
    print(f"{R3.serialize().hex() = }")

    # Derive params from secret key
    Cw = W.mult(sk[0]) + W_.mult(sk[1])
    I = Gv + -(X0.mult(sk[2]) + X1.mult(sk[3]) + A.mult(sk[4]))

    # challenge
    # Fiat-Shamir heuristic
    c = PrivateKey(hashlib.sha256(
            Cw.serialize(True)
            +I.serialize(True)
            +Ma.serialize(True)
            +V.serialize(True)
            +U.serialize(True)
            +R1.serialize(True)
            +R2.serialize(True)
            +R3.serialize(True)
        ).digest(),
        raw=True
    )
    
    # signatures
    s = [kk.tweak_add(c.tweak_mul(sk[i].private_key)) for i, kk in enumerate(k)]
    c = c.private_key
    return ZKP(s=s, c=c)

def verify_iparams(
    attribute: Attribute,
    mac: MAC,
    iparams: Tuple[PublicKey, PublicKey],
    proof: ZKP,
) -> bool:
    '''
        Verifies that (t, V) is a credential generated from Ma and <Cw, I>
    '''
    # Extract signatures and challenge
    s = [PrivateKey(ss, raw=True) for ss in proof.s]
    c = PrivateKey(proof.c, raw=True)
    Cw, I = iparams

    Ma = attribute.Ma
    t = mac.t
    V = mac.V
    U = hash_to_curve(t.private_key)

    # Build commitments
    R1 = W.mult(s[0]) + W_.mult(s[1]) + -Cw.mult(c)
    R2 = X0.mult(s[2]) + X1.mult(s[3]) + A.mult(s[4]) + I.mult(c) + -Gv.mult(c)
    R3 = W.mult(s[0]) + U.mult(s[2]) + U.mult(s[3]).mult(t) + Ma.mult(s[4]) + -V.mult(c)

    ## DEBUG
    print("Verification:")
    print(f"{R1.serialize().hex() = }")
    print(f"{R2.serialize().hex() = }")
    print(f"{R3.serialize().hex() = }")

    # Simulated challenge Fiat-Shamir heuristic
    c_ = hashlib.sha256(
            Cw.serialize(True)
            +I.serialize(True)
            +Ma.serialize(True)
            +V.serialize(True)
            +U.serialize(True)
            +R1.serialize(True)
            +R2.serialize(True)
            +R3.serialize(True)
    ).digest()

    return c.private_key == c_

def generate_MAC(
    attribute: Attribute,
    sk: List[PrivateKey]
) -> MAC:
    '''
        Issues a credential for a given attribute
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
    # Draw randomness terms and extract commitments, params
    k = [PrivateKey() for _ in range(5)]
    Ca, Cx0, Cx1 = (
        commitments.Ca, 
        commitments.Cx0,
        commitments.Cx1
    )
    _, I = iparams

    # MAC
    R1 = I.mult(k[0]) # <-- comm for zI == Z
    R2 = X1.mult(k[0]) + X0.mult(k[1]) + Cx0.mult(k[2]) # <-- comm for Cx1 == tCx0 + z0X0 + zX1
    # Serial
    R3 = Gs.mult(k[3]) # <-- comm for S == rGs
    R4 = A.mult(k[0]) + H.mult(k[3]) + G.mult(k[4]) # <-- comm for Ca == zA + rH + aG

    ## DEBUG
    print("MAC generate proof:")
    print(f"{R1.serialize().hex() = }")
    print(f"{R2.serialize().hex() = }")
    print(f"{R3.serialize().hex() = }")
    print(f"{R4.serialize().hex() = }")

    r = attribute.r
    S = Gs.mult(r)

    c = PrivateKey(
        hashlib.sha256(
            I.serialize(True)
            +Cx0.serialize(True)
            +Cx1.serialize(True)
            +Ca.serialize(True)
            +S.serialize(True)
            +R1.serialize(True)
            +R2.serialize(True)
            +R3.serialize(True)
            +R4.serialize(True)
        ).digest(),
        raw=True
    )
    secrets = [commitments.z, commitments.z0, mac.t, attribute.r, attribute.a]
    s = [kk.tweak_add(
        c.tweak_mul(secrets[i].private_key)
    ) for i, kk in enumerate(k)]
    c = c.private_key
    return ZKP(s=s, c=c)

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

    s = [PrivateKey(p, raw=True) for p in proof.s]
    c = PrivateKey(proof.c, raw=True)

    I = Gv + -(X0.mult(x0) + X1.mult(x1) + A.mult(ya))
    Z = Cv + -(W.mult(w) + Cx0.mult(x0) + Cx1.mult(x1) + Ca.mult(ya))

    R1 = I.mult(s[0]) + -Z.mult(c)
    R2 = Cx0.mult(s[2]) + X0.mult(s[1]) + X1.mult(s[0]) + -Cx1.mult(c)
    R3 = Gs.mult(s[3]) + -S.mult(c)
    R4 = A.mult(s[0]) + H.mult(s[3]) + G.mult(s[4]) + -(Ca.mult(c))

    ## DEBUG
    print("MAC verify:")
    print(f"{R1.serialize().hex() = }")
    print(f"{R2.serialize().hex() = }")
    print(f"{R3.serialize().hex() = }")
    print(f"{R4.serialize().hex() = }")

    c_ = PrivateKey(hashlib.sha256(
            I.serialize(True)
            +Cx0.serialize(True)
            +Cx1.serialize(True)
            +Ca.serialize(True)
            +S.serialize(True)
            +R1.serialize(True)
            +R2.serialize(True)
            +R3.serialize(True)
            +R4.serialize(True)
        ).digest(),
        raw=True,
    ) # reduce by q

    return c.private_key == c_.private_key

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

    k = [PrivateKey() for _ in range(2)]
    R = A.mult(k[0]) + H.mult(k[1])

    ## DEBUG
    print("Prove balance:")
    print(f"{B.serialize(True).hex() = }")
    print(f"{R.serialize(True).hex() = }")

    c = PrivateKey(
        hashlib.sha256(
            B.serialize(True)
            +R.serialize(True)
        ).digest(),
        raw=True
    )

    delta_r_num = (int.from_bytes(r_sum.private_key, 'big')
        - int.from_bytes(r_sum_.private_key, 'big')) % q
    delta_r = PrivateKey(delta_r_num.to_bytes(32, 'big'), raw=True)

    secrets = [z_sum, delta_r]
    s = [kk.tweak_add(
        c.tweak_mul(
            secrets[i].private_key
        )
    ) for i, kk in enumerate(k)]
    c = c.private_key

    return ZKP(s=s, c=c)

def verify_balance(
    commitments: List[CommitmentSet],
    attributes: List[Attribute],
    balance_proof: ZKP,
    delta_amount: int,
) -> bool:    
    # Extract proof and challenge
    s = [PrivateKey(p, raw=True) for p in balance_proof.s]
    c = PrivateKey(balance_proof.c, raw=True)

    delta_a = PrivateKey(abs(delta_amount).to_bytes(32, 'big'), raw=True)
    B = -G.mult(delta_a) if delta_amount >= 0 else G.mult(delta_a)
    for (comm, att) in zip(commitments, attributes):
        Ca, Ma = comm.Ca, att.Ma
        B += Ca + -Ma

    R = A.mult(s[0]) + H.mult(s[1]) + -B.mult(c)

    ## DEBUG
    print("Verify balance:")
    print(f"{B.serialize(True).hex() = }")
    print(f"{R.serialize(True).hex() = }")

    c_ = PrivateKey(
        hashlib.sha256(
            B.serialize(True)
            +R.serialize(True)
        ).digest(),
        raw=True,
    ) # reduce by q

    return c.private_key == c_.private_key

'''
def prove_range(
    r: PrivateKey,
    a: PrivateKey
) -> Tuple[List[bytes], bytes]:
    Ma = 
'''