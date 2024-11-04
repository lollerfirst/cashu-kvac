from secp import GroupElement, Scalar, SCALAR_ZERO, q
from models import (
    ZKP,
    RangeZKP,
    Attribute,
    RandomizedCredentials,
    MAC,
    Statement,
    Equation,
)
from generators import (
    hash_to_curve,
    W, W_, X0, X1, Gv, A, G, H, Gs,
)
import hashlib

from typing import Tuple, List, Optional, Union
from enum import Enum

# Maximum allowed for a single attribute
RANGE_LIMIT = 1 << 51

# Powers of two mult H
# Used in range proofs.
GROUP_ELEMENTS_POW2 = [
    (Scalar((1 << i).to_bytes(32, "big")))*H
for i in range(RANGE_LIMIT.bit_length())]

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
    """
    A class for proving and verifying linear relations in zero-knowledge.

    This class provides methods for adding statements to be proven or verified,
    and for generating or verifying a zero-knowledge proof.

    Attributes:
        random_terms (List[Scalar]): Random terms used in the proof.
        challenge_preimage (bytes): The preimage of the challenge used in the proof.
        secrets (List[Scalar]): The secrets used to compute the proof.
        responses (List[Scalar]): The responses used in the verification.
        c (Scalar): The challenge extracted from the provided proof.
        mode (LinearRelationMode): The mode of the class, either PROVE or VERIFY.
    """
    random_terms: List[Scalar]  # k1, k2, ...
    challenge_preimage: bytes
    secrets: List[bytes]
    responses: List[Scalar]
    c: Scalar
    mode: LinearRelationMode

    def __init__(self,
        mode: LinearRelationMode,
        secrets: Optional[List[Scalar]] = None,
        proof: Optional[ZKP] = None,
    ):
        """
        Initializes the LinearRelationProverVerifier class.

        Parameters:
            mode (LinearRelationMode): The mode of the class, either PROVE or VERIFY.
            secrets (Optional[List[Scalar]]): The secrets used in the proof, required if mode is PROVE.
            proof (Optional[ZKP]): The proof used in the verification, required if mode is VERIFY.
        """
        match mode:
            case LinearRelationMode.PROVE:
                assert secrets is not None, "mode is PROVE but no secrets provided"
                self.secrets = secrets
                self.random_terms = [Scalar() for _ in secrets]
            case LinearRelationMode.VERIFY:
                assert proof is not None, "mode is VERIFY but no ZKP provided"
                self.responses = [Scalar(s) for s in proof.s]
                self.c = Scalar(proof.c)
            case _:
                raise Exception("unrecognized mode")

        self.challenge_preimage = b""
        self.mode = mode

    def add_statement(self, statement: Statement):
        """
        Adds a statement to be proven or verified.

        Parameters:
            statement (Statement): The statement to be added.
        """
        for eq in statement:
            R = G
            V = eq.value

            if self.mode.isProve:
                for i, P in enumerate(eq.construction):
                    R = (R + self.random_terms[i] * P) if P else R
            elif self.mode.isVerify:
                for i, P in enumerate(eq.construction):
                    R = (R + self.responses[i] * P) if P else R
                R = (R - self.c*V) if V else R     # We treat V == None as point to infinity

            R -= G
            # NOTE: No domain separation?
            if V:
                self.challenge_preimage += V.serialize(True) + R.serialize(True)
            else:
                self.challenge_preimage += R.serialize(True)
    
    def prove(self,
        add_to_challenge: Optional[List[GroupElement]] = None
    ) -> ZKP:
        """
        Generates a zero-knowledge proof.

        Parameters:
            add_to_challenge (Optional[List[GroupElement]]): Additional public keys to add to the challenge.

        Returns:
            ZKP: The generated zero-knowledge proof.
        """
        assert self.mode.isProve, "mode is not PROVE!"

        if add_to_challenge is not None:
            for E in add_to_challenge:
                self.challenge_preimage += E.serialize(True)

        c = Scalar(
            hashlib.sha256(self.challenge_preimage).digest()
        )
        
        responses = [(k + c*s).to_bytes()
            for k, s in zip(self.random_terms, self.secrets)]
        
        return ZKP(s=responses, c=c.to_bytes())

    def verify(self,
        add_to_challenge: Optional[List[GroupElement]] = None
    ) -> bool:
        """
        Verifies a zero-knowledge proof.

        Parameters:
            add_to_challenge (Optional[List[GroupElement]]): Additional public keys to add to the challenge.

        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        assert self.mode.isVerify, "mode is not VERIFY!"

        if add_to_challenge is not None:
            for E in add_to_challenge:
                self.challenge_preimage += E.serialize(True)

        c_ = Scalar(
            hashlib.sha256(self.challenge_preimage).digest()
        )

        return self.c == c_

def prove_iparams(
    sk: List[Scalar],
    attribute: Attribute,
    mac: MAC,
) -> ZKP:
    """
    Generates a zero-knowledge proof that mac was generated from attribute and sk.

    This function takes as input a secret key, an attribute, and a MAC, and returns a zero-knowledge proof that the MAC is valid for the given attribute and secret key.

    Parameters:
        sk (List[Scalar]): The secret key.
        attribute (Attribute): The attribute.
        mac (MAC): The MAC.

    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    Ma = attribute.Ma
    V = mac.V
    t = mac.t
    U = hash_to_curve(t.to_bytes())

    # Derive params from secret key
    Cw = sk[0] * W + sk[1] * W_
    I = Gv - (sk[2]*X0 + sk[3]*X1 + sk[4]*A)

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=sk,
    )
    prover.add_statement([
        Equation(                   # Cw = w*W  + w_*W_
            value=Cw,
            construction=[W, W_,]
        ),
        Equation(                   # I = Gv - x0*X0 - x1*X1 - ya*A
            value=Gv-I,          
            construction=[None] * 2 + [X0, X1, A]
        ),
        Equation(                   # V = w*W + x0*U + x1*t*U + ya*Ma
            value=V,
            construction=[
                W, None, U, t*U, Ma
            ]
        )
    ])


    return prover.prove()

def verify_iparams(
    attribute: Attribute,
    mac: MAC,
    iparams: Tuple[GroupElement, GroupElement],
    proof: ZKP,
) -> bool:
    """
    Verifies that MAC was generated from Attribute using iparams.

    This function takes as input an attribute, a MAC, iparams, and a
    proof, and returns True if the proof is valid for the given attribute
    and MAC, and False otherwise.

    Parameters:
        attribute (Attribute): The attribute.
        mac (MAC): The MAC.
        iparams (Tuple[GroupElement, GroupElement]): The iparams.
        proof (ZKP): The proof.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    Cw, I = iparams
    Ma = attribute.Ma
    t = mac.t
    V = mac.V
    U = hash_to_curve(t.to_bytes())

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement([
        Equation(                   # Cw = w*W  + w_*W_
            value=Cw,
            construction=[W, W_,]
        ),
        Equation(                   # I = Gv - x0*X0 - x1*X1 - ya*A
            value=(-I)+Gv,          
            construction=[None] * 2 + [X0, X1, A]
        ),
        Equation(                   # V = w*W + x0*U + x1*t*U + ya*Ma
            value=V,
            construction=[
                W, None, U, t*U, Ma
            ]
        )
    ])

    return verifier.verify()

def randomize_credentials(
    attribute: Attribute,
    mac: MAC,
) -> RandomizedCredentials:
    """
    Produces randomized commitments for the given attribute and MAC.

    This function takes as input an attribute and a MAC, and returns a randomized commitment set.

    Parameters:
        attribute (Attribute): The attribute.
        mac (MAC): The MAC.

    Returns:
        RandomizedCredentials: The randomized commitment set.
    """
    t = mac.t
    V = mac.V
    Ma = attribute.Ma
    U = hash_to_curve(t.private_key)
    z = Scalar()
    z0 = -(t*z)   

    Ca = z*A + Ma
    Cx0 = z*X0 + U
    Cx1 = z*X1 + t*U
    Cv = z*Gv + V

    return RandomizedCredentials(z=z, z0=z0, Ca=Ca, Cx0=Cx0, Cx1=Cx1, Cv=Cv)


def prove_MAC_and_serial(
    iparams: Tuple[GroupElement, GroupElement],
    commitments: RandomizedCredentials,
    mac: MAC,
    attribute: Attribute,
) -> ZKP:
    """
    Generates a zero-knowledge proof that the given commitments where derived
    from attribute and mac.

    Only who knows the opening of iparams can correctly verify this proof.

    Parameters:
        iparams (Tuple[GroupElement, GroupElement]): The iparams.
        commitments (RandomizedCredentials): The commitments.
        mac (MAC): The MAC.
        attribute (Attribute): The attribute.

    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    Ca, Cx0, Cx1 = (
        commitments.Ca, 
        commitments.Cx0,
        commitments.Cx1
    )
    _, I = iparams
    S = attribute.r*Gs
    Z = commitments.z*I

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
    prover.add_statement([
        Equation(           # Z = z*I
            value=Z,
            construction=[I]
        ),
        Equation(           # Cx1 = t*Cx0 + (-tz)*X0 + z*X1
            value=Cx1,
            construction=[X1, X0, Cx0]
        ),
        Equation(           # S = r*Gs
            value=S,
            construction=[None] * 3 + [Gs]
        ),
        Equation(           # Ca = z*A + r*H + a*G
            value=Ca,
            construction=[A, None, None, H, G]
        )
    ])

    return prover.prove()

def verify_MAC_and_serial(
    sk: List[Scalar],
    commitments: RandomizedCredentials,
    S: GroupElement,
    proof: ZKP,
) -> bool:
    """
    Verifies a zero-knowledge proof for the given MAC, serial, and commitments.

    This function takes as input a secret key, commitments, a public key S, and a zero-knowledge proof, and returns True if the proof is valid for the given commitments and secret key, and False otherwise.

    Parameters:
        sk (List[Scalar]): The secret key.
        commitments (RandomizedCredentials): The randomized commitments.
        S (GroupElement): The serial number S.
        proof (ZKP): The zero-knowledge proof.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    w, w_, x0, x1, ya = sk[:5]
    Ca, Cx0, Cx1, Cv = (
        commitments.Ca,
        commitments.Cx0,
        commitments.Cx1,
        commitments.Cv,
    )
    I = Gv - (x0*X0 + x1*X1 + ya*A)
    Z = Cv - (w*W + x0*Cx0 + x1*Cx1 + ya*Ca)

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement([
        Equation(           # Z = z*I
            value=Z,
            construction=[I]
        ),
        Equation(           # Cx1 = t*Cx0 + (-tz)*X0 + z*X1
            value=Cx1,
            construction=[X1, X0, Cx0]
        ),
        Equation(           # S = r*Gs
            value=S,
            construction=[None] * 3 + [Gs]
        ),
        Equation(           # Ca = z*A + r*H + a*G
            value=Ca,
            construction=[A, None, None, H, G]
        )
    ])

    
    return verifier.verify()

def prove_balance(
    commitment_sets: List[RandomizedCredentials],
    old_attributes: List[Attribute],                   
    new_attributes: List[Attribute],
) -> ZKP:
    """
    This function takes as input a list of commitment sets, a list of old attributes, and a list of new attributes, and returns a zero-knowledge proof that the balance is valid for the given commitment sets and attributes.

    Parameters:
        commitment_sets (List[RandomizedCredentials]): The list of commitment sets.
        old_attributes (List[Attribute]): The list of old attributes.
        new_attributes (List[Attribute]): The list of new attributes.

    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    z = [comm.z for comm in commitment_sets]
    r = [att.r for att in old_attributes]
    r_ = [att.r for att in new_attributes]

    z_sum = sum(z, Scalar(SCALAR_ZERO))
    r_sum = sum(r, Scalar(SCALAR_ZERO))
    r_sum_ = sum(r_, Scalar(SCALAR_ZERO))

    B = z_sum*A + r_sum*H - r_sum_*H

    delta_r = r_sum - r_sum_

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[z_sum, delta_r]
    )
    prover.add_statement([Equation(             # B = z*A + 𝚫r*H
        value=B,
        construction=[A, H]
    )])

    return prover.prove()

def verify_balance(
    commitments: List[GroupElement],
    attributes: List[GroupElement],
    balance_proof: ZKP,
    delta_amount: int,
) -> bool:
    """
    This function computes a balance from a list of "old" randomized attributes,
    a list of attributes and a public Δamount,
    then verifies zero-knowledge balance proof and returns True if the proof is valid, and False otherwise.

    Parameters:
        commitments (List[RandomizedCredentials]): The list of commitment sets.
        attributes (List[Attribute]): The list of attributes.
        balance_proof (ZKP): The zero-knowledge proof.
        delta_amount (int): The delta amount.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """

    delta_a = Scalar(abs(delta_amount).to_bytes(32, 'big'))
    B = -delta_a*G if delta_amount >= 0 else delta_a*G
    for Ca in commitments:
        B += Ca
    for Ma in attributes:
        B -= Ma

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=balance_proof,
    )
    verifier.add_statement([Equation(             # B = z*A + 𝚫r*H
        value=B,
        construction=[A, H]
    )])

    return verifier.verify()


def prove_range(
    attribute: Attribute
):
    # https://github.com/WalletWasabi/WalletWasabi/pull/4429
    # This amounts to 6KB. Nasty.

    # Get the attribute public point.
    Ma = attribute.Ma

    # Get the powers of 2 as PrivateKeys.
    K = GROUP_ELEMENTS_POW2

    # Decompose attribute's amount into bits.
    amount = int.from_bytes(attribute.a.to_bytes(), "big")
    bits = []
    for _ in range(RANGE_LIMIT.bit_length()):
        bits.append(Scalar((amount&1).to_bytes(32, "big")))
        amount >>= 1

    # Get `r` vector for B_i = b_i*G + r_i*H
    bits_blinding_factors = [Scalar() for _ in bits]

    # B is the bit commitments vector
    B = []
    for b_i, r_i in zip(bits, bits_blinding_factors):
        R_i = r_i*H
        B.append(R_i+G if not b_i.is_zero else R_i)

    # Hadamard product between
    # the blinding factors vector and the bits vector
    # We need to take the negation of this to obtain -r_i*b_i because
    # c*r_i*b_i*H will be the excess challenge term to cancel
    product_bits_and_blinding_factors = [
        -(r*b)
        for r, b in zip(bits_blinding_factors, bits)
    ]

    # Instantiate linear prover
    # Witnesses are:
    #   - r (attribute.r)
    #   - b_i
    #   - r_i
    #   - -(r_i * b_i) <-- needed to cancel out an excess challenge term in the third set of eqns
    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[attribute.r] + 
            bits +
            bits_blinding_factors +
            product_bits_and_blinding_factors,
    )

    # 1) This equation proves that Ma - Σ 2^i*B_i is a commitment to zero
    # But only the verifier calculates that separately with B and Ma
    # We (the prover) can provide V = r*H - Σ 2^i*r_i*H directly
    V = attribute.r*H
    for K_i, r_i in zip(K, bits_blinding_factors):
        V -= r_i*K_i

    # Com(0) = r*H - Σ (2^i*r_i)*H - Ma + Σ (2^i)*B_i
    statement = [Equation(               
        value=V,
        construction=[H] +
            [None] * len(B) +
            [-K[i] for i in range(len(B))]
    )]

    # 2) This set of equations proves that we know the opening of B_i for every i
    # Namely B_i - b_i*G is a commitment to zero
    statement += [Equation(
        value=B_i,
        construction=[None] +
            [None] * i + [G] +
            [None] * (len(B)-1) + [H]
    ) for i, B_i in enumerate(B)]

    # 3) This set of equations proves that each b_i is such that b_i^2 = b_i
    # NOTE: This is a little different because
    # the verifier does not use the challenge to verify these.
    # Instead they just use the same responses from (2) and multiply them against (B_i - G).
    # The only way the challenge terms cancel out is if
    # b_i^2cG - b_icG is a commitment to zero <==> b^2 = b <==> b = 0 or 1
    statement += [Equation(
        value=None, # To represent point at infinity
        construction=[None] + 
            [None] * i +
            [B_i-G] +
            [None] * (2*len(B)-1) + 
            [H]
        ) for i, B_i in enumerate(B)]
    
    prover.add_statement(statement)
    zkp = prover.prove()

    # and we return B the bit-commitments vector
    return RangeZKP(
        B=B,
        s=zkp.s,
        c=zkp.c
    )

def verify_range(
    Ma: GroupElement,
    proof: RangeZKP
) -> bool:

    # Get the bit commitments
    B = proof.B
    # Get powers of 2 in H
    K = GROUP_ELEMENTS_POW2

    # Verify the number of bits does not exceed log2(RANGE_LIMIT)
    if len(B) > RANGE_LIMIT.bit_length():
        return False

    # Calculate Ma - Σ 2^i*B_i
    V = Ma
    for i, B_i in enumerate(B):
        k = Scalar((1 << i).to_bytes(32, "big"))
        V -= k*B_i

    # Instantiate verifier with the proof
    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof
    )

    # 1)
    statement = [Equation(              
        value=V,
        construction=[H] +
            [None] * len(B) +
            [-K[i] for i in range(len(B))]
    )]

    # 2)
    statement += [Equation(
        value=B_i,
        construction=[None] +
            [None] * i +
            [G] +
            [None] * (len(B)-1) +
            [H]
    ) for i, B_i in enumerate(B)]

    # 3)
    statement += [Equation(
        value=None, # To represent point at infinity
        construction=[None] + 
            [None] * i +
            [B_i-G] +
            [None] * (2*len(B)-1) + 
            [H]
        ) for i, B_i in enumerate(B)]

    verifier.add_statement(statement)
    return verifier.verify()