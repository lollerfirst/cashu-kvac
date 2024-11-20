from secp import (
    GroupElement,
    Scalar,
    SCALAR_ZERO,
    ELEMENT_ZERO,
    q
)
from models import *
from generators import *
import hashlib

from typing import Tuple, List, Optional, Union
from enum import Enum

# Maximum allowed for a single attribute
RANGE_LIMIT = 1 << 32

# Powers of two mult H.
# Used in range proofs.
GROUP_ELEMENTS_POW2 = [
        (Scalar((1 << i).to_bytes(32, "big")))*G_blind
    for i in range(RANGE_LIMIT.bit_length())
]

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
    random_terms: List[Scalar]
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
                if self.c.is_zero:
                    raise Exception("provided proof has a scalar zero challenge")
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
            R = O
            V = eq.value

            if self.mode.isProve:
                for row in eq.construction:
                    for i, P in enumerate(row):
                        R += self.random_terms[i] * P
            elif self.mode.isVerify:
                for row in eq.construction:
                    for i, P in enumerate(row):
                        R += self.responses[i] * P
                R -= self.c*V

            # NOTE: No domain separation?
            self.challenge_preimage += V.serialize(True) + R.serialize(True)
        
        # Check that nothing strange is happening
        if self.challenge_preimage == b"":
            raise Exception("add_statement: empty challenge preimage")
    
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

        # NOTE: Use Merlin?
        # Are there any libraries for python? Don't think so.
        c_ = Scalar(
            hashlib.sha256(self.challenge_preimage).digest()
        )

        return self.c == c_

class BootstrapStatement:

    @classmethod
    def create(cls, Ma: GroupElement):
        return [
            Equation(                   # Ma = r*G_blind
                value=Ma,
                construction=[[G_blind]]
            )
        ]

class IparamsStatement:

    @classmethod
    def create(cls,
        Cw: GroupElement,
        I: GroupElement,
        V: GroupElement,
        Ma: GroupElement,
        Ms: GroupElement,
        t: Scalar,
    ):
        U = hash_to_curve(t.to_bytes())
        return [
            Equation(                   # Cw = w*W  + w_*W_
                value=Cw,
                construction=[[W, W_,]]
            ),
            Equation(                   # I = Gz_mac - x0*X0 - x1*X1 - ya*Gz_attribute - ys*Gz_script
                value=Gz_mac-I,          
                construction=[[O, O, X0, X1, Gz_attribute, Gz_script]]
            ),
            Equation(                   # V = w*W + x0*U + x1*t*U + ya*Ma + ys*Ms
                value=V,
                construction=[[W, O, U, t*U, Ma, Ms]]
            )
        ]

class CredentialsStatement:

    @classmethod
    def create(cls,
        Z: GroupElement,
        I: GroupElement,
        Cx0: GroupElement,
        Cx1: GroupElement,
        Ca: GroupElement,
    ):
        return [
            Equation(           # Z = r*I
                value=Z,
                construction=[[I]]
            ),
            Equation(           # Cx1 = t*Cx0 + (-tr)*X0 + r*X1
                value=Cx1,
                construction=[[X1, X0, Cx0]]
            ),
            Equation(           # Ca = r*Gz_amount + r*G_blind + a*G_amount
                value=Ca,       # MULTI-ROW: `r` witness is used twice for Gz_amount and G_blind
                construction=[
                    [Gz_attribute, O, O, G_amount],
                    [G_blind]
                ]
            )
        ]

class BalanceStatement:

    @classmethod
    def create(cls, B: GroupElement):
        return [Equation(             # B = r*Gz_attribute + 𝚫r*G_blind
            value=B,
            construction=[[Gz_attribute, G_blind]]
        )]

class ScriptEqualityStatement:

    @classmethod
    def create(cls, creds: List[GroupElement], attr: List[GroupElement]):
        statement = [
            Equation(             
                value=Cs,
                construction=[
                    [G_script]+
                    [O] * i +
                    [Gz_script] +
                    [O] * (len(creds)-1) + 
                    [G_blind]
                ]
            )
        for i, Cs in enumerate(creds)]
        statement += [
            Equation(
                value=Ms,
                construction=[
                    [G_script] +
                    [O] * (2*len(creds)+i) +
                    [G_blind]
                ]
            )
        for i, Ms in enumerate(attr)]
        return statement

class RangeStatement:
    
    @classmethod
    def create(cls,
        B: List[GroupElement],
        V: GroupElement,
    ):
        K = GROUP_ELEMENTS_POW2

        # 1) This equation proves that Ma - Σ 2^i*B_i is a commitment to zero
        statement = [Equation(               
            value=V,
            construction=[
                [G_blind] +
                [O] * len(B) +
                [-K[i] for i in range(len(B))]
            ]
        )]

        # 2) This set of equations proves that we know the opening of B_i for every i
        # Namely B_i - b_i*G is a commitment to zero
        statement += [Equation(
            value=B_i,
            construction=[
                [O] +
                [O] * i +
                [G_amount] +
                [O] * (len(B)-1) +
                [G_blind]
            ]
        ) for i, B_i in enumerate(B)]

        # 3) This set of equations proves that each b_i is such that b_i^2 = b_i
        # NOTE: This is a little different because
        # the verifier does not use the challenge to verify these.
        # Instead they just use the same responses from (2) and multiply them against (B_i - G).
        # The only way the challenge terms cancel out is if
        # b_i^2cG - b_icG is a commitment to zero <==> b^2 = b <==> b = 0 or 1
        statement += [Equation(
            value=O,
            construction=[
                [O] + 
                [O] * i +
                [B_i-G_amount] +
                [O] * (2*len(B)-1) + 
                [G_blind]
            ]
            ) for i, B_i in enumerate(B)]

        return statement

def prove_bootstrap(
    bootstrap: AmountAttribute
) -> ZKP:
    """
    Generates a zero-knowledge proofs that the bootstrap attribute does not encode value.

    Parameters:
        bootstrap (AmountAttribute): the bootstrap attribute.

    Returns:
        ZKP: The generated zero-knowledge proof
    """
    Ma = bootstrap.Ma
    r = bootstrap.r

    prover = LinearRelationProverVerifier(
        LinearRelationMode.PROVE,
        secrets=[r]
    )
    prover.add_statement(BootstrapStatement.create(Ma))
    
    return prover.prove()

def verify_bootstrap(
    bootstrap: GroupElement,
    proof: ZKP,
) -> bool:
    """
    Verifies that bootstrap does not encode value.

    Parameters:
        bootstrap (GroupElement): the bootstrap attribute.

    Returns:
        bool: True if verified successfully, False otherwise.
    """
    Ma = bootstrap
    verifier = LinearRelationProverVerifier(
        LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement(BootstrapStatement.create(Ma))

    return verifier.verify()

def prove_iparams(
    privkey: MintPrivateKey,
    mac: MAC,
    attribute: GroupElement,
    script: Optional[GroupElement] = None,
) -> ZKP:
    """
    Generates a zero-knowledge proof that mac was generated from attribute and sk.

    This function takes as input a secret key, an attribute, and a MAC, and returns a zero-knowledge proof that the MAC is valid for the given attribute and secret key.

    Parameters:
        privkey (MintPrivateKey): The secret key.
        mac (MAC): The MAC.
        attribute (GroupElement): The amount attribute.
        script (Optional[GroupElement]): Optional script attribute.
        
    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    Ma = attribute
    Ms = script if script else O
    V = mac.V
    t = mac.t

    Cw = privkey.Cw
    I = privkey.I

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=privkey.sk,
    )
    prover.add_statement(IparamsStatement.create(Cw, I, V, Ma, Ms, t))

    return prover.prove()

def verify_iparams(
    mac: MAC,
    iparams: Tuple[GroupElement, GroupElement],
    proof: ZKP,
    attribute: GroupElement,
    script: Optional[GroupElement] = None,
) -> bool:
    """
    Verifies that MAC was generated from AmountAttribute using iparams.

    This function takes as input an attribute, a MAC, iparams, and a
    proof, and returns True if the proof is valid for the given attribute
    and MAC, and False otherwise.

    Parameters:
        mac (MAC): The MAC.
        iparams (Tuple[GroupElement, GroupElement]): The iparams.
        proof (ZKP): The proof.
        attribute (GroupElement): The amount attribute.
        script (Optional[GroupElement]): The script attribute.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    Cw, I = iparams
    Ma = attribute
    Ms = script if script else O
    t = mac.t
    V = mac.V

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement(IparamsStatement.create(Cw, I, V, Ma, Ms, t))

    return verifier.verify()

def randomize_credentials(
    mac: MAC,
    attribute: AmountAttribute,
    script: Optional[ScriptAttribute] = None,
    reveal_script: bool = False,
) -> RandomizedCredentials:
    """
    Produces randomized commitments for the given attribute and MAC.

    This function takes as input an attribute and a MAC, and returns a randomized commitment set.

    Parameters:
        mac (MAC): The MAC. 
        attribute (AmountAttribute): The amount attribute.
        script (Optional[ScriptAttribute], optional): The optional script attribute (use if you don't want to reveal the script)
        reveal_script (bool, optional): If True, only randomize blinding factor for the script commitment. Defaults to False

    Returns:
        RandomizedCredentials: The randomized commitment set.
    """
    t = mac.t
    V = mac.V
    Ma = attribute.Ma
    Ms = O
    if script:
        if reveal_script:
            Ms = script.r*G_blind
        else:
            Ms = script.Ms

    U = hash_to_curve(t.to_bytes())
    r = attribute.r  

    Ca = r*Gz_attribute + Ma
    Cs = r*Gz_script + Ms
    Cx0 = r*X0 + U
    Cx1 = r*X1 + t*U
    Cv = r*Gz_mac + V

    return RandomizedCredentials(Ca=Ca, Cs=Cs, Cx0=Cx0, Cx1=Cx1, Cv=Cv)


def prove_MAC(
    mint_pubkey: Tuple[GroupElement, GroupElement],
    credentials: RandomizedCredentials,
    mac: MAC,
    attribute: AmountAttribute,
) -> ZKP:
    """
    Generates a zero-knowledge proof that the given commitments where derived
    from attribute and mac.

    Only who knows the opening of iparams can correctly verify this proof.

    Parameters:
        mint_pubkey (Tuple[GroupElement, GroupElement]): The public key tuple of the Mint.
        credentials (RandomizedCredentials): The randomized credentials.
        mac (MAC): The MAC.
        attribute (AmountAttribute): The amount attribute.

    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    Ca, Cx0, Cx1 = ( 
        credentials.Ca,
        credentials.Cx0,
        credentials.Cx1
    )
    _, I = mint_pubkey
    r = attribute.r
    a = attribute.a
    t = mac.t
    r0 = -(t*r)
    Z = r*I

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[r, r0, t, a]
    )
    prover.add_statement(CredentialsStatement.create(Z, I, Cx0, Cx1, Ca))

    return prover.prove()

def verify_MAC(
    privkey: MintPrivateKey,
    credentials: RandomizedCredentials,
    proof: ZKP,
    script: Optional[bytes] = None,
) -> bool:
    """
    Verifies a zero-knowledge proof for the given MAC, serial, and commitments.

    This function takes as input a secret key, commitments, a public key S, and a zero-knowledge proof, and returns True if the proof is valid for the given commitments and secret key, and False otherwise.

    Parameters:
        privkey (MintPrivateKey): The mint secret key.
        credentials (RandomizedCredentials): The randomized commitments.
        proof (ZKP): The zero-knowledge proof.
        script (Optional[bytes], optional): The script if revealed

    Returns:
        bool: True if the proof is valid, False otherwise.
    """
    Ca, Cs, Cx0, Cx1, Cv = (
        credentials.Ca,
        credentials.Cs,
        credentials.Cx0,
        credentials.Cx1,
        credentials.Cv,
    )
    I = privkey.I
    S = O
    if script:
        s = Scalar(hashlib.sha256(script).digest())
        S = s*G_script
    Z = Cv - (
        privkey.w*W
        + privkey.x0*Cx0
        + privkey.x1*Cx1
        + privkey.ya*Ca
        + privkey.ys*(Cs+S)
    )

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement(CredentialsStatement.create(Z, I, Cx0, Cx1, Ca))

    return verifier.verify()

def prove_balance(
    old_attributes: List[AmountAttribute],                   
    new_attributes: List[AmountAttribute],
) -> ZKP:
    """
    This function takes as input a list of old attributes and a list of new attributes, and returns a zero-knowledge proof of the balance between them.

    Parameters:
        old_attributes (List[AmountAttribute]): The list of old amount attributes.
        new_attributes (List[AmountAttribute]): The list of new amount attributes.

    Returns:
        ZKP: The generated zero-knowledge proof.
    """
    r = [att.r for att in old_attributes]
    r_ = [att.r for att in new_attributes]

    r_sum = sum(r, Scalar(SCALAR_ZERO))
    r_sum_ = sum(r_, Scalar(SCALAR_ZERO))

    delta_r = r_sum - r_sum_
    B = r_sum*Gz_attribute + delta_r*G_blind

    prover = LinearRelationProverVerifier(
        mode=LinearRelationMode.PROVE,
        secrets=[r_sum, delta_r]
    )
    prover.add_statement(BalanceStatement.create(B))

    return prover.prove()

def verify_balance(
    credentials: List[RandomizedCredentials],
    new_attributes: List[GroupElement],
    balance_proof: ZKP,
    delta_amount: int,
) -> bool:
    """
    This function computes a balance from a list of "old" randomized attributes,
    a list of attributes and a public Δamount,
    then verifies zero-knowledge balance proof and returns True if the proof is valid, and False otherwise.

    Parameters:
        credentials (List[RandomizedCredentials]): The list of randomized credentials.
        new_attributes (List[AmountAttribute]): The list of new attributes.
        balance_proof (ZKP): The zero-knowledge proof.
        delta_amount (int): The amount by which credentials and new attributes supposedly differ.

    Returns:
        bool: True if the proof is valid, False otherwise.
    """

    delta_a = Scalar(abs(delta_amount).to_bytes(32, 'big'))
    B = -delta_a*G_amount if delta_amount >= 0 else delta_a*G_amount
    for creds in credentials:
        B += creds.Ca
    for Ma in new_attributes:
        B -= Ma

    verifier = LinearRelationProverVerifier(
        mode=LinearRelationMode.VERIFY,
        proof=balance_proof,
    )
    verifier.add_statement(BalanceStatement.create(B))

    return verifier.verify()


def prove_range(
    attribute: AmountAttribute
):
    # This is a naive range proof with bit-decomposition
    # https://gist.github.com/lollerfirst/82644d9ef47cef15508054b9431b123b 

    # Get the attribute public point.
    Ma = attribute.Ma

    # Get the powers of 2 as PrivateKeys.
    K = GROUP_ELEMENTS_POW2

    # Decompose attribute's amount into bits.
    amount = int.from_bytes(attribute.a.to_bytes(), "big")
    bits = []
    for _ in range((RANGE_LIMIT-1).bit_length()):
        bits.append(Scalar((amount&1).to_bytes(32, "big")))
        amount >>= 1

    # Get `r` vector for B_i = b_i*G + r_i*H
    bits_blinding_factors = [Scalar() for _ in bits]

    # B is the bit commitments vector
    B = []
    for b_i, r_i in zip(bits, bits_blinding_factors):
        R_i = r_i*G_blind
        B.append(R_i+G_amount if not b_i.is_zero else R_i)

    # Hadamard product between
    # the blinding factors vector and the bits vector
    # We need to take the negation of this to obtain -r_i*b_i because
    # c*r_i*b_i*H will be the excess challenge term to cancel
    product_bits_and_blinding_factors = [
        -(r*b)
        for r, b in zip(bits_blinding_factors, bits)
    ]

    V = attribute.r*G_blind
    for K_i, r_i in zip(K, bits_blinding_factors):
        V -= r_i*K_i

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
    
    prover.add_statement(RangeStatement.create(B, V))
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
    # Get powers of 2 in G_blind
    K = GROUP_ELEMENTS_POW2

    # Verify the number of bits does not exceed log2(RANGE_LIMIT-1)
    if len(B) >= RANGE_LIMIT.bit_length():
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

    verifier.add_statement(RangeStatement.create(B, V))
    return verifier.verify()

def prove_script_equality(
    old_amount_attributes: List[AmountAttribute],
    old_script_attributes: List[ScriptAttribute],
    new_script_attributes: List[ScriptAttribute],
) -> ZKP:
    """
    Parameters:
        old_amount_attributes(List[AmountAttribute]):
        old_script_attributes (List[ScriptAttribute]): The old script attributes
        new_script_attributes (List[ScriptAttribute]): The new script attributes
    Returns:
        (ZKP) Proof that `s` is the same in the old `Cs` and new `Ms`
    """
    s = new_script_attributes[0].s
    ar_list = [att.r for att in old_amount_attributes]      # `AmountAttribute`s blinding factors
    r_list = [att.r for att in old_script_attributes]       # `ScriptAttribute`s blinding factors
    new_r_list = [att.r for att in new_script_attributes]   # new `ScriptAttribute`s blinding factors

    prover = LinearRelationProverVerifier(
        LinearRelationMode.PROVE,
        secrets=[s]+ar_list+r_list+new_r_list,
    )
    prover.add_statement(ScriptEqualityStatement.create(
        [script_att.Ms + amount_att.r*Gz_script
        for amount_att, script_att in zip(old_amount_attributes, old_script_attributes)],
        [att.Ms for att in new_script_attributes]
    ))
    
    return prover.prove()

def verify_script_equality(
    old_credentials: List[RandomizedCredentials],
    new_script_attributes: List[GroupElement],
    proof: ZKP,
) -> bool:
    """
    Verifies a proof of same script used across all `randomized_script_attributes` and `new_script_attributes`

    Parameters:
        randomized_credentials (List[RandomizedCredentials]): The old randomized credentials
        new_script_attributes (List[GroupElement]): New script attributes
    Returns:
        (bool) True if successfully verified, False otherwise
    """

    verifier = LinearRelationProverVerifier(
        LinearRelationMode.VERIFY,
        proof=proof,
    )
    verifier.add_statement(ScriptEqualityStatement.create(
        [cred.Cs for cred in old_credentials],
        new_script_attributes,
    ))

    return verifier.verify()