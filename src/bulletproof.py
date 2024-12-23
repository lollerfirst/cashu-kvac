from .secp import Scalar, GroupElement, scalar_zero, scalar_one
from .transcript import CashuTranscript
from .generators import *
from .models import AmountAttribute

from dataclasses import dataclass
from typing import List, Tuple

# Maximum allowed for a single attribute
RANGE_LIMIT = 1 << 32

# Scalars in powers of 2
SCALAR_POWERS_2 = [Scalar((1<<i).to_bytes(32, "big")) for i in range(32)]

# Get generators (Could be hard-coded)
G = [hash_to_curve(f"IPA_G_{i}_".encode("utf-8"))
    for i in range(128)]
H = [hash_to_curve(f"IPA_H_{i}_".encode("utf-8"))
    for i in range(128)]
U = hash_to_curve(b"IPA_U_")

def get_generators(length: int):
    global G, H, U
    if hamming_weight(length) != 1:
        print("switching to next pow 2")
        length = 1 << length.bit_length()
    if length > len(G):
        G += [hash_to_curve(f"IPA_G_{i}_".encode("utf-8"))
                for i in range(len(G), length)]
        H += [hash_to_curve(f"IPA_H_{i}_".encode("utf-8"))
                for i in range(len(H), length)]
    return (G[:length], H[:length], U)

@dataclass
class InnerProductArgument:
    public_inputs: List[Tuple[GroupElement, GroupElement]]
    tail_end_scalars: Tuple[Scalar, Scalar]

def hamming_weight(n: int) -> int:
    return sum( [n&(1<<i)>0 for i in range(n.bit_length())] )

def pad(l: List[Scalar], to: int) -> List[Scalar]:
    pad_len = to - ( len(l) % to )
    return l + [scalar_zero for _ in range(pad_len)]

def pad_one(l: List[Scalar], to: int) -> List[Scalar]:
    pad_len = to - ( len(l) % to )
    return l + [scalar_one for _ in range(pad_len)]

def inner_product(l: List[Scalar], r: List[Scalar]) -> Scalar:
    return sum([ll * rr for ll, rr in zip(l, r)], scalar_zero)

# https://eprint.iacr.org/2017/1066.pdf
def get_folded_IPA(
    transcript: CashuTranscript,
    generators: Tuple[List[GroupElement], List[GroupElement], GroupElement],
    P: GroupElement,
    a: List[Scalar],
    b: List[Scalar],
) -> InnerProductArgument:
    assert len(a) == len(b), "the two lists have different length"

    # Extract generators
    G, H, U = generators

    ## PROTOCOL 1 ##
    # `get_folded_IPA` implements Protocol 2, a proof system for relation (3).
    # Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
    transcript.append(b"Com(P)_", P)
    tetha = transcript.get_challenge(b"tetha_chall_")

    # Switch generator U
    U = tetha*U
    ## END PROTOCOL 1 ##

    # Ensure len is a power of 2
    assert hamming_weight(len(a)) == 1, "len(a) and len(b) is not a power of 2"
    n = len(a)

    ipa = []

    # Recursive subdivision
    while n > 1:
        n >>= 1
        c_left = inner_product(a[:n], b[n:])
        c_right = inner_product(a[n:], b[:n])
        L = sum(
            [a_i * G_i + b_i * H_i for (a_i, G_i, b_i, H_i)
                in zip(a[:n], G[n:2*n], b[n:], H[:n])],
            c_left * U
        )
        R = sum(
            [a_i * G_i + b_i * H_i for (a_i, G_i, b_i, H_i)
                in zip(a[n:], G[:n], b[:n], H[n:2*n])],
            c_right * U
        )

        ipa.append((L, R))
        
        # Prover -> Verifier : L, R
        # Verifier -> Prover : x (challenge)

        transcript.append(b"IPA_L_", L)
        transcript.append(b"IPA_R_", R)

        x = transcript.get_challenge(b"IPA_chall_")
        x_inv = x.invert()
        
        # fold a and b
        a = [a_i * x + a_n_i * x_inv
            for (a_i, a_n_i) in zip(a[:n], a[n:])]
        b = [b_i * x_inv + b_n_i * x
            for (b_i, b_n_i) in zip(b[:n], b[n:])]

        # fold generators
        G = [G_i * x_inv + G_n_i * x
            for (G_i, G_n_i) in zip(G[:n], G[n:2*n])]
        H = [H_i * x + H_n_i * x_inv
            for (H_i, H_n_i) in zip(H[:n], H[n:2*n])]

    # append last 2 elements to IPA
    assert len(a) == 1 and len(b) == 1

    return InnerProductArgument(
        public_inputs=ipa,
        tail_end_scalars=(a[0], b[0]),
    )

def verify_folded_IPA(
    transcript: CashuTranscript,
    generators: Tuple[List[GroupElement], List[GroupElement], GroupElement],
    ipa: InnerProductArgument,
    P: GroupElement, # <- the commitment
    c: Scalar, # <- the inner product
) -> bool:
    log2_n = len(ipa.public_inputs)
    n = 1 << log2_n

    # Extract generators
    G, H, U = generators
    
    ## PROTOCOL 1 ##
    # `verify_folded_IPA` implements Protocol 2, a proof system for relation (3).
    # Protocol 1 (here) makes Protocol 2 into a proof system for relation (2).
    transcript.append(b"Com(P)_", P)
    tetha = transcript.get_challenge(b"tetha_chall_")

    # Switch generator U
    U = tetha*U
    # Tweak commitment P
    P += c*U
    ## END PROTOCOL 1 ##

    ## PROTOCOL 2 ##
    # Extract scalars of the recursion end from IPA
    a, b = ipa.tail_end_scalars

    # Get challenges
    challs = []
    for L, R in ipa.public_inputs:
        transcript.append(b"IPA_L_", L)
        transcript.append(b"IPA_R_", R)
        x = transcript.get_challenge(b"IPA_chall_")
        challs.append((x, x.invert()))

    # Recursion unrolling - We reduce O(n*log_2(n)) GroupElement multiplications
    # to O(n) by unrolling the prover's loop (we have the challenges) and
    # performing the O(log_2(n)) arithmetic operations on scalars instead.
    G_aH_b = O
    for i, (G_i, H_i) in enumerate(zip(G, H)):
        s = scalar_one
        for j, x in enumerate(reversed(challs)):
            # Use x if the j-th bit of i is 1
            # else use x^-1
            bit = (i>>j) & 1
            s *= x[bit^1]
        # Always pair 2 multiplications and 1 addition        
        G_aH_b += (a*s)*G_i + (b*s.invert())*H_i
    
    P_ = sum(
        [(x[0]*x[0])*L + (x[1]*x[1])*R
            for x, (L, R) in zip(challs, ipa.public_inputs)],
        P
    )
    
    return G_aH_b + (a*b)*U == P_

@dataclass
class BulletProof:
    
    A: GroupElement
    S: GroupElement
    T_1: GroupElement
    T_2: GroupElement
    t_x: Scalar
    tau_x: Scalar
    mu: Scalar
    ipa: InnerProductArgument

    @classmethod
    def create(
        cls,
        transcript: CashuTranscript,
        attributes: List[AmountAttribute],
    ) -> "BulletProof":
        # Domain separation
        transcript.domain_sep(b"Bulletproof_Statement_")

        # Extract amount scalar, blinding factor Scalar
        # and pedersen commitment
        a = [attribute.a for attribute in attributes]
        gamma = [attribute.r for attribute in attributes]
        V = [attribute.Ma for attribute in attributes]

        m = len(attributes)
        n = (RANGE_LIMIT-1).bit_length()

        # Decompose attribute's amounts into bits.
        a_left = []
        a_right = []
        for a_j in a:
            amount = int.from_bytes(a_j.to_bytes(), "big")
            for i in range(n):
                bit = (amount >> i) & 1
                a_left.append(Scalar(bit.to_bytes(32, "big")))
                a_right.append(Scalar((1-bit).to_bytes(32, "big")))
        
        # pad a_left and a_right to a len power of 2
        next_len_pow2 = 1 << (n*m).bit_length()
        if hamming_weight(n*m) != 1:
            a_left = pad(a_left, next_len_pow2)
            a_right = pad_one(a_right, next_len_pow2)
            m = next_len_pow2 // n

        # Append Ma and bit-length to the transcript
        for j, V_j in enumerate(V):
            transcript.append(f"Com(V_{j})_".encode(), V_j)
        transcript.append(b"Com(m)_", hash_to_curve(m.to_bytes(32, "big")))

        # Get generators
        G, H, U = get_generators(m*n)

        # Compute Com(A)
        alpha = Scalar()
        A = sum(
            [a_l_i * G_i + a_r_i * H_i
                for (a_l_i, G_i, a_r_i, H_i) in zip(a_left, G, a_right, H)],
            alpha * G_blind,
        )

        # Compute Com(S)
        rho = Scalar()
        s_l, s_r = [Scalar() for _ in a_left], [Scalar() for _ in a_right]
        S = sum(
            [s_l_i * G_i + s_r_i * H_i
                for (s_l_i, G_i, s_r_i, H_i) in zip(s_l, G, s_r, H)],
            rho * G_blind,
        )

        # Prover -> Verifier: A, S
        # Verifier -> Prover: y, z

        # Append A and S to transcript
        transcript.append(b"Com(A)_", A)
        transcript.append(b"Com(S)_", S)

        # Get y challenge
        y = transcript.get_challenge(b"y_chall_")

        # Commit y
        transcript.append(b"Com(y)_", hash_to_curve(y.to_bytes()))

        # Get z challenge
        z = transcript.get_challenge(b"z_chall_")
        
        zs = [scalar_one]
        for _ in range(1, 3+m):
            zs.append(zs[-1] * z)

        # Calculate ẟ(y, z)     Definition (between 71-72)
        p = z + zs[2]
        twos = SCALAR_POWERS_2

        ys = [scalar_one]
        for _ in range(1, n*m):
            ys.append(ys[-1] * y)

        delta_y_z = sum(
            [p * y_i + zs[3] * zs[i//n] * twos[i%n]
                for i, y_i in enumerate(ys)],
            scalar_zero
        )

        # l(X) and r(X) linear vector polynomials   (70-71)
        l: List[List[Scalar]] = [[], []]
        r: List[List[Scalar]] = [[], []]
        for j in range(m):
            for i in range(n):   
                l[0].append(a_left[j*n+i] + z)
                l[1].append(s_l[j*n+i])
                
                r[0].append(ys[j*n+i] * (a_right[j*n+i] + z)
                    + zs[2] * zs[j] * twos[i]
                )
                r[1].append(ys[j*n+i] * s_r[j*n+i])

        # t(X) = <l(X), r(X)> = t_0 + t_1 * X + t_2 * X^2
        
        # Calculate constant term t_0       
        #t_0_check = zs[2] * sum([a_j*z_j for (a_j, z_j) in zip(a, zs)], scalar_zero) + delta_y_z
        t_0 = inner_product(l[0], r[0])
        #print(f"{t_0 == t_0_check = }")
        #print(f"{t_0.serialize() = }\n{t_0_check.serialize() = }")

        # Calculate coefficient t_1. From definition (1)
        t_1 = inner_product(l[1], r[0]) + inner_product(l[0], r[1])

        # Calculate coefficient t_2. From definition (1)
        t_2 = inner_product(l[1], r[1])

        # Hide t_1, t_2 coefficients of t(x)
        # into Pedersen commitments     (52-53)
        tau_1, tau_2 = [Scalar() for _ in range(2)]
        T_1 = t_1 * G_amount + tau_1 * G_blind
        T_2 = t_2 * G_amount + tau_2 * G_blind

        # Prover -> Verifier: T_1, T_2
        # Verifier -> Prover: x

        # Append T_1, T_2 to transcript
        transcript.append(b"Com(T_1)_", T_1)
        transcript.append(b"Com(T_2)_", T_2)

        # Get challenge x (named x because used for evaluation of t(x))
        x = transcript.get_challenge(b"x_chall_")
        x_2 = x*x

        # now evaluate t(x) at x    (58-60)
        l_x = [l_0 + l_1 * x for l_0, l_1 in zip(l[0], l[1])]
        r_x = [r_0 + r_1 * x for r_0, r_1 in zip(r[0], r[1])]
        t_x = inner_product(l_x, r_x)

        # and compute tau_x (We blinded the coefficients, so we need to
        # take care of that)    (61)
        tau_0 = zs[2] * sum([g_j*z_j for g_j, z_j in zip(gamma, zs)], scalar_zero)
        tau_x = tau_0 + tau_1 * x + tau_2 * x_2

        # blinding factors for A, S     (62)
        mu = alpha + rho * x

        # Switch generators H -> y^n*H    (64)
        H_ = [y_i.invert()*H_i for y_i, H_i in zip(ys, H)]

        # Compute commitment P = l(x)*G + r(x)*H'
        P = sum(
            [l_x_i*G_i + r_x_i*H_i
                for (l_x_i, G_i, r_x_i, H_i) in zip(l_x, G, r_x, H_)],
            O
        )

        # Now instead of sending l and r we fold them.
        # We get the IPA for l, r.
        ipa = get_folded_IPA(transcript, (G, H_, U), P, l_x, r_x)

        # Prover -> Verifier: t_x, tau_x, mu, ipa

        return cls(
            A=A,
            S=S,
            T_1=T_1,
            T_2=T_2,
            t_x=t_x,
            tau_x=tau_x,
            mu=mu,
            ipa=ipa
        )

    def verify(
        self,
        transcript: CashuTranscript,
        attributes: List[GroupElement],
    ) -> bool:
        transcript.domain_sep(b"Bulletproof_Statement_")
        
        # Prover -> Verifier: A, S
        # Verifier -> Prover: y, z

        n = (RANGE_LIMIT-1).bit_length()
        len_pow2 = 1 << len(self.ipa.public_inputs)
        m = len_pow2 // n

        # Get generators
        G, H, U = get_generators(n*m)

        # Append Ma and bit-length to the transcript
        V = attributes
        for i, V_i in enumerate(V):
            transcript.append(f"Com(V_{i})_".encode("utf-8"), V_i)
        transcript.append(b"Com(n)_", hash_to_curve(n.to_bytes(32, "big")))

        # Append A and S to transcript
        A, S = self.A, self.S
        transcript.append(b"Com(A)_", A)
        transcript.append(b"Com(S)_", S)

        # Get y challenge
        y = transcript.get_challenge(b"y_chall_")

        # Commit y
        transcript.append(b"Com(y)_", hash_to_curve(y.to_bytes()))

        # Get z challenge
        z = transcript.get_challenge(b"z_chall_")
        zs = [scalar_one]
        for _ in range(1, 3+m):
            zs.append(zs[-1] * z)

        # Calculate ẟ(y, z)     Definition (39)
        p = z + zs[2]
        twos = SCALAR_POWERS_2
        ys = [scalar_one]
        for _ in range(1, len_pow2):
            ys.append(ys[-1] * y)
    
        delta_y_z = sum(
            [p * y_i + zs[3] * zs[i//n] * twos[i%n]
                for i, y_i in enumerate(ys)],
            scalar_zero
        )        

        # Prover -> Verifier: T_1, T_2
        # Verifier -> Prover: x

        # Append T_1, T_2 to transcript
        T_1, T_2 = self.T_1, self.T_2
        transcript.append(b"Com(T_1)_", T_1)
        transcript.append(b"Com(T_2)_", T_2)

        # Get challenge x (named x because used for evaluation of t(x))
        x = transcript.get_challenge(b"x_chall_")
        #print(f"{x.serialize() = }")
        x_2 = x*x

        # Switch generators H -> y^n*H    (64)
        H_ = [y_i.invert()*H_i for y_i, H_i in zip(ys, H)]

        t_x = self.t_x
        tau_x = self.tau_x
        # Check that t_x = t(x) = t_0 + t_1*x + t_2*x^2     (72)
        V_z_m = sum([zs[j] * V_j for j, V_j in enumerate(V)], O)
        if not t_x*G_amount + tau_x*G_blind == zs[2]*V_z_m + delta_y_z*G_amount + x*T_1 + x_2*T_2:
            return False

        # Compute commitment to l(x) and r(x)   (72)
        mu = self.mu
        P = -mu*G_blind + A + x*S
        for j in range(m):
            for i in range(n):
                P += (
                    z*G[j*n+i] + (z*ys[j*n+i])*H_[j*n+i] +
                    (zs[2]*zs[j]*twos[i])*H_[j*n+i]
                )

        # Check l and r are correct using IPA   (67)
        # Check t_x is correct                  (68)
        return verify_folded_IPA(transcript, (G, H_, U), self.ipa, P, t_x)

'''
# TESTING
cli_tscr = CashuTranscript()
mint_tscr = CashuTranscript()

a = [Scalar() for _ in range(96)] + [scalar_zero] * 32
b = [Scalar() for _ in range(96)] + [scalar_zero] * 32
P = sum(
    [a_i*G_i + b_i*H_i
        for (a_i, G_i, b_i, H_i) in zip(a, G, b, H)],
    O
)
ipa = get_folded_IPA(cli_tscr, get_generators(128), P, a, b)
assert len(ipa.public_inputs) == 7
c = inner_product(a, b)
assert verify_folded_IPA(mint_tscr, (G, H, U), ipa, P, c)

attributes = [AmountAttribute.create(14), AmountAttribute.create(1), AmountAttribute.create(11)] 
range_proof = BulletProof.create(cli_tscr, attributes)
assert range_proof.verify(mint_tscr, [att.Ma for att in attributes])
'''