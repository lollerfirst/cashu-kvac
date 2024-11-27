from .secp import Scalar, GroupElement, SCALAR_ZERO
from .transcript import CashuTranscript
from .generators import hash_to_curve, O

from dataclasses import dataclass
from typing import List, Tuple

scalar_zero = Scalar(SCALAR_ZERO)
scalar_one = Scalar(int(1).to_bytes(32, 'big'))

# Get generators (Could be hard-coded)
G = [hash_to_curve(f"IPA_G_{i}_".encode("utf-8"))
    for i in range(64)]
H = [hash_to_curve(f"IPA_H_{i}_".encode("utf-8"))
    for i in range(64)]
U = hash_to_curve(b"IPA_U_")
#print(f"G (before) = {[G_i.serialize(True).hex() for G_i in G]}")

@dataclass
class InnerProductArgument:
    public_inputs: List[Tuple[GroupElement, GroupElement]]
    tail_end_scalars: Tuple[Scalar, Scalar]

def hamming_weight(n: int) -> int:
    sum( [n&(1<<i)>0 for i in range(n.bit_length())] )

def pad(l: List[Scalar], to: int) -> List[Scalar]:
    pad_len = to - ( len(l) % to )
    return l + [scalar_zero for _ in range(pad_len)]

def inner_product(l: List[Scalar], r: List[Scalar]) -> Scalar:
    return sum([ll * rr for ll, rr in zip(l, r)], scalar_zero)

# https://eprint.iacr.org/2017/1066.pdf
def get_folded_IPA(
    transcript: CashuTranscript,
    generators: Tuple[List[GroupElement], List[GroupElement], GroupElement],
    a: List[Scalar],
    b: List[Scalar]
) -> InnerProductArgument:
    assert len(a) == len(b), "the two lists have different length"

    # Extract generators
    G, H, U = generators

    # Ensure len is a power of 2
    len_pow2 = 1 << (len(a).bit_length()-1)
    next_len_pow2 = 1 << len(a).bit_length()
    if hamming_weight(len(a)) != 1:
        a = pad(a, next_len_pow2)
        b = pad(b, next_len_pow2)
        len_pow2 = next_len_pow2

    ipa = []

    # Recursive subdivision
    n = len_pow2
    while n > 1:
        n >>= 1
        c_left = inner_product(a[:n], b[n:])
        c_right = inner_product(a[n:], b[:n])
        # REMEMBER: always pair multiplications
        # so then in the C impl we can go faster with Shamir's trick.
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
        #print(f"{x.serialize() = }")
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
        print(f"fold: {G[0].serialize(True).hex() = }")

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
) -> bool:
    log2_n = len(ipa.public_inputs)
    n = 1 << log2_n

    # Extract generators
    G, H, U = generators
    print(f"{len(G) = } {len(H) = }")
    # extract scalars of the recursion end from IPA
    a, b = ipa.tail_end_scalars

    # get challenges
    x = []
    for L, R in ipa.public_inputs:
        transcript.append(b"IPA_L_", L)
        transcript.append(b"IPA_R_", R)
        chall = transcript.get_challenge(b"IPA_chall_")
        x.append((chall, chall.invert()))
        #print(f"{chall.serialize() = }")

    print(f"{n = }")
    print(f"{len(x) = }")
    # fold generators
    for chal, chal_inv in x:
        n >>= 1
        G = [G_i * chal_inv + G_n_i * chal
            for (G_i, G_n_i) in zip(G[:n], G[n:2*n])]
        H = [H_i * chal + H_n_i * chal_inv
            for (H_i, H_n_i) in zip(H[:n], H[n:2*n])]
        print(f"{len(G) = }")
        print(f"unroll: {G[0].serialize(True).hex() = }")

    G_a = a*G[0]
    H_b = b*H[0]
    '''
    # Recursion unrolling - let's try to get this right...
    G_a = O
    H_b = O
    for i in range(n):
        G_i = G[i]
        H_i = H[i]
        for j in range(log2_n):
            # Use x if the j-th bit of i is 1
            # else use x^-1
            bit = (i>>j) & 1
            G_i *= x[j][bit^1]
            H_i *= x[j][bit]
          
        G_a += a*G_i
        H_b += b*H_i
    print(f"{G_unrolled.serialize(True).hex() = }")
    '''
    P_ = sum(
        [(x[j][0]*x[j][0])*L + (x[j][1]*x[j][1])*R
            for j, (L, R) in enumerate(ipa.public_inputs)],
        P
    )
    
    return G_a + H_b + (a*b)*U == P_

cli_tscr = CashuTranscript()
mint_tscr = CashuTranscript()
a = [Scalar() for _ in range(51)]
b = [Scalar() for _ in range(51)]
P = sum(
    [a_i*G_i + b_i*H_i
        for (a_i, G_i, b_i, H_i) in zip(a, G, b, H)],
    inner_product(a, b) * U
)
ipa = get_folded_IPA(cli_tscr, (G, H, U), a, b)
#print(f"G (after) = {[G_i.serialize(True).hex() for G_i in G]}")
assert len(ipa.public_inputs) == 6
assert verify_folded_IPA(mint_tscr, (G, H, U), ipa, P)
