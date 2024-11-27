from .secp import Scalar, GroupElement, SCALAR_ZERO
from .transcript import CashuTranscript
from .generators import hash_to_curve

from dataclasses import dataclass

scalar_zero = Scalar(SCALAR_ZERO)

@dataclass
class InnerProductArgument:
    public_inputs: List[Tuple[GroupElement, GroupElement]] = []
    tail_end_scalars: Tuple[Scalar, Scalar] = None

def hamming_weight(n: int) -> int:
    sum( [x&(1<<i)>0 for i in range(n.bit_length())] )

def pad(l: List[Scalar], to: int) -> List[Scalar]:
    pad_len = to - ( len(l) % to )
    return l + [scalar_zero for _ in range(pad_len)]

def inner_product(l: List[Scalar], r: List[Scalar]) -> Scalar:
    return sum([ll * rr for ll, rr in zip(l, r)], scalar_zero)

# https://eprint.iacr.org/2017/1066.pdf
def get_folded_IPA(
    transcript: CashuTranscript,
    a: List[Scalar],
    b: List[Scalar]
) -> InnerProductArgument:
    assert len(a) == len(b), "the two lists have different length"

    # Ensure len is a power of 2
    len_pow2 = 1 << (len(a).bit_length()-1)
    next_len_pow2 = 1 << len(a).bit_length()
    if hamming_weight(len(a)) != 1:
        a = pad(a, next_len_pow2)
        b = pad(b, next_len_pow2)
        len_pow2 = next_len_pow2

    # Get generators (Could be hard-coded)
    G = [hash_to_curve(f"IPA_G_{i}_".encode("utf-8"))
        for i in range(len_pow2)]
    H = [hash_to_curve(f"IPA_H_{i}_".encode("utf-8"))
        for i in range(len_pow2)]
    U = hash_to_curve(b"IPA_U_")

    ipa = InnerProductArgument()

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
                in zip(a[:n], G[n:], b[n:], H[:n])],
            c_left * U
        )
        R = sum(
            [a_i * G_i + b_i * H_i for (a_i, G_i, b_i, H_i)
                in zip(a[n:], G[:n], b[:n], H[n:])],
            c_right * U
        )

        ipa.public_inputs.append((L, R))
        
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
            for (G_i, G_n_i) in zip(G[:n], G[n:])]
        H = [H_i * x + H_n_i * x_inv
            for (H_i, H_n_i) in zip(H[:n], H[n:])]

    # append last 2 elements to IPA
    assert len(a) == 1 and len(b) == 1
    ipa.tail_end_scalars.append((a[0], b[0]))

    return ipa