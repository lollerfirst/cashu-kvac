from .merlin.merlin import MerlinTranscript
from .secp import Scalar

class CashuTranscript:
    t: MerlinTranscript

    def __init__(self):
        self.t = MerlinTranscript(b"Secp256k1_Cashu_")

    def domain_sep(self, label: bytes, message: bytes):
        self.t.commit_bytes(label, message)
    
    def append(self, label: bytes, element: GroupElement):
        message = element.serialize(True)
        self.t.commit_bytes(label, message)

    def get_challenge(self, label: bytes) -> Scalar:
        challenge_bytes = self.t.get_challenge_bytes(label, 32)
        c = Scalar(challenge_bytes)
        assert not c.is_zero, "got challenge == SCALAR_ZERO"
        return c