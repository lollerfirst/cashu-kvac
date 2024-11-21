from extension._merlin import ffi, lib

class MerlinTranscript:
    
    def __init__(self, label: bytes):
        if len(label) == 0:
            raise Exception("Cannot instantiate a transcript with no label")
        self.mctx = ffi.new("merlin_transcript*")
        lib.merlin_transcript_init(self.mctx, label, len(label))

    def __enter__(self):
        return self

    def __exit__(self, _, __, ___):
        pass

    def __copy__(self):
        raise TypeError(f"Copying of {self.__class__.__name__} is not allowed")

    def __deepcopy__(self, memo):
        raise TypeError(f"Deep copying of {self.__class__.__name__} is not allowed")

    def commit_bytes(self, label: bytes, data: bytes) -> None:
        if len(label) == 0 or len(data) == 0:
            raise Exception("Cannot commit to bytestrings of length 0")
        lib.merlin_transcript_commit_bytes(self.mctx, label, len(label), data, len(data))
    
    def get_challenge_bytes(self, label: bytes, size: int) -> bytes:
        if not 0 < size < (1<<32):
            raise Exception("Requested a challenge of invalid size")
        if len(label) == 0:
            raise Exception("Label of size zero is not allowed")
        buffer = ffi.new("uint8_t[]", size)
        lib.merlin_transcript_challenge_bytes(
            self.mctx,
            label,
            len(label),
            buffer,
            size
        )
        return bytes(ffi.buffer(buffer, size))

'''
# Testing

import random
import string

def random_label(length=10):
    return bytes(''.join(random.choices(string.ascii_letters + string.digits, k=length)), 'utf-8')

# Create a random label for testing
label = random_label()
size = 32  # Size for the challenge bytes

# Testing the MerlinTranscript class within a context manager
with MerlinTranscript(label) as transcript:
    print(f"Successfully created MerlinTranscript with label: {label}")
    
    # Commit some data
    commit_label = random_label()
    data = bytes("Some random data", 'utf-8')
    transcript.commit_bytes(commit_label, data)
    print(f"Committed data: {data} with label: {commit_label}")
    
    # Request challenge bytes
    challenge_bytes = transcript.get_challenge_bytes(commit_label, size)
    print(f"Challenge bytes: {challenge_bytes}")

print("Test completed successfully.")
'''