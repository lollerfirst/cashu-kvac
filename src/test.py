from kvac import (
    prove_iparams,
    verify_iparams,
    randomize_credentials,
    prove_MAC_and_serial,
    verify_MAC_and_serial,
    prove_balance,
    verify_balance,
    prove_range,
    verify_range,
)
from models import (
    Attribute,
    MAC
)
from secp import Scalar
from generators import (
    W, W_, X0, X1, A, G, Gv
)

# Mint's secret key <w, w_, x0, x1, ya>
w, w_, x0, x1, ya = [Scalar() for _ in range(5)]
sk = (w, w_, x0, x1, ya)

# Mint iparams <Cw, I> 
Cw = W*w + W_*(w_)
I = Gv + -(X0*x0 + X1*x1 + A*ya)
iparams = (Cw, I)

# User creates 1 attribute worth 16
attribute = Attribute.create(16)

# Mint verifies: range proof, balance proof and issues a MAC with a proof of iparams. 
mac = MAC.generate(attribute, sk)
proof = prove_iparams(sk, attribute, mac)

# User verifies iparams for issued attribute (no tagging plz)
assert verify_iparams(attribute, mac, iparams, proof)

print("iparams successfully verified!")

# User randomizes commitment and produces proof of MAC for it
credentials = randomize_credentials(attribute, mac)
proof_MAC_serial = prove_MAC_and_serial(iparams, credentials, mac, attribute)
serial = attribute.serial
assert verify_MAC_and_serial(sk, credentials, serial, proof_MAC_serial)

print("MAC and Serial successfully verified")

# Compute another credential worth 32 and have it signed
new_attribute = Attribute.create(8)

# Prove the balance between randomized commitments and new attributes
balance_proof = prove_balance([credentials], [attribute], [new_attribute])

assert verify_balance(
    [credentials.Ca],
    [new_attribute.Ma],
    balance_proof,
    8
)

print("Balance proof successfully verified")

range_proof = prove_range(attribute)
assert verify_range(attribute.Ma, range_proof)

print("Range proof successfully verified")