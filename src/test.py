from kvac import (
    create_attribute,
    generate_MAC,
    prove_iparams,
    verify_iparams,
    randomize_commitment,
    prove_MAC_and_serial,
    verify_MAC_and_serial,
    prove_balance,
    verify_balance,
    prove_range,
    verify_range,
)
from secp import PrivateKey
from generators import (
    W, W_, X0, X1, A, G, Gv
)

# Mint's secret key <w, w_, x0, x1, ya>
w, w_, x0, x1, ya = [PrivateKey() for _ in range(5)]
sk = (w, w_, x0, x1, ya)

# Mint iparams <Cw, I> 
Cw = W.mult(w) + W_.mult(w_)
I = Gv + -(X0.mult(x0) + X1.mult(x1) + A.mult(ya))
iparams = (Cw, I)

# User creates 1 attribute worth 16
attribute = create_attribute(16)

# Mint verifies: range proof, balance proof and issues a MAC with a proof of iparams. 
mac = generate_MAC(attribute, sk)
proof = prove_iparams(sk, attribute, mac)

# User verifies iparams for issued attribute (no tagging plz)
assert verify_iparams(attribute, mac, iparams, proof)

print("iparams successfully verified!")

# User randomizes commitment and produces proof of MAC for it
commitmentset = randomize_commitment(attribute, mac)
proof_MAC_serial = prove_MAC_and_serial(iparams, commitmentset, mac, attribute)
serial = attribute.get_serial()
assert verify_MAC_and_serial(sk, commitmentset, serial, proof_MAC_serial)

print("MAC and Serial successfully verified")

# Compute another credential worth 32 and have it signed
new_attribute = create_attribute(8)

# Prove the balance between randomized commitments and new attributes
balance_proof = prove_balance([commitmentset], [attribute], [new_attribute])

assert verify_balance(
    [commitmentset.lose_secrets()],
    [new_attribute.lose_secrets()],
    balance_proof,
    8
)

print("Balance proof successfully verified")

range_proof = prove_range(attribute)
assert verify_range(attribute.lose_secrets(), range_proof)

print("Range proof successfully verified")