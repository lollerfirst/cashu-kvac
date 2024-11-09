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
    prove_bootstrap,
    verify_bootstrap,
)
from models import (
    Attribute,
    MAC,
    MintPrivateKey,
)
from secp import Scalar

# Mint's secret key
sk = [Scalar() for _ in range(6)]
mint_privkey = MintPrivateKey(*sk)
iparams = (mint_privkey.Cw, mint_privkey.I)

# User creates 1 attribute worth 16
attribute = Attribute.create(16)

# Mint verifies: range proof, balance proof and issues a MAC with a proof of iparams. 
mac = MAC.generate(attribute.Ma, mint_privkey)
proof = prove_iparams(mint_privkey, attribute.Ma, mac)

# User verifies iparams for issued attribute (no tagging plz)
assert verify_iparams(attribute.Ma, mac, iparams, proof)

print("iparams successfully verified!")

# User randomizes commitment and produces proof of MAC for it
credentials = randomize_credentials(attribute, mac)
proof_MAC_serial = prove_MAC_and_serial(iparams, credentials, mac, attribute)
serial = attribute.serial
assert verify_MAC_and_serial(mint_privkey, credentials, serial, proof_MAC_serial)

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

bootstrap = Attribute.create(0)
proof_bootstrap = prove_bootstrap(bootstrap)
assert verify_bootstrap(bootstrap.Ma, proof_bootstrap)

print("Bootstrap attribute successfully verified")