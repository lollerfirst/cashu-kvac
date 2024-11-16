from kvac import *
from models import *
from secp import Scalar
import random

# Mint's secret key
sk = [Scalar() for _ in range(6)]
mint_privkey = MintPrivateKey(*sk)
iparams = (mint_privkey.Cw, mint_privkey.I)

# User creates 1 attribute worth 16
attribute = AmountAttribute.create(16)

# Mint verifies: range proof, balance proof and issues a MAC with a proof of iparams. 
mac = MAC.generate(mint_privkey, attribute.Ma)
proof = prove_iparams(mint_privkey, mac, attribute.Ma)

# User verifies iparams for issued attribute (no tagging plz)
assert verify_iparams(mac, iparams, proof, attribute.Ma)

print("iparams successfully verified!")

# User randomizes commitment and produces proof of MAC for it
credentials = randomize_credentials(mac, attribute)
proof_MAC = prove_MAC(iparams, credentials, mac, attribute)
assert verify_MAC(mint_privkey, credentials, proof_MAC)

print("MAC and Serial successfully verified")

# Compute another credential worth 8
new_attribute = AmountAttribute.create(8)

# Prove the balance between randomized commitments and new attributes
balance_proof = prove_balance([attribute], [new_attribute])

assert verify_balance(
    [credentials],
    [new_attribute.Ma],
    balance_proof,
    8
)

print("Balance proof successfully verified")

wrong_range_attr = AmountAttribute.create(2**52)
range_proof = prove_range(attribute)
wrong_range_proof = prove_range(wrong_range_attr)
assert verify_range(attribute.Ma, range_proof)
assert not verify_range(wrong_range_attr.Ma, wrong_range_proof)

print("Range proof successfully verified")

bootstrap = AmountAttribute.create(0)
wrong_bootstrap = AmountAttribute.create(1)
proof_bootstrap = prove_bootstrap(bootstrap)
wrong_proof_bootstrap = prove_bootstrap(wrong_bootstrap)
assert verify_bootstrap(bootstrap.Ma, proof_bootstrap)
assert not verify_bootstrap(wrong_bootstrap.Ma, wrong_proof_bootstrap)

print("Bootstrap attribute successfully verified")

# Script
script = random.randbytes(32)
script_attr = ScriptAttribute.create(script)
new_script_attr = [ScriptAttribute.create(script) for _ in range(6)]
wrong_script_attr = ScriptAttribute.create(b'\x99')
mac = MAC.generate(mint_privkey, bootstrap.Ma, script_attr.Ms)
randomized_creds = randomize_credentials(mac, bootstrap, script_attr)
script_proof = prove_script_equality([bootstrap], [script_attr], new_script_attr)
wrong_script_proof = prove_script_equality([bootstrap], [script_attr], [wrong_script_attr])
assert verify_script_equality([randomized_creds], [att.Ms for att in new_script_attr], script_proof)
assert not verify_script_equality([randomized_creds], [wrong_script_attr.Ms], wrong_script_proof)

print("Script equality proof successfully verified")