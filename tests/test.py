from src.kvac import *
from src.models import *
from src.secp import Scalar
import random
import pytest

@pytest.fixture
def transcripts():
    prove_transcript = CashuTranscript()
    verify_transcript = CashuTranscript()
    return prove_transcript, verify_transcript

@pytest.fixture
def mint_privkey():
    sk = [Scalar() for _ in range(6)]
    mint_privkey = MintPrivateKey(*sk)
    return mint_privkey

def test_iparams(transcripts, mint_privkey):   
    
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint verifies: range proof, balance proof and issues a MAC with a proof of mint_publickey. 
    mac = MAC.generate(mint_privkey, attribute.Ma)
    proof = prove_iparams(mint_transcript, mint_privkey, mac, attribute.Ma)

    # User verifies mint_publickey for issued attribute
    assert verify_iparams(cli_transcript, mac, mint_publickey, proof, attribute.Ma)

def test_wrong_iparams(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    sk = [Scalar() for _ in range(6)]
    different_mint_privkey = MintPrivateKey(*sk)

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint verifies: range proof, balance proof and issues a MAC with a proof of mint_publickey. 
    mac = MAC.generate(mint_privkey, attribute.Ma)
    proof = prove_iparams(mint_transcript, different_mint_privkey, mac, attribute.Ma)

    # User verifies mint_publickey for issued attribute
    assert not verify_iparams(cli_transcript, mac, mint_publickey, proof, attribute.Ma)

def test_mac(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint generates MAC
    mac = MAC.generate(mint_privkey, attribute.Ma)

    # User randomizes commitment and produces proof of MAC for it
    credentials = randomize_credentials(mac, attribute)
    proof_MAC = prove_MAC(cli_transcript, mint_publickey, credentials, mac, attribute)
    assert verify_MAC(mint_transcript, mint_privkey, credentials, proof_MAC)

def test_different_randomization(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    # Mint generates MAC
    mac = MAC.generate(mint_privkey, attribute.Ma)

    # user tries to randomize with another scalar
    k = Scalar()
    U = hash_to_curve(mac.t.to_bytes())
    Ca = k*Gz_attribute + attribute.Ma
    Cs = k*Gz_script + O
    Cx0 = k*X0 + U
    Cx1 = k*X1 + mac.t*U
    Cv = k*Gz_mac + mac.V

    credentials = RandomizedCredentials(Ca=Ca, Cs=Cs, Cx0=Cx0, Cx1=Cx1, Cv=Cv)

    proof_MAC = prove_MAC(cli_transcript, mint_publickey, credentials, mac, attribute)
    assert not verify_MAC(mint_transcript, mint_privkey, credentials, proof_MAC)

def test_balance(transcripts, mint_privkey):
    mint_publickey = (mint_privkey.Cw, mint_privkey.I)
    cli_transcript, mint_transcript = transcripts

    # User creates 1 attribute worth 16
    attribute = AmountAttribute.create(16)

    mac = MAC.generate(mint_privkey, attribute.Ma)
    credentials = randomize_credentials(mac, attribute)
    
    # Compute another credential worth 8
    new_attribute = AmountAttribute.create(8)

    # Prove the balance between randomized commitments and new attributes
    balance_proof = prove_balance(cli_transcript, [attribute], [new_attribute])

    assert verify_balance(mint_transcript,
        [credentials],
        [new_attribute.Ma],
        balance_proof,
        8
    )

'''

wrong_range_attr = AmountAttribute.create(RANGE_LIMIT)
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
wrong_script_attr = ScriptAttribute.create(b"\x99")
mac = MAC.generate(mint_privkey, bootstrap.Ma, script_attr.Ms)
randomized_creds = randomize_credentials(mac, bootstrap, script_attr)
script_proof = prove_script_equality([bootstrap], [script_attr], new_script_attr)
wrong_script_proof = prove_script_equality([bootstrap], [script_attr], [wrong_script_attr])
assert verify_script_equality([randomized_creds], [att.Ms for att in new_script_attr], script_proof)
assert not verify_script_equality([randomized_creds], [wrong_script_attr.Ms], wrong_script_proof)

print("Script equality proof successfully verified")
'''