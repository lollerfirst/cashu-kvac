import timeit
import random
from src.kvac import *

# Mint's private/public keys
sk = [Scalar() for _ in range(6)]
mint_privkey = MintPrivateKey(*sk)
mint_pubkey = (mint_privkey.Cw, mint_privkey.I)

# Client's transcript
client_tscr = CashuTranscript()

# Mint's transcript
mint_tscr = CashuTranscript()

bootstrap = AmountAttribute.create(0)
script_attr = ScriptAttribute.create(b"\x00"*32)
mac_0 = MAC.generate(mint_privkey, bootstrap.Ma, script_attr.Ms)

attr_16 = AmountAttribute.create(16)

proof = None

def bench_bootstrap_prove():
    global proof
    proof = prove_bootstrap(client_tscr, bootstrap)

def bench_bootstrap_verify():
    verify_bootstrap(mint_tscr, bootstrap.Ma, proof)

def bench_iparams_prove():
    global proof
    proof = prove_iparams(mint_tscr, mint_privkey, mac_0, bootstrap.Ma, script_attr.Ms)

def bench_iparams_verify():
    verify_iparams(client_tscr, mac_0, mint_pubkey, proof, bootstrap.Ma, script_attr.Ms)

def bench_range_prove():
    global proof
    proof = prove_range(client_tscr, attr_16)

def bench_range_verify():
    verify_range(mint_tscr, attr_16.Ma, proof)

def run_benchmark(func_name, repeat=1000, number=1):
    """Runs a benchmark and returns average, min, and max execution times."""
    times = timeit.repeat(f"{func_name}()", globals=globals(), repeat=repeat, number=number)
    tot_time = sum(times)
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    return tot_time, avg_time, min_time, max_time

benchmarks = [
    ("Bootstrap Prove", "bench_bootstrap_prove"),
    ("Bootstrap Verify", "bench_bootstrap_verify"),
    ("Iparams Prove", "bench_iparams_prove"),
    ("Iparams Verify", "bench_iparams_verify"),
    ("Range Prove", "bench_range_prove"),
    ("Range Verify", "bench_range_verify")
]

print(f"{'Benchmark':<30}{'Average Time (s)':<20}{'Min Time (s)':<20}{'Max Time (s)':<20}{'Total Time (s)':<20}")
print("=" * 100)
for name, func in benchmarks:
    tot_time, avg, min_time, max_time = run_benchmark(func)
    print(f"{name:<30}{avg:<20.9f}{min_time:<20.9f}{max_time:<20.9f}{tot_time:<20.9f}")
