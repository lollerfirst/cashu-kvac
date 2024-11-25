import timeit
import random
from secp256k1 import PrivateKey, PublicKey
from src.generators import hash_to_curve

scalar_bytes = random.randbytes(32)
scalar_bytes1 = random.randbytes(32)
point = PrivateKey(scalar_bytes, raw=True).pubkey
point1 = PrivateKey(scalar_bytes1, raw=True).pubkey
scalar = PrivateKey(scalar_bytes, raw=True)
scalar1 = PrivateKey(scalar_bytes1, raw=True)

point_bytes = point.serialize(True)

def bench_mul():
    _ = point.tweak_mul(scalar.private_key)

def bench_add():
    _ = point.combine([point.public_key, point1.public_key])

def bench_scalar_mul():
    _ = scalar.tweak_mul(scalar1.private_key)

def bench_scalar_add():
    _ = scalar.tweak_add(scalar1.private_key)

def bench_scalar_init():
    _ = PrivateKey(scalar_bytes, raw=True)

def bench_group_element_init():
    _ = PublicKey(point_bytes, raw=True)

'''
def bench_neg():
    _ = point.__neg__()

def bench_sub():
    _ = point.tweak_add()

def bench_scalar_neg():
    _ = -scalar1

def bench_scalar_sub():
    _ = scalar - scalar1
'''

def run_benchmark(func_name, repeat=10000, number=1):
    """Runs a benchmark and returns average, min, and max execution times."""
    times = timeit.repeat(f"{func_name}()", globals=globals(), repeat=repeat, number=number)
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    return avg_time, min_time, max_time

benchmarks = [
    ("PrivateKey-Point Multiplication", "bench_mul"),
    ("Point Addition", "bench_add"),
    #("Point Negation", "bench_neg"),
    #("Point Subtraction", "bench_sub"),
    ("PrivateKey Multiplication", "bench_scalar_mul"),
    ("PrivateKey Addition", "bench_scalar_add"),
    #("PrivateKey Negation", "bench_scalar_neg"),
    #("PrivateKey Subtraction", "bench_scalar_sub"),
    ("PrivateKey Instantiation", "bench_scalar_init"),
    ("PublicKey Instantiation", "bench_group_element_init"),
]

print(f"{'Benchmark':<33}{'Average Time (s)':<20}{'Min Time (s)':<20}{'Max Time (s)':<20}")
print("=" * 84)
for name, func in benchmarks:
    avg, min_time, max_time = run_benchmark(func)
    print(f"{name:<33}{avg:<20.9f}{min_time:<20.9f}{max_time:<20.9f}")
