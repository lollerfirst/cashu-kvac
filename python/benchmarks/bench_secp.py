import timeit
import random
from src.secp import Scalar, GroupElement
from src.generators import hash_to_curve

scalar_bytes = random.randbytes(32)
scalar_bytes1 = random.randbytes(32)
point = hash_to_curve(scalar_bytes)
point1 = hash_to_curve(scalar_bytes1)
scalar = Scalar(scalar_bytes)
scalar1 = Scalar(scalar_bytes1)

point_bytes = point.serialize(True)

def bench_h2c():
    _ = hash_to_curve(scalar_bytes)

def bench_mul():
    _ = scalar * point

def bench_add():
    _ = point + point1

def bench_neg():
    _ = -point1

def bench_sub():
    _ = point - point1

def bench_scalar_mul():
    _ = scalar * scalar1

def bench_scalar_add():
    _ = scalar + scalar1

def bench_scalar_neg():
    _ = -scalar1

def bench_scalar_sub():
    _ = scalar - scalar1

def bench_scalar_invert():
    _ = scalar.invert()

def bench_scalar_init():
    _ = Scalar(scalar_bytes)

def bench_group_element_init():
    _ = GroupElement(point_bytes)

def run_benchmark(func_name, repeat=10000, number=1):
    """Runs a benchmark and returns average, min, and max execution times."""
    times = timeit.repeat(f"{func_name}()", globals=globals(), repeat=repeat, number=number)
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    return avg_time, min_time, max_time

benchmarks = [
    ("HashToCurve", "bench_h2c"),
    ("Scalar-Point Multiplication", "bench_mul"),
    ("Point Addition", "bench_add"),
    ("Point Negation", "bench_neg"),
    ("Point Subtraction", "bench_sub"),
    ("Scalar Multiplication", "bench_scalar_mul"),
    ("Scalar Addition", "bench_scalar_add"),
    ("Scalar Negation", "bench_scalar_neg"),
    ("Scalar Subtraction", "bench_scalar_sub"),
    ("Scalar Modular Inversion", "bench_scalar_invert"),
    ("Scalar Instantiation", "bench_scalar_init"),
    ("GroupElement Instantiation", "bench_group_element_init"),
]

print(f"{'Benchmark':<30}{'Average Time (s)':<20}{'Min Time (s)':<20}{'Max Time (s)':<20}")
print("=" * 80)
for name, func in benchmarks:
    avg, min_time, max_time = run_benchmark(func)
    print(f"{name:<30}{avg:<20.9f}{min_time:<20.9f}{max_time:<20.9f}")
