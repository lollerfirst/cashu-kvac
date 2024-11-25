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
    _ = scalar*point

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

def bench_scalar_init():
    _ = Scalar(scalar_bytes)

def bench_group_element_init():
    _ = GroupElement(point_bytes)

h2c_time = timeit.timeit("bench_h2c()", globals=globals(), number=10000)
mul_time = timeit.timeit("bench_mul()", globals=globals(), number=10000)
add_time = timeit.timeit("bench_add()", globals=globals(), number=10000)
neg_time = timeit.timeit("bench_neg()", globals=globals(), number=10000)
sub_time = timeit.timeit("bench_sub()", globals=globals(), number=10000)

scalar_mul_time = timeit.timeit("bench_scalar_mul()", globals=globals(), number=10000)
scalar_add_time = timeit.timeit("bench_scalar_add()", globals=globals(), number=10000)
scalar_neg_time = timeit.timeit("bench_scalar_neg()", globals=globals(), number=10000)
scalar_sub_time = timeit.timeit("bench_scalar_sub()", globals=globals(), number=10000)

scalar_init_time = timeit.timeit("bench_scalar_init()", globals=globals(), number=10000)
group_element_init_time = timeit.timeit("bench_group_element_init()", globals=globals(), number=10000)

print("10000 iterations")
print(f"HashToCurve time: {h2c_time:.9f} seconds")
print(f"Scalar-Point multiplication time: {mul_time:.9f} seconds")
print(f"Point addition time: {add_time:.9f} seconds")
print(f"Point negation time: {neg_time:.9f} seconds")
print(f"Point subtraction time: {sub_time:.9f} seconds")
print("=======================================")
print(f"Scalar multiplication time: {scalar_mul_time:.9f} seconds")
print(f"Scalar addition time: {scalar_add_time:.9f} seconds")
print(f"Scalar negation time: {scalar_neg_time:.9f} seconds")
print(f"Scalar subtraction time: {scalar_sub_time:.9f} seconds")
print("=======================================")
print(f"Scalar instantiation time: {scalar_init_time:.9f} seconds")
print(f"GroupElement instantiation time: {group_element_init_time:.9f} seconds")