# Deterministic recovery of Amount Attributes

### Normal execution:

During a normal swap/mint/melt operation, the client generates a tag $t$ deterministically with its wallet master key and an appropriately chosen derivation path. Each output in the request is identified by its own $t^i$. After the request is successful, the Mint stores the attributes
in the outputs of the request $(M_a^i, t^i)$ in its database.

### Recovery:

Recovery works as follows:

* For each possible output $i$ the client derives its blinding factor $r_a^i$ and its tag $t_a^i$. 

* The Client then requests the server (Mint) for the $M_a^i$ associated with each $t^i$

* Once obtained the attributes, the client unblinds them: $A^i = M_a^i - r_a^i\cdot G_\text{blind}$.

* Now $A = a\cdot G_\text{amount}$ with $a \in [0, B]$.

$B$ is smaller or equal to the largest amount that the wallet ever contained. So for example $B < 100000 \ \text{sats}$.

At this point all the client has to do to find the correct amount is attack the DL. This is extremely easy since $B$ is so small. In the case of $B < 100000$, it's doable with less than $316$ iterations of the [Baby-Step-Giant-Step algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step).

Here follows an example implementation:
```python
from sympy.ntheory import nextprime
from random import getrandbits
from math import sqrt, ceil

p = nextprime(getrandbits(256))
print(f"{p = }")

# Amount to find
a = 1097

# Generator (G_amount)
g = 2

# Unblinded amount commitment
A = pow(g, a, p)

# Bound on the amounts
B = 100000

m = ceil(sqrt(B))
g_m_inv = pow(g, -m, p)

table = {}
iterations = 0
for j in range(m):
    iterations += 1
    index = pow(g, j, p)
    table[index] = j

x = -1
V = A
for i in range(m):
    iterations += 1
    if V in table:
        x = i*m + table[V]
        break
    else:
        V *= g_m_inv
        V %= p

print(f"{x = }")
print(f"{iterations = }")
```

### Recovery Spent Checks:

As with normal ecash, the client will later have to requestsep arate "nullifier state check" to the Mint in order to determine the spendability of each output they just recovered. This has privacy compromising implications