# Deterministic recovery of Amount Attributes

### Normal execution:

* Client generates: $t = \text{BIP39}(\text{seed}, \text{"t"}, d)$ where $d$ is some derivation.

* Mint generates $U = \text{HashToCurve}(t)$ as usual

* Mint stores $(M_a, t)$

### Recovery:
* Client pre-computes (or has already saved) a hash-table `T`, mapping $iG_\text{amount}$ to $i$ for $i \in [0, b)$, where
    $b$ is some upper bound on the possible amount.

* Client derives $r = \text{BIP39}(\text{seed}, \text{"r"}, d)$, $t = \text{BIP39}(\text{seed}, \text{"t"}, d)$

* Client asks the server (Mint) for the $M_a$ associated with a $t$

* Client unblinds the amount attribute: $A = M_a - rG_\text{blind}$.

* Client obtains $a$ from a table lookup on `T`: `a = T[A]`
