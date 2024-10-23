# Deterministic recovery of HMACs

### Normal execution:

* Client generates: $t' = \text{HMAC}(\text{seed}, \text{"t"}, i)$

* Mint takes $t = Hash(t')$. This step might be unnecessary since HashToCurve should be secure for arbitrary inputs

* Mint generates $U = \text{HashToCurve}(t)$ as usual

* Mint stores $(M_a, t)$

### Recovery:
* $r = \text{HMAC}(\text{seed}, \text{"r"}, i)$

* Client asks the server (Mint) for the $M_a$ associated with a $t'$

* Client starts with $M'_a \leftarrow rH$ and  $i \leftarrow 0$ and an upper bound on the iterations $b$. Then it checks whether $M'_a \overset{?}= M_a$:
    - If true, then $a = i$
    - If it's not, $M'_a \leftarrow M'_a + G$ and $i \leftarrow i+1$ 
