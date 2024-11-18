# Deterministic recovery of HMACs

### Normal execution:

* Client generates: $t' = \text{BIP39}(\text{seed}, \text{"t"}, d)$ where $d$ is some derivation.

* Mint takes $t = \text{Hash}(t')$. This step might be unnecessary since HashToCurve should be secure for arbitrary inputs

* Mint generates $U = \text{HashToCurve}(t)$ as usual

* Mint stores $(M_a, t)$

### Recovery:
* $r = \text{BIP39}(\text{seed}, \text{"r"}, d')$, where $d'$ is some derivation

* Client asks the server (Mint) for the $M_a$ associated with a $t'$

* Client starts with $M'_a \leftarrow rH$ and  $i \leftarrow 0$ and an upper bound on the iterations $b$. Then it checks whether $M'_a \overset{?}= M_a$:
    - If true, then $a = i$
    - If it's not, $M'_a \leftarrow M'_a + G$ and $i \leftarrow i+1$ and repeat the check. 
