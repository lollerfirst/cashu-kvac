## Definitions

### `Scalar` and `GroupElement`
> [Scalar](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/secp.py#L11)

A `Scalar` is an element of group $\mathbb{Z}_q$, where $q$ is prime and is also called the order of the group.
`Scalar` is also commonly referred to as `PrivateKey` and in cashu-kvac `Scalar` is a wrap-around secp256k1-py's `PrivateKey` with some added functionality.

> [GroupElement](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/secp.py#L74)

A `GroupElement` is a point on the *secp256k1* curve ($\mathbb{G}$). Also commonly referred to as `PublicKey`, in cashu-kvac it is indeed a wrap-around secp256k1-py's `PublicKey` similarly to `Scalar`.


### Generators
> [Generators](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/generators.py#L20)

Generators are points on the `secp256k1` curve can be used as a basis from which it's possible to compute any other point on the curve through repetitive adding.

The term "generator" here is used loosely. While NUMS points might not necessarily generate the entire group of points on the curve, they can still be considered generators in the sense that they can be used to derive a large number of other points through repeated point addition.

In KVAC, different generators are used for specific purposes. Each generator is derived using NUMS (`HashToCurve`) to ensure the discrete logarithm relationship between any pair of them remains unknown:
- $G_w, G_{w'}, G_{x_0}, G_{x_1}$: Used for computing the algebraic `MAC` (on the mint's side) and later for presenting credentials (on the client's side).
- $G_\text{zmac}, G_\text{zamount}, G_\text{zscript}$: Used for randomizing the `MAC` alongside `AmountAttribute` and `ScriptAttribute`.
- $G_\text{amount}, G_\text{script}$: Encode amounts into an `AmountAttribute` and scripts into a `ScriptAttribute`.
- $G_\text{blind}$: Utilized for blinding terms in `AmountAttribute` and `ScriptAttribute`.

### Mint Private Key
> [MintPrivateKey](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L10)

In KVAC, a keyset is a single tuple of six secret values (for all amounts):
```math
sk = (w, w', x_0, x_1, y_a, y_s)
```

* $y_a$: Private key for signing `AmountAttributes`.
* $y_s$: Private key for signing `ScriptAttributes`.
* $w, w', x0, x1$: additional secret values needed for security hardening of the scheme.

### Mint Public Parameters
> [MintPublicKey](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L30)

The Mint's "public key" is a tuple $(I, C_w)$, calculated as:

* $I = G_\text{zmac} - (x_0G_{x_0} + x_1G_{x_1} + y_aG_\text{zamount} + y_sG_\text{zscript})$
* $C_w = wG_w + w'G_{w'}$

### AmountAttribute
> [AmountAttribute](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L89)

A point encoding an amount `a` with blindness `r_a`.
Composition:
* $r_a \leftarrow \text{BIP39}(\text{seed}, \text{"r-amount"}, \text{derivation})$
* secret: $(a, r_a)$
* public: $M_a = r_aG_\text{blind} + aG_\text{amount}$

### Bootstrap AmountAttribute
Simply a `AmountAttribute` encoding $0$.
Composition:
* $r_a \leftarrow \text{BIP39}(\text{seed}, \text{"r-amount"}, \text{derivation})$
* secret: $(r_a)$
* public: $M_a = r_aG_\text{blind}$

### ScriptAttribute
> [ScriptAttribute](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L48)

A point encoding a script hash `s` with blindness `r_s`.
Composition:
* $r_s \leftarrow \text{BIP39}(\text{seed}, \text{"r-script"}, \text{derivation})$
* secret: $(s, r_s)$
* public: $M_s = r_sG_\text{blind} + sG_\text{script}$

### MAC
> [MAC](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L140)

Equivalent to Cashu's `BlindedSignature`.

The Mint generates this algebraic MAC using its secret parameters (`sk`) after verifying `RandomizedCredentials` (see section Protocol). This MAC binds the `AmountAttribute` and `ScriptAttribute` together, ensuring neither can be presented alone.

Here $t$ can be picked by both the Mint or the wallet. If the wallet picks it, they will have to send it together with the `AmountAttribute` (and possibly `ScriptAttribute`).

The main advantage of letting the wallet derive $t$ from seed is that we
can later leverage this for a recovery scheme that does not leak information to the Mint.

Composition:
* $t \overset{\\$}\leftarrow Z_q$ (Mint) or $t \leftarrow \text{BIP39}(\text{seed}, \text{"t"}, \text{derivation})$ (wallet)
* $M_a$ from `AmountAttribute`
* $M_s$ from `ScriptAttribute` or point at infinity if no script.
* $U = \text{HashToCurve}(t)$
* $V = wG_w + x_0U + x_1tU + y_aM_a + y_sM_s$
* MAC: $(t, V)$

### Credentials
We consider the `MAC` together with `AmountAttribute` and `ScriptAttribute` to be a set of credentials.

### RandomizedCredentials
> [RandomizedCredentials](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L472)

Before being sent to the Mint, the credentials are "randomized" to break the link to the issuance.
In other words, they are blinded a second time with a different generator.

We use the blinding term $r_a$ used for `AmountAttribute` and compute:

* $U = \text{HashToCurve}(t)$, where $t$ is the `MAC` scalar value
* $C_a = r_aG_\text{zamount} + M_a$
* $C_s = r_aG_\text{zscript} + M_s$
* $C_{x_0} = r_aG_{x_0} + U$
* $C_{x_1} = r_aG_{x_1} + tU$
* $C_v = r_aG_\text{zmac} + V$, where $V$ is the `MAC` public point value
* RandomizedCredentials: $(C_a, C_s, C_{x_0}, C_{x_1}, C_v)$

> [!NOTE]
> $r_a$ is the only scalar that will produce a valid randomization.

### Tweaking the amount in AmountAttribute
> [tweak amount](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/models.py#L126)

Amounts can be tweaked by both the Mint and client to produce new attributes that encode $a + \delta_a$.
* $M_a' = M_a + \delta_aG_\text{amount}$

### Nullifiers
Nullifiers are values (or a single value) used to mark credentials as spent, ensuring they cannot be reused. In the Cashu protocol, the nullifier for a coin is typically the $Y$ value within the `Proof` object.

Here, we decide to use $C_a$ from the `RandomizedCredentials` as the nullifier. The rationale is rooted in the design of $\pi_\text{MAC}$, which requires $C_a$ to be constructed using the same witness term $r_a$ for both blinding and randomization. This dependency ensures that there is only one valid way to randomize $M_a$ while maintaining valid credentials. Consequently, $C_a$ is guaranteed to be unique and suitable as a nullifier.

### Proof of same secret keys ($\pi_\text{iparams}$)
> [IparamsStatement](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L187)

Proof $\pi_\text{iparams}$ of knowledge of $(w, w', x_0, x_1, y_a)$ such that:

1) $w, w'$ were used to construct $C_w$:
```math
C_w = wG_w + w'G_{w'}
```
2) $x0, x1, y_a, y_s$ were used to construct $I$:
```math
G_v - I = x_0G_{x_0} + x_1G_{x_1} + y_aG_\text{z-amount} + y_sG_\text{z-script}
```
3) the same secret values were used to construct $V$:
```math
V = wG_w + x_0U + x_1tU + y_aM_a + y_sM_s
```

This is the equivalent of Cashu's current DLEQ proofs, where the Mint proves to the client they are signing with the same
keys as for everybody else (no tagging).

<!--
construction:
```math
\displaylines{
\begin{align}
sk &= (w, w', x_0, x_1, y_a)\\
\mathbf{k} &\overset{$}\leftarrow Z_q^{5}\\
R_0 &= k_0G_w + k_1G_{w'}\\
R_1 &= k_2G_{x_0} + k_3G_{x_1} + k_4G_a\\
R_2 &= k_0G_w + k_2U + k_3tU + k_4M_a\\
c &= \text{Hash}(R_0, R_1, R_2, C_w, G_v - I, V)\\
s_i &= k_i + c(sk_i) \ \ \forall i \in [0, 5)\\
\text{proof is } &(\mathbf{s}, c)
\end{align}
}
```

verification:
```math
\displaylines{
\begin{align}
R_0 &= s_0G_w + s_1G_{w'} - cC_w\\
    &= (k_0+cw)G_w + (k_1+cw')G_{w'} - cC_w\\
    &= k_0G_w + k_1G_{w'}.\\
R_1 &= s_2G_{x_0} + s_3G_{x_1} + s_4G_a - c(G_v - I)\\
    &= (k_2+cx_0)G_{x_0} + (k_3+cx_1)G_{x_1} + (k_4+cy_a)G_a - c(G_v - I)\\
    &= k_2G_{x_0} + k_3G_{x_1} + k_4G_a.\\
R_2 &= s_0G_w + s_2U + s_3tU + s_4M_a - cV\\
    &= (k_0+cw)G_w + (k_2+cx_0)U + (k_3+cx_1)tU + (k_4+cy_a)M_a - cV\\
    &= k_0G_w + k_2U + k_3tU + k_4M_a.\\
c' &= \text{Hash}(R_0, R_1, R_2, C_w, G_v - I, V)\\
c' &\overset{?}= c
\end{align}
}
```
-->

### Proof of Range for `AmountAttribute` $M_a$ ($\pi_\text{range}$)
> [RangeStatement](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L292)

This is to prove that the amount encoded into $M_a$ does not exceed a particular limit $L$ (chosen as a power of 2).

The attribute's amount is decomposed into a bit-vector $\mathbf{b}$ of length $l = \log_2(L-1)$.
$\mathbf{b}$ is then committed to:
```math
\displaylines{
\mathbf{r'} \overset{$}\leftarrow \mathbb{Z}_q^l\\
\mathbf{B} = \mathbf{b}\cdot G_\text{amount} + \mathbf{r'}\cdot G_\text{blind}
}
```

$\pi_\text{range}$ then proves 3 relations in zero knowledge:
1) The bit decomposition sums up to `a`:
```math
a = \sum_{i=0}^l2^ib_i
```
2) Knowledge of the discrete logs behind the bit-commitments vector $B$:
```math
\mathbf{B} = \mathbf{b}\cdot G_\text{amount} + \mathbf{r'}\cdot G_\text{blind}
```
3) discrete logs behind the decomposition are either $0$ or $1$ in value:
```math
\displaylines{
\mathbf{b}\circ\mathbf{b} - \mathbf{b} = 0\\
\text{($\circ$ is the Hadamard or element-wise product of vectors.)}
}
```

Statement 3 leverages the fact that:
```math
b^2 = b \iff b = 0 \lor b = 1
```

<!--
proof construction:

```math
\displaylines{
\begin{aligned}
n &= \log_2{L}\\
k, \mathbf{k_b}, \mathbf{k_r}, \mathbf{k_rb} &\overset{$} \leftarrow \mathbb{Z}_q^{1 + 3n}\\
V &= rG_h - \sum_{i=0}^n 2^ir'_iG_h\\
R_0 &= kG_h - \sum_{i=0}^{n}{k_{r_i}2^iG_h}\\
R_{i+1} &= k_{b_i}G_g + k_{r_i}G_h \ \ \forall i \in [0, n)\\
R_{i+n+1} &= k_{b_i}(B_i - G_g) + k_{rb_i}G_h \ \ \forall i \in [0, n)\\
c &= \text{Hash}(R_0, R_1, \ldots, R_n, R_{n+1}, \ldots, R_{2n}, V, B_0, \ldots, B_{n-1})\\
s_r &= k + cr\\
\mathbf{s_b} &= \mathbf{k_b} + c\mathbf{b}\\
\mathbf{s_{r'}} &= \mathbf{k_r} + c\mathbf{r'}\\
\mathbf{s_{r'b}} &= \mathbf{k_rb} - c\mathbf{b}\circ\mathbf{r'}\\
\text{proof is } &(s_r, \mathbf{s_b}, \mathbf{s_{r'}}, \mathbf{s_{r'b}}, c)
\end{aligned}
}
```

verification:
```math
\displaylines{
\begin{aligned}
n &= \log_2{L}\\
V &= M_a - \sum_{i=0}^{n} 2^iB_i\\
  &= aG_g + rG_h - \sum_{i=0}^{n}\left(2^ib_iG_g + 2^ir'_iG_h\right) &\bigg(aG_g = \sum_{i=0}^n 2^ib_iG_g\bigg)\\
  &= rG_h - \sum_{i=0}^n 2^ir'_iG_h.\\
R_0 &= s_rG_h - \sum_{i=0}^{n}{s_{r'_i}2^iG_h} - cV\\
    &= (k+cr)G_h - \sum_{i=0}^{n}\left((k_{r_i} + cr'_i)2^iG_h\right) - cV\\
    &= kG_h - \sum_{i=0}^{n}{\left(k_{r_i}\right)2^iG_h}.\\
R_{i+1} &= s_{b_i}G_g + s_{r'_i}G_h - cB_i \\
        &= (k_{b_i}+cb_i)G_g + (k_{r_i} + cr'_i)G_h - c(b_iG_g + r'_iG_h)\\
        &= k_{b_i}G_g + k_{r_i}G_h &\forall i \in [0, n).\\
R_{i+n+1} &= s_{b_i}(B_i-G_g) + s_{r'b_i}G_h\\
          &= (k_{b_i}+cb_i)(B_i - G_g) + (k_{r'b_i}-cr_ib_i)G_h\\
          &= k_{b_i}(B_i-G_g) + cb_iB_i - cb_iG_g + k_{r'b_i}G_h - cr_ib_iG_h\\
          &= k_{b_i}(B_i-G_g) + k_{r'b_i}G_h + cb_i^2G_g - cb_iG_g + cb_ir_iG_h - cr_ib_iG_h &\left(b_i^2 = b_i\right)\\
          &= k_{b_i}(B_i-G_g) + k_{r'b_i}G_h &\forall i \in [0, n).\\
c' &= \text{Hash}(R_0, R_1, \ldots, R_n, R_{n+1}, \ldots, R_{2n}, V, B_0, B_1, \ldots, B_{n-1})\\
c' &\overset{?}= c
\end{aligned}
}
```
-->

### Proof of MAC ($\pi_\text{MAC}$):
> [CredentialsStatement](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L217)

This proof shows that `RandomizedCredentials` were computed from a valid `MAC` for a certain `AmountAttribute` and `ScriptAttribute`.

The public inputs to this proof are the `RandomizedCredentials` $(C_a, C_s, C_{x_0}, C_{x_1}, C_v)$
$\pi_\text{MAC}$ proves 3 relations:
1) $Z = r_aI$ where $r_a$ is the blinding factor from `AmountAttribute`.
2) $C_a = r_aG_\text{zamount} + r_aG_\text{blind} + aG_\text{amount}$ to prove $r_a$ is indeed the same as in `AmountAttribute`.
3) $C_{x_1} = tC_{x_0} + (-tr_a)G_{x_0} + r_aG_{x_1}$, where $t$ is the scalar value in the `MAC`.

Statement 1 works because the Mint uses private keys $sk$ and the `RandomizedCredentials` to re-calculate $Z$ autonomously as:
```math
Z = C_v - (wC_w + x_0C_{x_0} + x_1C_{x_1} + y_aC_a + y_sC_s)
```

### Proof of Balance ($\pi_\text{balance}$):
> [BalanceStatement](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L247)

This proof shows that the difference in encoded amount between the sum of many `RandomizedCredentials`'s $C_{a_i}$ and many new `AmountAttribute`s $M_{a_i}$ is exactly $\Delta_a$.

$\pi_\text{balance}$ proves 1 relation:
```math
B = \sum_{i=0}^n\left(r_{a_i}\right)G_\text{zamount} + \sum_{i=0}^n\left(r_{a_i}-r'_{a_i}\right)G_\text{blind}
```
Where $r'_{a_i}$ (with the apex $'$) are the amount blinding terms for the new attributes.

This statement works because the Mint uses $\Delta_a$ to re-compute the verification value $B$ autonomously as:

```math
B = \Delta_aG_\text{amount} + \sum_{i=0}^{n}\left(C_{a_i}-M_{a_i}\right)
```

### Proof Of Same Script ($\pi_\text{script}$)

> [ScriptEqualityStatement](https://github.com/lollerfirst/cashu-kvac/blob/c6497c8e69da1e3df7dcc2705114fe7d68986f30/src/kvac.py#L242)

During any swap operation, a client has the option to reveal the `ScriptAttribute`'s commitment $M_s$ to the Mint ([code](https://github.com/lollerfirst/cashu-kvac/blob/c6497c8e69da1e3df7dcc2705114fe7d68986f30/src/models.py#L215)). If the script is disclosed, the Mint can evaluate and execute it, determining whether to accept the transaction based on the script's outcome.

However, if the client chooses **not** to reveal the script, they must instead prove that the script encoded in each of the **new** attributes matches the script encoded in the **old** `RandomizedCredential`s. This proof can be accomplished in an all-to-all manner using a batch discrete logarithm equivalence.

$\pi_\text{script}$ proves $n+m$ relations, where $m$ is the number of **old** `RandomizedCredential`s provided and $n$ is the number of **new** `AmountAttribute`/`ScriptAttribute` pairs:

```math
\displaylines{
\begin{aligned}
M_{s_i} &= s \cdot G_\text{script} + r_{s_i} \cdot G_\text{blind} \ \ \forall i \in [0, m-1] \\
C_{s_i} &= s \cdot G_\text{script} + r_{s_i} \cdot G_\text{blind} + r_{a_i} \ \ \forall i \in [0, n-1] \cdot G_\text{zscript}
\end{aligned}
}
```

---

## Protocol
This section explains how a _client/wallet_ (used interchangeably) interacts with a _Mint_ (capital 'M' to distinguish it from the verb "minting").

### Bootstrapping
To perform any interaction (e.g., mint, swap, or melt) with the Mint, a client needs credentials worth $0$ ([46](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L46)). This is because the Mint always requires a valid set of `RandomizedCredentials` for every operation.

To handle this, the client makes a special `BootstrapRequest`:
1. The client requests a `MAC` for an `AmountAttribute` $M_a$ that encodes $0$, optionally including a `ScriptAttribute` $M_s$ with a script hash $s$.
2. The client generates a proof, $\pi_\text{bootstrap}$, to confirm that $M_a$ encodes $0$ [(48)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L48).
3. The client sends $(M_a, M_s, \pi_\text{bootstrap})$ to the Mint.

The Mint processes the `BootstrapRequest` as follows:
1. It verifies the proof $\pi_\text{bootstrap}$ [(53)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L53)
2. If the proof is valid, it issues a `MAC` $(t, V)$ for $M_a$ (and $M_s$ if provided) [(56)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L56).
3. It creates and returns $\pi_\text{iparams}$ to prove that the private keys it used are not linked to individual users [(57)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L57).

From the wallet's perspective, this bootstrapping process is only needed once per Mint.

### SwapRequest
When a client wants to swap coins, they:
1. Create new `AmountAttribute` and `ScriptAttribute` pairs that encode the current wallet balance (minus any fees) and, if applicable, the same script hash as in the current `ScriptAttribute` [(65-66)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L65).
2. Generate `RandomizedCredentials` using the `MAC`, `AmountAttribute`, and `ScriptAttribute` [(72)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L72).

The client also generates the following ZK-proofs:
- $\pi_\text{balance}$: Proves that the balance difference $\Delta_a$ (should equal $0$ or the fees) between old and new wallet balances is valid. Inputs: **old** and **new** `AmountAttribute`s [(78)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L78).
- $\pi_\text{range}$: For each new `AmountAttribute`, proves the value is within the range $[0, L-1]$. [(69)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L69).
- $\pi_\text{MAC}$: Proves that the provided `RandomizedCredential`s are valid and unspent. [(75)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L75)
- $\pi_\text{script}$: Ensures all **new** `ScriptAttribute`s encode the same script hash $s$ as the **old** `RandomizedCredential`s. [(81)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L81).

The client sends:
- (**old** `RandomizedCredential`s, **new** `AmountAttribute`/`ScriptAttribute` pairs)  
- All proofs.

The Mint then [(89-105)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L89):
1. Acknowledges the balance difference $\Delta_a$.
2. Verifies that it hasn’t seen the `RandomizedCredentials` $C_a$ before.
3. Validates all proofs.

If verification passes, the Mint issues new `MAC`s for the new `AmountAttribute` and `ScriptAttribute` pairs [(108)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L108). As with the `BootstrapRequest`, the Mint also produces $\pi_\text{iparams}$ to prove to the wallet its private key usage [(109)](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/examples/full_interaction.py#L109).

### Wallet-to-Wallet
Sending coins to another wallet is simpler:
- A coin is a tuple of secrets and its corresponding `MAC`:

```math
\text{Coin} = ((r_a, a), (r_s, s), (t, V))
```

No extra information is needed, as all proofs and randomization can be computed directly by the receiving wallet.

### Blank Outputs for Overpaid Fee Change

In Cashu, wallets often *overpay* during melt operations to ensure successful transactions, accounting for the unpredictability of lightning fees.

To allow the Mint to return the excess coins to the client, the client provides "blank" `BlindedMessage`s with no predefined amount. The Mint then assigns a value to these outputs and signs them with its keys.

With KVAC, this process is simplified:

1. During a melt operation, the client declares a $\Delta_a$ between the inputs and outputs that exceeds the peg-out amount (amount in the melt quote). This claim is substantiated by $\pi_\text{balance}$.
2. The Mint returns the overpaid amount $o$ by adjusting the commitment $M_a$ of the **new** `AmountAttribute`. Specifically, it tweaks the commitment as follows:
```math
   M_{a'} \gets M_a + o \cdot G_\text{amount}
```

---

### `CashuTranscript`

> [CashuTranscript](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L26)

`CashuTranscript` is a wrapper around a `MerlinTranscript`, which is used to manage a transcript for cryptographic operations. The `MerlinTranscript` itself is a tool for maintaining a running log of messages during interactive or non-interactive cryptographic protocols. It provides a way to securely commit to various inputs and derive challenges deterministically.

### Key Features of `CashuTranscript`:

1. **Domain Separation**:
   - `domain_sep` ensures that different contexts or types of operations within the protocol are distinguishable by their unique labels. This prevents potential cross-protocol attacks where inputs in one context might be interpreted as valid in another.

2. **Commitments**:
   - The `append` method commits a group element to the transcript.

3. **Challenge Derivation**:
   - The `get_challenge` method extracts a cryptographic challenge deterministically from the transcript. This challenge is used in proofs, ensuring it depends on all prior transcript data, providing strong security guarantees.

### Role in Zero-Knowledge Proving and Verifying:

In a zero-knowledge proof (ZKP), the prover aims to convince the verifier of a statement's validity without revealing any secrets. `CashuTranscript` plays a crucial role in ensuring the soundness and security of this process.

1. **Non-Interactive Proofs**:
   - Using the Fiat-Shamir heuristic, `CashuTranscript` turns interactive proofs into non-interactive ones by simulating the verifier's role in generating challenges. This makes it possible to create proofs that can be verified later without an interactive session.

2. **Binding**:
   - The commitments recorded in the transcript bind the prover to specific values. This ensures that the prover cannot alter their proof after seeing the challenge.

3. **Challenge Integrity**:
   - The challenges derived via `CashuTranscript` are deterministic but depend on the entire transcript. This means any tampering with the transcript will produce a different challenge, making it impossible to forge valid proofs.

4. **Security Against Replay Attacks**:
   - Since the transcript includes domain separators and commitments to public and private inputs, reusing a proof in a different context will result in a mismatch in the challenge, invalidating the proof.

---

## Explanation of the Generic Proof of Knowledge (PoK) Mechanism

> [Schnorr Prover/Verifier](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L57)

The implementation creates and verifies **Proofs of Knowledge (PoK)** for linear relations using a non-interactive zero-knowledge proof (NIZKP) protocol. This approach makes use of the **Fiat-Shamir heuristic**, which transforms an interactive proof into a non-interactive one by using a cryptographic hash function.


### **1. Definitions and Setup**
#### Linear Relation
A linear relation is a mathematical statement of the form:
```math
\sum_{i=1}^n s_i P_i = V
```
where:
- $\(s_i\)$ are **secrets** (values the prover knows but does not wish to reveal).
- $\(P_i\)$ are **public points** (elements from a group/in most cases the previously mentioned generators).
- $\(V\)$ is the **verification value (public input)**.

The goal is for the prover to convince the verifier that they know the $\(s_i\)$ values that satisfy the relation without revealing the secrets.

### **2. Proving Phase**
In the proving phase, the prover demonstrates knowledge of the secrets $\(\{s_i\}\)$ without revealing them.

#### Steps:
1. **Generate Random Terms**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L98)
   
   For each secret $\(s_i\)$, the prover generates a random term $\(k_i\)$ (a private nonce):
   
```math
k_i \sim \mathbb{Z}_q
```

2. **Compute Commitments**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L129)
   
   The prover computes public-nonce commitments $\(R\)$ for the linear relation using the $\(k_i\)$:
   
```math
R = \sum_{i=1}^n k_i P_i
```

3. **Append to Transcript**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L138)
   
   The prover serializes the verification value (public input) $\(V\)$ and commitments $\(R\)$ and appends them to the
   running transcript.

4. **Compute Challenge**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L150)
   
   The prover derives a challenge $\(c\)$ from the current state of the transcript:
   
```math
c = H(R\ldots \ \text{||} \ V\ldots)
```
   The challenge is a deterministic random scalar.

5. **Compute Responses**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L152)
   
   For each secret $\(s_i\)$, the prover computes a response $\(z_i\)$:
```math
z_i = k_i + c \cdot s_i
```

6. **Generate Proof**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L155)
   
   The prover packages the responses $\(\{z_i\}\)$ and the challenge $\(c\)$ into a proof object:
```math
\text{Proof} = \{z_1, z_2, \ldots, z_n, c\}
```

---

### **3. Verification Phase**
In the verification phase, the verifier ensures the proof is valid without learning the secrets.

#### Steps:
1. **Extract Proof Components**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L101)
   
   The verifier extracts the responses $\(\{z_i\}\)$ and challenge $\(c\)$ from the proof.

2. **Recompute Commitments**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L133)
   
   Using the responses $\(\{z_i\}\)$ and public points $\(\{P_i\}\)$ given by the proof's statement, the verifier recomputes the commitments:
```math
R' = \sum_{i=1}^n z_i P_i - c \cdot V
```
   - If $\(R'\)$ matches the original commitments, it suggests the prover's responses are consistent with the claimed linear relation.

3. **Recompute Challenge**:
   > [code](https://github.com/lollerfirst/cashu-kvac/blob/14024615471e3d6cb328bade1db0db3e6d67fd38/src/kvac.py#L166)
   
   The verifier computes the challenge from the commitments and the public inputs:
```math
c' = H(R'\ldots \ \text{||} \ V\ldots)
```

4. **Validate Proof**:
   The verifier checks if:
```math
c' = c
```
   If this equality holds, the proof is valid.


### **Key Insights**
- The use of random terms $\(k_i\)$ ensures that the proof does not leak information about the secrets $\(\{s_i\}\)$.
- The cryptographic hash function $\(H\)$ guarantees that the challenge $\(c\)$ is unpredictable and tamper-proof.
- The recomputation of $\(R'\)$ in the verification phase confirms the consistency of the prover's claim.


### **Mathematical Details**
**Proof of Correctness**:
The responses $\(z_i\)$ are defined as:
```math
z_i = k_i + c \cdot s_i
```
Substituting into the recomputed commitments during verification:
```math
R' = \sum_{i=1}^n z_i P_i - c \cdot V
= \sum_{i=1}^n (k_i + c \cdot s_i) P_i - c \cdot V
```
Expanding:
```math
R' = \sum_{i=1}^n k_i P_i + c \cdot \sum_{i=1}^n s_i P_i - c \cdot V
```
Using the linear relation $\(\sum_{i=1}^n s_i P_i = V\)$, this simplifies to:
```math
R' = \sum_{i=1}^n k_i P_i = R
```
Thus, the recomputed commitments $\(R'\)$ match the original commitments $\(R\)$, ensuring the proof is valid.
