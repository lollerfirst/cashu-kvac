# Anonymous Credentials for Cashu

Experimental implementation of the core crypto behind an anonymous credentials enabled Mint.

### KVAC Scheme:
* Paper on KVAC used for CoinJoins: https://eprint.iacr.org/2021/206.pdf
* The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption: https://eprint.iacr.org/2019/1416

### KVAC for Cashu:
* Definitions and Protocol explaination (WIP): [HERE](protocol_explanation.md)

### Extras
* Deterministic Recovery: read `deterministic_recovery.md`
* Server/Mint can tweak the amounts encoded in the attributes: $M_a' = M_a + \delta G_\text{amount}$
* We are using $r$ as both the randomizing factor and the blinding factor:
  - different generators with unknown discrete log between them guarantees hiding.
  - Benefit: no $\pi_\text{serial}$ because not needed anymore.
  - $C_a$ becomes the serial

### Range proofs:
Range proofs are implemented as [BULLETPROOFS](https://eprint.iacr.org/2017/1066.pdf).
