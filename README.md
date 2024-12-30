# Anonymous Credentials for Cashu

Experimental implementation of the core crypto behind an anonymous credentials enabled Mint.

### Compile and Run Tests
```shell
cargo build && cargo test
```

### Usage Examples

Creating a `AmountAttribute`:
```rust
use cashu_kvac::models::AmountAttribute;

// Normal
let amount_attribute = AmountAttribute::new(10, None);

// Chosen blinding factor (derived from BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let amount_attribute_1 = AmountAttribute::new(10, Some(custom_blinding_factor));
```

Creating a `ScriptAttribute`:
```rust
use cashu_kvac::models::ScriptAttribute;

let script = b"38c3";

// Normal
let script_attribute = ScriptAttribute::new(script, None);

// Chosen blinding factor (derived from BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let script_attribute = ScriptAttribute::new(script, custom_blinding_factor);
```

Issuing a `MAC` on a `AmountAttribute`:
```rust
use cashu_kvac::models::{AmountAttribute, ScriptAttribute, MAC};
use cashu_kvac::secp::Scalar;

let scalars = vec![Scalar::random(); 6];
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

// Client generates these
let amount_attribute = AmountAttribute::new(10, None);
let amount_commitment = amount_attribute.commitment();
let t_tag = Scalar::random();

// Mint issues the MAC on the tag `t` and the commitments (amount and possibly script)
let mac = MAC::generate(&mint_privkey, amount_commitment, None, Some(t_tag)).unwrap();

```

Assembling a `Coin`:
```rust
use cashu_kvac::models::Coin;

// Takes ownership of the arguments
let coin = Coin::new(amount_attribute, script_attribute, mac);
```

Randomizing a `Coin` into a `RandomizedCoin` (mandatory before perfoming a swap, mint, melt):
```rust
use cashu_kvac::models::RandomizedCoin;

let randomized_coin = RandomizedCoin::from_coin(&coin, false).unwrap();

// Randomized coin, but the script will be revealed
let randomized_coin_with_script_reveal = RandomizedCoin::from_coin(&coin, true).unwrap();
```

Proving the balance between inputs and outputs of a swap:
```rust
use cashu_kvac::transcript::CashuTranscript;
use cashu_kvac::models::{AmountAttribute, MAC};

let transcript = CashuTranscript::new();

let scalars = vec![Scalar::random(); 6];
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

let inputs = vec![
    AmountAttribute::new(12, None),
    AmountAttribute::new(11, None),
];
let outputs = vec![AmountAttribute::new(23, None)];

// We assume the inputs were already issued a MAC previously
let macs: Vec<MAC> = inputs
    .iter()
    .map(|input| {
        MAC::generate(&privkey, input.commitment(), None, None).expect("MAC expected")
    })
    .collect();

let proof = BalanceProof::create(&inputs, &outputs, &mut transcript);
```

> [!NOTE]
> It is possible to prove/verify custom statement with `SchorrProver` and `SchnorrVerifier`

### KVAC Scheme
* Paper on KVAC used for CoinJoins: https://eprint.iacr.org/2021/206.pdf
* The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption: https://eprint.iacr.org/2019/1416

### KVAC for Cashu
Definitions and Protocol explaination (WIP): [HERE](protocol_explanation.md)

### Extras
* [Deterministic Recovery](deterministic_recovery.md)
* Server/Mint can tweak the amounts encoded in the attributes: $M_a' = M_a + \delta G_\text{amount}$
* We are using $r$ as both the randomizing factor and the blinding factor:
  - different generators with unknown discrete log between them guarantees hiding.
  - Benefit: no $\pi_\text{serial}$ because not needed anymore.
  - $C_a$ (Randomized Amount Commitment) is chosen as the nullifier

### Range proofs
Range proofs are implemented as [BULLETPROOFS](https://eprint.iacr.org/2017/1066.pdf).
