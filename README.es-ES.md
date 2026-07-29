# Credenciales Anónimas para Cashu

Implementación experimental de la criptografía central detrás de un Mint habilitado con credenciales anónimas.

### Compilar y ejecutar pruebas

```shell
cargo build && cargo test
```

### Ejecutar benchmarks

```shell
cargo +nightly bench
```

### Ejemplos de uso

Creando un `AmountAttribute`:
```rust
use cashu_kvac::models::AmountAttribute;

// Normal
let amount_attribute = AmountAttribute::new(10, None);

// Factor de cegamiento elegido (ej. derivado de BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let amount_attribute_1 = AmountAttribute::new(10, Some(custom_blinding_factor));
```

Creando un `ScriptAttribute`:
```rust
use cashu_kvac::models::ScriptAttribute;

let script = b"38c3";

// Normal
let script_attribute = ScriptAttribute::new(script, None);

// Factor de cegamiento elegido (derivado de BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let script_attribute = ScriptAttribute::new(script, custom_blinding_factor);
```

Emitiendo un `MAC` sobre un `AmountAttribute`:
```rust
use cashu_kvac::models::{AmountAttribute, ScriptAttribute, MAC, MintPrivateKey};
use cashu_kvac::secp::Scalar;

let scalars = (0..6).map(|_| Scalar::random()).collect();
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

// El cliente genera estos
let amount_attribute = AmountAttribute::new(10, None);
let amount_commitment = amount_attribute.commitment();
let tag = Scalar::random();

// El Mint emite el MAC sobre el tag y los compromisos (monto y posiblemente script)
// Devuelve un GroupElement que representa el MAC
let mac = MAC::generate(&mint_privkey, amount_commitment, None, tag).unwrap();

```

Creando `RandomizedCommitments` a partir de atributos y MAC (obligatorio antes de realizar un swap, mint, melt):
```rust
use cashu_kvac::models::RandomizedCommitments;

// Crear compromisos aleatorizados a partir del atributo de monto, atributo de script, tag y MAC
let randomized_commitments = RandomizedCommitments::from_attributes_and_mac(
    &amount_attribute,
    Some(&script_attribute), // o None si no hay script
    tag,
    mac,
    false // reveal_script
).unwrap();

// Compromisos aleatorizados, pero el script será revelado
let randomized_commitments_with_script_reveal = RandomizedCommitments::from_attributes_and_mac(
    &amount_attribute,
    Some(&script_attribute),
    tag,
    mac,
    true // reveal_script
).unwrap();
```

Probando el balance entre entradas y salidas de un swap:
```rust
use cashu_kvac::transcript::CashuTranscript;
use cashu_kvac::models::{AmountAttribute, MAC, MintPrivateKey};
use cashu_kvac::secp::{Scalar, GroupElement};

let mut transcript = CashuTranscript::new();

let scalars = (0..6).map(|_| Scalar::random()).collect();
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

let inputs = vec![
    AmountAttribute::new(12, None),
    AmountAttribute::new(11, None),
];
let outputs = vec![AmountAttribute::new(23, None)];

// Asumimos que las entradas ya recibieron un MAC previamente
let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
let macs: Vec<GroupElement> = inputs
    .iter()
    .zip(tags.iter())
    .map(|(input, tag)| {
        MAC::generate(&mint_privkey, input.commitment(), None, *tag).expect("MAC expected")
    })
    .collect();

let proof = BalanceProof::create(&inputs, &outputs, &mut transcript);
```

> [!NOTE]
> Puedes probar/verificar enunciados arbitrarios con `SchorrProver` y `SchnorrVerifier`

### Bindings de WASM y Javascript
Para generar los bindings de WASM y javascript, instala `wasm-pack`:

```sh
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Clona este repositorio:
```sh
git clone https://github.com/lollerfirst/cashu-kvac
```

Luego, navega al directorio del repositorio y genera el WASM con:
```sh
wasm-pack build --target {node|web}
```

La librería se compilará en un paquete bajo `./pkg` desde el directorio raíz del repositorio.

### Esquema KVAC
El diseño de esta librería se basa en el esquema KVAC, y específicamente en estos 2 artículos:

* KVAC usado para CoinJoins (WabiSabi): https://eprint.iacr.org/2021/206.pdf
* The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption: https://eprint.iacr.org/2019/1416

### Explicación del Protocolo
Definiciones y explicación del protocolo (WIP): [AQUÍ](protocol_explanation.md)

### Extras
* [Recuperación Determinista](deterministic_recovery.md)
* El Servidor/Mint puede ajustar los montos codificados en los atributos: $M_a' = M_a + \delta G_\text{amount}$ . Esto puede usarse para devolver cosas como comisiones excedentes de manera concisa.
* **[Desviación del esquema]** Uso del factor de cegamiento $r$ en los Compromisos de Pedersen tanto para el cegamiento como para la aleatorización:
  * diferentes generadores con logaritmo discreto desconocido entre ellos garantizan el ocultamiento.
  * Beneficio: no se requiere $\pi_\text{serial}$ porque ya no es necesario.
  * $C_a$ (Compromiso de Monto Aleatorizado) es elegido como el nullifier.

### Pruebas de rango (Range proofs)

Las pruebas de rango son necesarias para verificar que las salidas de las solicitudes estén dentro de un rango determinado, evitando cualquier posible desbordamiento (overflow) que pudiera engañar a la Prueba de Balance.

Variaciones:

* [x] [BULLETPROOFS](https://eprint.iacr.org/2017/1066.pdf)
* [ ] [BULLETPROOFS++](https://eprint.iacr.org/2022/510.pdf) circuitos aritméticos
* [ ] [SHARP](https://eprint.iacr.org/2022/1153.pdf) que mejoraría el tiempo de creación/verificación diez veces. Existen algunos sabores diferentes de sharp, algunos de los cuales utilizan grupos de orden oculto.

### Transcript
Cada prueba de Conocimiento Cero utiliza un transcript dedicado definido en `transcript.rs` y ajustado por una cadena de bytes de separación de dominio para los diversos enunciados que necesitan ser probados.
