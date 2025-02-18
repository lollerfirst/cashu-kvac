//! # Model Module
//! Module containing models involved in KVAC operations

use crate::{
    bulletproof::BulletProof,
    errors::Error,
    generators::{hash_to_curve, GENERATORS},
    secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO},
};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The maximum allowed range for values.
pub const RANGE_LIMIT: u64 = u32::MAX as u64;

/// Public minting key used for verifying coin issuance.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Hash, Deserialize, Debug, Eq, PartialEq)]
pub struct MintPublicKey {
    pub Cw: GroupElement,
    pub I: GroupElement,
}

/// Private minting key used for signing coins.
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Hash, Deserialize, Debug, Eq, PartialEq)]
pub struct MintPrivateKey {
    pub w: Scalar,
    pub w_: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
    pub ys: Scalar,
    pub public_key: MintPublicKey,
}

#[allow(non_snake_case)]
impl MintPrivateKey {
    /// Constructs a `MintPrivateKey` from an array of scalars.
    ///
    /// # Arguments
    ///
    /// * `scalars` - A slice containing six `Scalar` values.
    ///
    /// # Returns
    ///
    /// Returns `Ok(MintPrivateKey)` if the input has exactly six scalars.
    /// Returns `Err(Error::InvalidMintPrivateKey)` if the input length is incorrect.
    ///
    /// # Errors
    ///
    /// This function will return `Error::InvalidMintPrivateKey` if `scalars` does not contain exactly six elements.
    pub fn from_scalars(scalars: &[Scalar]) -> Result<Self, Error> {
        if let [w, w_, x0, x1, ya, ys] = scalars {
            let Cw = GENERATORS.W.clone() * w + &(GENERATORS.W_.clone() * w_);
            let I = GENERATORS.Gz_mac.clone()
                - &(GENERATORS.X0.clone() * x0
                    + &(GENERATORS.X1.clone() * x1)
                    + &(GENERATORS.Gz_attribute.clone() * ya)
                    + &(GENERATORS.Gz_script.clone() * ys));
            let public_key = MintPublicKey { Cw, I };
            Ok(MintPrivateKey {
                w: w.clone(),
                w_: w_.clone(),
                x0: x0.clone(),
                x1: x1.clone(),
                ya: ya.clone(),
                ys: ys.clone(),
                public_key,
            })
        } else {
            Err(Error::InvalidMintPrivateKey)
        }
    }

    /// Serializes the private key into an array of scalars.
    ///
    /// # Returns
    ///
    /// A `Vec<Scalar>` containing six elements representing the private key components.
    ///
    /// # Panics
    ///
    /// This function does **not** panic under normal conditions.
    pub fn to_scalars(&self) -> Vec<Scalar> {
        vec![
            self.w.clone(),
            self.w_.clone(),
            self.x0.clone(),
            self.x1.clone(),
            self.ya.clone(),
            self.ys.clone(),
        ]
    }
}

/// Represents a zero-knowledge proof (ZKP) with commitment scalars.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub struct ZKP {
    pub s: Vec<Scalar>,
    pub c: Scalar,
}

/// Zero-knowledge proof (ZKP) with `s` responses and `c` challenge.
#[derive(Serialize, Deserialize, Hash, Debug, Clone, PartialEq, Eq)]
pub enum RangeZKP {
    BULLETPROOF(BulletProof),
}

/// Structure holding the secret values for pedersen commitment encoding a script (spending conditions)
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptAttribute {
    pub s: Scalar,
    pub r: Scalar,
}

#[allow(non_snake_case)]
impl ScriptAttribute {
    /// Creates a new script attribute from a given script and optional blinding factor.
    ///
    /// # Arguments
    ///
    /// * `script` - A slice of bytes representing the script. This is used to generate the scalar `s`.
    /// * `blinding_factor` - An optional reference to a 32-byte array that serves as the blinding factor.
    ///   If provided, it is used to create the scalar `r`. If not provided, a random
    ///   scalar `r` is generated.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `ScriptAttribute` containing the computed scalars `r` and `s`.
    pub fn new(script: &[u8], blinding_factor: Option<&[u8]>) -> Self {
        let s = Scalar::new(&Sha256Hash::hash(script).to_byte_array());
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);

            ScriptAttribute { r, s }
        } else {
            let r = Scalar::random();
            ScriptAttribute { r, s }
        }
    }

    /// Computes the commitment of the script attribute.
    ///
    /// # Returns
    ///
    /// Returns a `GroupElement` representing the commitment of the script attribute, calculated
    /// as the linear combination of the generators `G_script` and `G_blind` with the scalars `s` and `r`.
    pub fn commitment(&self) -> GroupElement {
        GENERATORS.G_script.clone() * &self.s + &(GENERATORS.G_blind.clone() * &self.r)
    }
}

/// Structure holding the secret values for pedersen commitments encoding amounts
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountAttribute {
    #[serde(
        serialize_with = "serialize_amount",
        deserialize_with = "deserialize_amount"
    )]
    pub a: Scalar,
    pub r: Scalar,
}

fn serialize_amount<S>(a: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let amount: u64 = a.into();
    serializer.serialize_u64(amount)
}

fn deserialize_amount<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    let amount = u64::deserialize(deserializer)?;
    Ok(Scalar::from(amount))
}

#[allow(non_snake_case)]
impl AmountAttribute {
    /// Creates a new amount attribute from a given amount and optional blinding factor.
    ///
    /// # Arguments
    ///
    /// * `amount` - A `u64` representing the amount to be associated with the attribute. This is used to create the scalar `a`.
    /// * `blinding_factor` - An optional reference to a 32-byte array that serves as the blinding factor.
    ///   If provided, it is used to create the scalar `r`. If not provided, a random
    ///   scalar `r` is generated.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `AmountAttribute` containing the computed scalars `r` and `a`.
    pub fn new(amount: u64, blinding_factor: Option<&[u8]>) -> Self {
        let a = Scalar::from(amount);
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);
            AmountAttribute { r, a }
        } else {
            let r = Scalar::random();
            AmountAttribute { r, a }
        }
    }

    /// Computes the commitment of the amount attribute.
    ///
    /// # Returns
    ///
    /// Returns a `GroupElement` representing the commitment of the amount attribute, calculated
    /// as the linear combination of the generators `G_amount` and `G_blind` with the scalars `a` and `r`.
    pub fn commitment(&self) -> GroupElement {
        GENERATORS.G_amount.clone() * &self.a + &(GENERATORS.G_blind.clone() * &self.r)
    }

    /// Changes the amount in this attribute by adding values to the secret `a` scalar.
    ///
    /// # Arguments
    ///
    /// * `amount` - A `u64` value to be added to the current amount represented by the scalar `a`.
    ///
    /// # Returns
    ///
    /// Returns a mutable reference to `Self`, allowing for method chaining.
    pub fn tweak_amount(&mut self, amount: u64) -> &Self {
        self.a.tweak_add(&Scalar::from(amount));
        self
    }
}

/// Structure holding the key components of an algebraic MAC, used
/// by the Mint to verify authenticity of the tokens
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, Eq, PartialEq)]
pub struct MAC {
    pub t: Scalar,
    pub V: GroupElement,
}

impl MAC {
    /// Generate a new MAC from the Mint's private key,
    /// for a particular amount commitment and script commitment pair.
    ///
    /// # Arguments
    ///
    /// * `privkey` - A reference to the `MintPrivateKey` used to generate the MAC.
    /// * `amount_commitment` - A reference to a `GroupElement` representing the amount commitment.
    /// * `script_commitment` - An optional reference to a `GroupElement` representing the script commitment.
    ///   If not provided, a zero `GroupElement` is used.
    /// * `t_tag` - An optional reference to a `Scalar` that can be used as a tag. If not provided, a random
    ///   `Scalar` is generated.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Self, Error>`, where `Self` is the newly generated `MAC` instance on success,
    /// or an `Error` if the MAC generation fails (e.g., if hashing to curve fails).
    #[allow(non_snake_case)]
    pub fn generate(
        privkey: &MintPrivateKey,
        amount_commitment: &GroupElement,
        script_commitment: Option<&GroupElement>,
        t_tag: Option<&Scalar>,
    ) -> Result<Self, Error> {
        let t: Scalar;
        if let Some(t_tag_some) = t_tag {
            t = t_tag_some.clone();
        } else {
            t = Scalar::random();
        }
        let t_bytes: [u8; 32] = t.as_ref().into();
        let U = hash_to_curve(&t_bytes)?;
        let Ma = amount_commitment.clone();
        let Ms: GroupElement;
        if let Some(com) = script_commitment {
            Ms = com.clone();
        } else {
            Ms = GroupElement::new(&GROUP_ELEMENT_ZERO);
        }
        let V = GENERATORS.W.clone() * &privkey.w
            + &(U.clone() * &privkey.x0)
            + &(U.clone() * &(t.clone() * &privkey.x1))
            + &(Ma * &(privkey.ya) + &(Ms * &(privkey.ys)));
        Ok(MAC { t, V })
    }
}

/// Structure that captures
/// `AmountAttribute`, `ScriptAttribute` and the `MAC`
/// issued on them
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    #[serde(rename = "amount")]
    pub amount_attribute: AmountAttribute,
    #[serde(rename = "script")]
    pub script_attribute: Option<ScriptAttribute>,
    pub mac: MAC,
}

impl Coin {
    /// Create a new `Coin` from an amount attribute, a script attribute, and a MAC.
    ///
    /// # Arguments
    ///
    /// * `amount_attribute` - An `AmountAttribute` representing the amount associated with the coin.
    /// * `script_attribute` - An optional `ScriptAttribute` that may contain additional script-related information.
    /// * `mac` - A `MAC` issued by the mint for authentication and integrity of the coin.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `Coin` containing the provided
    pub fn new(
        amount_attribute: AmountAttribute,
        script_attribute: Option<ScriptAttribute>,
        mac: MAC,
    ) -> Self {
        Coin {
            amount_attribute,
            script_attribute,
            mac,
        }
    }
}

/// Contains the randomized commitments of a `Coin`.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomizedCoin {
    /// Randomized Attribute Commitment
    pub Ca: GroupElement,
    /// Randomized Script Commitment
    pub Cs: GroupElement,
    /// Randomized MAC-specific Generator "U"
    pub Cx0: GroupElement,
    /// Randomized tag commitment
    pub Cx1: GroupElement,
    /// Randomized MAC
    pub Cv: GroupElement,
}

impl RandomizedCoin {
    /// Create a randomized coin, with randomized commitments from a normal `Coin`.
    ///
    /// `reveal_script` must be set to true if the script inside the `ScriptAttribute`
    /// will be revealed to the Mint/server.
    ///
    /// # Arguments
    ///
    /// * `coin` - A reference to a `Coin` instance from which the randomized coin will be created.
    /// * `reveal_script` - A boolean indicating whether the script inside the `ScriptAttribute`
    ///   will be revealed. If true, the randomized script commitment will be void,
    ///   leaving space for the Mint to "fill in" the blank with the hash of the
    ///   script (spending conditions) provided by the user
    ///
    /// # Returns
    ///
    /// Returns a `Result<Self, Error>`, where `Self` is the newly created `RandomizedCoin` instance
    /// on success, or an `Error` if the creation of the randomized coin fails (e.g., if hashing to
    /// curve fails).
    #[allow(non_snake_case)]
    pub fn from_coin(coin: &Coin, reveal_script: bool) -> Result<Self, Error> {
        let t = coin.mac.t.clone();
        let V = coin.mac.V.as_ref();
        let t_bytes: [u8; 32] = (&coin.mac.t).into();
        let U = hash_to_curve(&t_bytes)?;
        let Ma = coin.amount_attribute.commitment();
        let r = &coin.amount_attribute.r;
        let Ms: GroupElement;
        if let Some(attr) = &coin.script_attribute {
            if reveal_script {
                Ms = GENERATORS.G_blind.clone() * attr.r.as_ref();
            } else {
                Ms = attr.commitment().clone();
            }
        } else {
            Ms = GroupElement::new(&GROUP_ELEMENT_ZERO);
        }

        let Ca = GENERATORS.Gz_attribute.clone() * r + &Ma;
        let Cs = GENERATORS.Gz_script.clone() * r + &Ms;
        let Cx0 = GENERATORS.X0.clone() * r + &U;
        let Cx1 = GENERATORS.X1.clone() * r + &(U * &t);
        let Cv = GENERATORS.Gz_mac.clone() * r + V;

        Ok(RandomizedCoin {
            Ca,
            Cs,
            Cx0,
            Cx1,
            Cv,
        })
    }
}

/// Structure that holds information about an equation to be proven
/// or for which a proof has to be verified.
pub struct Equation {
    /// Left-hand side of the equation (public input)
    pub lhs: GroupElement,
    /// Right-hand side of the equation (construction of the relation)
    pub rhs: Vec<Vec<GroupElement>>,
}

/// A statement is a collection of relations (equations)
pub struct Statement {
    /// Domain Separator of the proof
    pub domain_separator: &'static [u8],
    /// Relations
    pub equations: Vec<Equation>,
}

#[allow(unused_imports)]
mod tests {
    use crate::{generators::hash_to_curve, models::ScriptAttribute, secp::Scalar};

    use super::{AmountAttribute, MAC};

    #[allow(dead_code)]
    const B_FACTOR: &[u8; 32] = b"deadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn test_serialize_amount_attr() {
        let a = AmountAttribute::new(10, Some(B_FACTOR));
        let serialized = serde_json::to_string(&a).unwrap();
        let target =
            "{\"a\":10,\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        assert_eq!(serialized.as_str(), target);
    }

    #[test]
    fn test_deserialize_amount_attr() {
        let a = AmountAttribute::new(10, Some(B_FACTOR));
        let serialized =
            "{\"a\":10,\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        let deserialized: AmountAttribute =
            serde_json::from_str(serialized).expect("Cannot deserialize");
        assert!(deserialized.a == a.a);
    }

    #[test]
    fn test_serialize_script_attr() {
        let script_attr = ScriptAttribute::new(b"38c3", Some(B_FACTOR));
        let serialized = serde_json::to_string(&script_attr).unwrap();
        let target = "{\"s\":\"c87557af1c5e640a085df471d68a5a97c9aaf4d379add58da3d7d5e0fe0df487\",\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        assert_eq!(serialized.as_str(), target);
    }

    #[test]
    fn test_deserialize_script_attr() {
        let script_attr = ScriptAttribute::new(b"38c3", Some(B_FACTOR));
        let serialized = "{\"s\":\"c87557af1c5e640a085df471d68a5a97c9aaf4d379add58da3d7d5e0fe0df487\",\"r\":\"6465616462656566646561646265656664656164626565666465616462656566\"}";
        let deserialized: ScriptAttribute = serde_json::from_str(serialized).unwrap();
        assert!(deserialized.s == script_attr.s);
    }

    #[test]
    fn test_serialize_mac() {
        let target = "{\"t\":\"fa5cb78b4dfaa8763fe62cc687f0e2383ac6a10c7817f5c8bd99c4f87d673da4\",\"V\":\"022b5028285ab8646380eed0a07d76cab4379a43680df72428ee792a6f7a3910d0\"}";
        // fake MAC for testing purposes
        let t =
            Scalar::try_from("fa5cb78b4dfaa8763fe62cc687f0e2383ac6a10c7817f5c8bd99c4f87d673da4")
                .unwrap();
        let t_bytes: [u8; 32] = t.as_ref().into();
        let mac = MAC {
            t,
            V: hash_to_curve(&t_bytes).unwrap(),
        };
        let serialized = serde_json::to_string(&mac).unwrap();
        assert_eq!(serialized, target);
    }

    #[test]
    fn test_deserialize_mac() {
        let serialized = "{\"t\":\"fa5cb78b4dfaa8763fe62cc687f0e2383ac6a10c7817f5c8bd99c4f87d673da4\",\"V\":\"022b5028285ab8646380eed0a07d76cab4379a43680df72428ee792a6f7a3910d0\"}";
        let t =
            Scalar::try_from("fa5cb78b4dfaa8763fe62cc687f0e2383ac6a10c7817f5c8bd99c4f87d673da4")
                .unwrap();
        let t_bytes: [u8; 32] = t.as_ref().into();
        let mac = MAC {
            t,
            V: hash_to_curve(&t_bytes).unwrap(),
        };
        let deserialized: MAC = serde_json::from_str(serialized).unwrap();
        assert_eq!(mac.t, deserialized.t);
        assert_eq!(mac.V, deserialized.V);
    }
}
