use crate::{
    errors::Error,
    generators::{hash_to_curve, GENERATORS},
    secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO},
};
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;

pub const RANGE_LIMIT: u64 = std::u32::MAX as u64;

#[allow(non_snake_case)]
pub struct MintPrivateKey {
    pub w: Scalar,
    pub w_: Scalar,
    pub x0: Scalar,
    pub x1: Scalar,
    pub ya: Scalar,
    pub ys: Scalar,

    // Public parameters
    pub Cw: GroupElement,
    pub I: GroupElement,
}

#[allow(non_snake_case)]
impl MintPrivateKey {
    pub fn from_scalars(scalars: &[Scalar; 6]) -> Self {
        let [w, w_, x0, x1, ya, ys] = scalars;
        let Cw = GENERATORS.W.clone() * w + &(GENERATORS.W_.clone() * w_);
        let I = GENERATORS.Gz_mac.clone()
            - &(GENERATORS.X0.clone() * x0
                + &(GENERATORS.X1.clone() * x1
                    + &(GENERATORS.Gz_attribute.clone() * ya
                        + &(GENERATORS.Gz_script.clone() * ys))));
        MintPrivateKey {
            w: w.clone(),
            w_: w_.clone(),
            x0: x0.clone(),
            x1: x1.clone(),
            ya: ya.clone(),
            ys: ys.clone(),
            Cw,
            I,
        }
    }

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

    pub fn pubkey(&self) -> (&GroupElement, &GroupElement) {
        (self.Cw.as_ref(), self.I.as_ref())
    }
}

pub struct ZKP {
    pub s: Vec<Scalar>,
    pub c: Scalar,
}

#[allow(non_snake_case)]
pub struct ScriptAttribute {
    pub r: Scalar,
    pub s: Scalar,
    Ms: GroupElement,
}

#[allow(non_snake_case)]
impl ScriptAttribute {
    pub fn new(script: &[u8], blinding_factor: Option<&[u8; 32]>) -> Self {
        let s = Scalar::new(&Sha256Hash::hash(script).to_byte_array());
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);
            let Ms = GENERATORS.G_script.clone() * &s + &(GENERATORS.G_blind.clone() * &r);
            ScriptAttribute { r, s, Ms }
        } else {
            let r = Scalar::random();
            let Ms = GENERATORS.G_script.clone() * &s + &(GENERATORS.G_blind.clone() * &r);
            ScriptAttribute { r, s, Ms }
        }
    }

    pub fn commitment(&self) -> &GroupElement {
        self.Ms.as_ref()
    }
}

#[allow(non_snake_case)]
pub struct AmountAttribute {
    pub a: Scalar,
    pub r: Scalar,
    Ma: GroupElement,
}

#[allow(non_snake_case)]
impl AmountAttribute {
    pub fn new(amount: u64, blinding_factor: Option<&[u8; 32]>) -> Self {
        let a = Scalar::from(amount);
        if let Some(b_factor) = blinding_factor {
            let r = Scalar::new(b_factor);
            let Ma = GENERATORS.G_amount.clone() * &a + &(GENERATORS.G_blind.clone() * &r);
            AmountAttribute { r, a, Ma }
        } else {
            let r = Scalar::random();
            let Ma = GENERATORS.G_amount.clone() * &a + &(GENERATORS.G_blind.clone() * &r);
            AmountAttribute { r, a, Ma }
        }
    }

    pub fn commitment(&self) -> &GroupElement {
        self.Ma.as_ref()
    }
}

#[allow(non_snake_case)]
pub struct MAC {
    pub t: Scalar,
    pub V: GroupElement,
}

impl MAC {
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
            + &(U.clone() * &privkey.x0
                + &(U.clone() * &(t.clone() * &privkey.x1)
                    + &(Ma * &(privkey.ya) + &(Ms * &(privkey.ys)))));
        Ok(MAC { t, V })
    }
}

/// Spendable coin.
/// Contains `AmountAttribute`, `ScriptAttribute`
/// and the `MAC` approval by the Mint.
pub struct Coin {
    pub amount_attribute: AmountAttribute,
    pub script_attribute: Option<ScriptAttribute>,
    pub mac: MAC,
}

impl Coin {
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

/// Contains randomized commitments of a `Coin`.
/// Used for unlinkable multi-show.
#[allow(non_snake_case)]
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

        let Ca = GENERATORS.Gz_attribute.clone() * r + Ma;
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

pub struct Equation {
    /// Left-hand side of the equation (public input)
    pub lhs: GroupElement,
    /// Right-hand side of the equation (construction of the relation)
    pub rhs: Vec<Vec<GroupElement>>,
}

pub struct Statement {
    /// Domain Separator of the proof
    pub domain_separator: &'static [u8],
    /// Relations
    pub equations: Vec<Equation>,
}
