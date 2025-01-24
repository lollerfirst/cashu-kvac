use crate::bulletproof::BulletProof;
use crate::errors::Error;
use crate::generators::{hash_to_curve, GENERATORS};
use crate::models::{
    AmountAttribute, Coin, Equation, MintPrivateKey, MintPublicKey, RandomizedCoin, RangeZKP, ScriptAttribute, Statement, MAC, ZKP
};
use crate::secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO, SCALAR_ZERO};
use crate::transcript::CashuTranscript;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;

pub struct SchnorrProver<'a> {
    random_terms: Vec<Scalar>,
    secrets: Vec<Scalar>,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrProver<'a> {
    pub fn new(transcript: &'a mut CashuTranscript, secrets: Vec<Scalar>) -> Self {
        SchnorrProver {
            random_terms: vec![Scalar::random(); secrets.len()],
            secrets,
            transcript,
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(self, statement: Statement) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(statement.domain_separator);

        for equation in statement.equations.into_iter() {
            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (k, P) in self.random_terms.iter().zip(row.into_iter()) {
                    R = R + (P * k).as_ref();
                }
            }

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
        self
    }

    #[allow(non_snake_case)]
    pub fn prove(self) -> ZKP {
        // Draw a challenge from the running transcript
        let c = self.transcript.get_challenge(b"chall_");

        // Create responses to the challenge
        let mut responses: Vec<Scalar> = vec![];
        for (k, s) in self.random_terms.into_iter().zip(self.secrets.into_iter()) {
            responses.push(k + (s * c.as_ref()).as_ref());
        }

        ZKP { s: responses, c }
    }
}

pub struct SchnorrVerifier<'a> {
    responses: Vec<Scalar>,
    challenge: Scalar,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrVerifier<'a> {
    pub fn new(transcript: &'a mut CashuTranscript, proof: ZKP) -> Self {
        SchnorrVerifier {
            responses: proof.s,
            challenge: proof.c,
            transcript,
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(self, statement: Statement) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(statement.domain_separator);

        for equation in statement.equations.into_iter() {
            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (s, P) in self.responses.iter().zip(row.into_iter()) {
                    R = R + (P * s).as_ref();
                }
            }
            R = R - (V.clone() * self.challenge.as_ref()).as_ref();

            self.transcript.append_element(b"R_", &R);
            self.transcript.append_element(b"V_", &V);
        }
        self
    }

    pub fn verify(&mut self) -> bool {
        let challenge_ = self.transcript.get_challenge(b"chall_");
        challenge_ == self.challenge
    }
}

pub struct BootstrapProof;

impl BootstrapProof {
    pub fn statement(amount_commitment: &GroupElement) -> Statement {
        Statement {
            domain_separator: b"Bootstrap_Statement_",
            equations: vec![Equation {
                // Ma = r*G_blind
                lhs: amount_commitment.clone(),
                rhs: vec![vec![GENERATORS.G_blind.clone()]],
            }],
        }
    }

    pub fn create(amount_attribute: &AmountAttribute, transcript: &mut CashuTranscript) -> ZKP {
        let statement = BootstrapProof::statement(&amount_attribute.commitment());
        SchnorrProver::new(transcript, vec![amount_attribute.r.clone()])
            .add_statement(statement)
            .prove()
    }

    pub fn verify(
        amount_commitment: &GroupElement,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let statement = BootstrapProof::statement(amount_commitment);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct MacProof;

#[allow(non_snake_case)]
impl MacProof {
    pub fn statement(
        Z: GroupElement,
        I: GroupElement,
        randomized_coin: &RandomizedCoin,
    ) -> Statement {
        let Cx0 = randomized_coin.Cx0.clone();
        let Cx1 = randomized_coin.Cx1.clone();
        let Ca = randomized_coin.Ca.clone();
        let O = GroupElement::new(&GROUP_ELEMENT_ZERO);
        Statement {
            domain_separator: b"MAC_Statement_",
            equations: vec![
                // Z = r*I
                Equation {
                    lhs: Z,
                    rhs: vec![vec![I]],
                },
                Equation {
                    // Cx1 = t*Cx0 + (-tr)*X0 + r*X1
                    lhs: Cx1,
                    rhs: vec![vec![GENERATORS.X1.clone(), GENERATORS.X0.clone(), Cx0]],
                },
                Equation {
                    // Ca = r_a*Gz_attribute + r_a*G_blind + a*G_amount
                    // MULTI-ROW: `r` witness is used twice for Gz_amount and G_blind
                    lhs: Ca,
                    rhs: vec![
                        vec![
                            GENERATORS.Gz_attribute.clone(),
                            O.clone(),
                            O.clone(),
                            GENERATORS.G_amount.clone(),
                        ],
                        vec![GENERATORS.G_blind.clone()],
                    ],
                },
            ],
        }
    }

    pub fn create(
        mint_publickey: &MintPublicKey,
        coin: &Coin,
        randomized_coin: &RandomizedCoin,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        let r_a = coin.amount_attribute.r.clone();
        let a = coin.amount_attribute.a.clone();
        let t = coin.mac.t.clone();
        let r0 = -r_a.clone() * t.as_ref();
        let (_Cw, I) = (mint_publickey.Cw.as_ref(), mint_publickey.I.as_ref());
        let Z = I.clone() * &coin.amount_attribute.r;
        let statement = MacProof::statement(Z, I.clone(), randomized_coin);
        SchnorrProver::new(transcript, vec![r_a, r0, t, a])
            .add_statement(statement)
            .prove()
    }

    pub fn verify(
        mint_privkey: &MintPrivateKey,
        randomized_coin: &RandomizedCoin,
        script: Option<&[u8]>,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let (w, x0, x1, ya, ys) = (
            &mint_privkey.w,
            &mint_privkey.x0,
            &mint_privkey.x1,
            &mint_privkey.ya,
            &mint_privkey.ys,
        );
        let (Cx0, Cx1, Ca, Cs, Cv) = (
            randomized_coin.Cx0.clone(),
            randomized_coin.Cx1.clone(),
            randomized_coin.Ca.clone(),
            randomized_coin.Cs.clone(),
            randomized_coin.Cv.clone(),
        );
        let mut S = GroupElement::new(&GROUP_ELEMENT_ZERO);
        if let Some(scr) = script {
            let s = Scalar::new(&Sha256Hash::hash(scr).to_byte_array());
            S = GENERATORS.G_script.clone() * s.as_ref();
        }
        let Z = Cv
            - &(GENERATORS.W.clone() * w
                + &(Cx0 * x0 + &(Cx1 * x1 + &(Ca * ya + &((Cs + &S) * ys)))));
        let (_Cw, I) = (
            mint_privkey.public_key.Cw.as_ref(),
            mint_privkey.public_key.I.as_ref(),
        );
        let statement = MacProof::statement(Z, I.clone(), randomized_coin);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct IParamsProof;

#[allow(non_snake_case)]
impl IParamsProof {
    pub fn statement(
        mint_publickey: &MintPublicKey,
        mac: &MAC,
        amount_commitment: &GroupElement,
        script_commitment: &GroupElement,
    ) -> Statement {
        let O = GroupElement::new(&GROUP_ELEMENT_ZERO);
        let t_tag_bytes: [u8; 32] = mac.t.as_ref().into();
        let t = mac.t.as_ref();
        let U = hash_to_curve(&t_tag_bytes).expect("Couldn't get map MAC tag to GroupElement");
        let V = mac.V.clone();
        let (Cw, I) = (mint_publickey.Cw.as_ref(), mint_publickey.I.as_ref());
        let Ma = amount_commitment.clone();
        let Ms = script_commitment.clone();
        Statement {
            domain_separator: b"Iparams_Statement_",
            equations: vec![
                Equation {
                    // Cw = w*W  + w_*W_
                    lhs: Cw.clone(),
                    rhs: vec![vec![GENERATORS.W.clone(), GENERATORS.W_.clone()]],
                },
                Equation {
                    // I = Gz_mac - x0*X0 - x1*X1 - ya*Gz_attribute - ys*Gz_script
                    lhs: I.clone() - &GENERATORS.Gz_mac,
                    rhs: vec![vec![
                        O.clone(),
                        O.clone(),
                        -GENERATORS.X0.clone(),
                        -GENERATORS.X1.clone(),
                        -GENERATORS.Gz_attribute.clone(),
                        -GENERATORS.Gz_script.clone(),
                    ]],
                },
                Equation {
                    // V = w*W + x0*U + x1*t*U + ya*Ma + ys*Ms
                    lhs: V,
                    rhs: vec![vec![GENERATORS.W.clone(), O, U.clone(), U * t, Ma, Ms]],
                },
            ],
        }
    }

    pub fn create(
        mint_privkey: &MintPrivateKey,
        mac: &MAC,
        amount_commitment: &GroupElement,
        script_commitment: Option<&GroupElement>,
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        let script_commitment: &GroupElement = match script_commitment {
            Some(scr) => scr,
            None => GENERATORS.O.as_ref(),
        };
        let statement = IParamsProof::statement(
            &mint_privkey.public_key,
            mac,
            amount_commitment,
            script_commitment,
        );
        SchnorrProver::new(transcript, mint_privkey.to_scalars())
            .add_statement(statement)
            .prove()
    }

    pub fn verify(
        mint_publickey: &MintPublicKey,
        coin: &Coin,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let script_commitment: GroupElement = match &coin.script_attribute {
            Some(scr) => scr.commitment(),
            None => GENERATORS.O.clone(),
        };
        let statement = IParamsProof::statement(
            mint_publickey,
            &coin.mac,
            &coin.amount_attribute.commitment(),
            &script_commitment,
        );
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct BalanceProof;

#[allow(non_snake_case)]
impl BalanceProof {
    pub fn statement(B: GroupElement) -> Statement {
        Statement {
            domain_separator: b"Balance_Statement_",
            equations: vec![Equation {
                lhs: B,
                rhs: vec![vec![
                    GENERATORS.Gz_attribute.clone(),
                    GENERATORS.G_blind.clone(),
                ]],
            }],
        }
    }

    pub fn create(
        inputs: &[AmountAttribute],
        outputs: &[AmountAttribute],
        transcript: &mut CashuTranscript,
    ) -> ZKP {
        let mut r_sum = Scalar::new(&SCALAR_ZERO);
        for input in inputs.iter() {
            r_sum = r_sum + &input.r;
        }
        let mut r_sum_ = Scalar::new(&SCALAR_ZERO);
        for output in outputs.iter() {
            r_sum_ = r_sum_ + &output.r;
        }
        let delta_r = (-r_sum_) + r_sum.as_ref();
        let B = GENERATORS.Gz_attribute.clone() * r_sum.as_ref()
            + (GENERATORS.G_blind.clone() * delta_r.as_ref()).as_ref();
        let statement = BalanceProof::statement(B);
        SchnorrProver::new(transcript, vec![r_sum, delta_r])
            .add_statement(statement)
            .prove()
    }

    pub fn verify(
        inputs: &[RandomizedCoin],
        outputs: &[GroupElement],
        delta_amount: i64,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let delta_a = Scalar::from(delta_amount.unsigned_abs());
        let mut B = GENERATORS.G_amount.clone() * &delta_a;
        if delta_amount >= 0 {
            B.negate();
        }
        for input in inputs.iter() {
            B = B + input.Ca.as_ref();
        }
        for output in outputs.iter() {
            B = B - output;
        }
        let statement = BalanceProof::statement(B);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct ScriptEqualityProof;

#[allow(non_snake_case)]
impl ScriptEqualityProof {
    pub fn statement(
        inputs: &[RandomizedCoin],
        outputs: &[(GroupElement, GroupElement)],
    ) -> Statement {
        let O: GroupElement = GENERATORS.O.clone();
        let mut equations: Vec<Equation> = Vec::new();

        for (i, zcoin) in inputs.iter().enumerate() {
            let construction = vec![
                vec![GENERATORS.G_script.clone()],
                vec![O.clone(); i],
                vec![GENERATORS.Gz_script.clone()],
                vec![O.clone(); inputs.len() - 1],
                vec![GENERATORS.G_blind.clone()],
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

            equations.push(Equation {
                lhs: zcoin.Cs.clone(),
                rhs: vec![construction],
            });
        }
        for (i, commitments) in outputs.iter().enumerate() {
            let construction = vec![
                vec![GENERATORS.G_script.clone()],
                vec![O.clone(); 2 * inputs.len() + i],
                vec![GENERATORS.G_blind.clone()],
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

            let (_Ma, Ms) = commitments;
            equations.push(Equation {
                lhs: Ms.clone(),
                rhs: vec![construction],
            });
        }
        Statement {
            domain_separator: b"Script_Equality_Statement_",
            equations,
        }
    }

    pub fn create(
        inputs: &[Coin],
        randomized_inputs: &[RandomizedCoin],
        outputs: &[(AmountAttribute, ScriptAttribute)],
        transcript: &mut CashuTranscript,
    ) -> Result<ZKP, Error> {
        if inputs.is_empty() || randomized_inputs.is_empty() || outputs.is_empty() {
            return Err(Error::EmptyList);
        }
        let commitments: Vec<(GroupElement, GroupElement)> = outputs
            .iter()
            .map(|(aa, sa)| (aa.commitment().clone(), sa.commitment().clone()))
            .collect();
        let statement = ScriptEqualityProof::statement(randomized_inputs, &commitments);
        let s = inputs[0]
            .script_attribute
            .as_ref()
            .ok_or(Error::NoScriptProvided)?
            .s
            .clone();
        let r_a_list = inputs
            .iter()
            .map(|coin| coin.amount_attribute.r.clone())
            .collect();
        let r_s_list = inputs
            .iter()
            .map(|coin| {
                coin.script_attribute
                    .as_ref()
                    .expect("Expected Script Attribute")
                    .r
                    .clone()
            })
            .collect();
        let new_r_s_list = outputs
            .iter()
            .map(|(_, script_attr)| script_attr.r.clone())
            .collect();
        Ok(SchnorrProver::new(
            transcript,
            vec![vec![s], r_a_list, r_s_list, new_r_s_list]
                .into_iter()
                .flatten()
                .collect(),
        )
        .add_statement(statement)
        .prove())
    }

    pub fn verify(
        randomized_inputs: &[RandomizedCoin],
        outputs: &[(GroupElement, GroupElement)],
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        if randomized_inputs.is_empty() || outputs.is_empty() {
            return false;
        }
        let statement = ScriptEqualityProof::statement(randomized_inputs, outputs);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

pub struct RangeProof;

#[allow(non_snake_case)]
impl RangeProof {
    pub fn create_bulletproof(
        transcript: &mut CashuTranscript,
        attributes: &Vec<(AmountAttribute, Option<ScriptAttribute>)>,
    ) -> RangeZKP {
        let bulletproof = BulletProof::new(transcript, attributes);
        RangeZKP::BULLETPROOF(bulletproof)
    }

    pub fn verify_bulletproof(
        transcript: &mut CashuTranscript,
        attribute_commitments: &Vec<(GroupElement, Option<GroupElement>)>,
        proof: RangeZKP,
    ) -> bool {
        match proof {
            RangeZKP::BULLETPROOF(bulletproof) => bulletproof.verify(transcript, &attribute_commitments),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        errors::Error,
        generators::{hash_to_curve, GENERATORS},
        models::{AmountAttribute, Coin, MintPrivateKey, RandomizedCoin, ScriptAttribute, MAC},
        secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO},
        transcript::CashuTranscript,
    };

    use super::{BalanceProof, BootstrapProof, IParamsProof, MacProof, ScriptEqualityProof};

    fn transcripts() -> (CashuTranscript, CashuTranscript) {
        let mint_transcript = CashuTranscript::new();
        let client_transcript = CashuTranscript::new();
        (mint_transcript, client_transcript)
    }

    fn privkey() -> MintPrivateKey {
        let scalars = vec![Scalar::random(); 6];
        MintPrivateKey::from_scalars(&scalars).expect("Could not generate private key")
    }

    #[test]
    fn test_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let bootstrap_attr = AmountAttribute::new(0, None);
        let proof = BootstrapProof::create(&bootstrap_attr, client_transcript.as_mut());
        assert!(BootstrapProof::verify(
            &bootstrap_attr.commitment(),
            proof,
            &mut mint_transcript
        ))
    }

    #[test]
    fn test_wrong_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mut bootstrap_attr = AmountAttribute::new(1, None);
        let proof = BootstrapProof::create(&mut bootstrap_attr, client_transcript.as_mut());
        assert!(!BootstrapProof::verify(
            &bootstrap_attr.commitment(),
            proof,
            &mut mint_transcript
        ))
    }

    #[test]
    fn test_iparams() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
            .expect("Couldn't generate MAC");
        let proof = IParamsProof::create(
            &mint_privkey,
            &mac,
            &amount_attr.commitment(),
            None,
            &mut client_transcript,
        );
        let coin = Coin::new(amount_attr, None, mac);
        assert!(IParamsProof::verify(
            &mint_privkey.public_key,
            &coin,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_wrong_iparams() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let mint_privkey_1 = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
            .expect("Couldn't generate MAC");
        let proof = IParamsProof::create(
            &mint_privkey,
            &mac,
            &amount_attr.commitment(),
            None,
            &mut client_transcript,
        );
        let coin = Coin::new(amount_attr, None, mac);
        assert!(!IParamsProof::verify(
            &mint_privkey_1.public_key,
            &coin,
            proof,
            &mut mint_transcript
        ))
    }

    #[test]
    fn test_mac() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
            .expect("Couldn't generate MAC");
        let coin = Coin::new(amount_attr, None, mac);
        let randomized_coin =
            RandomizedCoin::from_coin(&coin, false).expect("Expected a randomized coin");
        let proof = MacProof::create(
            &mint_privkey.public_key,
            &coin,
            &randomized_coin,
            &mut client_transcript,
        );
        assert!(MacProof::verify(
            &mint_privkey,
            &randomized_coin,
            None,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_wrong_mac() {
        #[allow(non_snake_case)]
        fn generate_custom_rand(coin: &Coin) -> Result<RandomizedCoin, Error> {
            let t = coin.mac.t.clone();
            let V = coin.mac.V.as_ref();
            let t_bytes: [u8; 32] = (&coin.mac.t).into();
            let U = hash_to_curve(&t_bytes)?;
            let Ma = coin.amount_attribute.commitment();
            // We try and randomize differently.
            let z = Scalar::random();
            let Ms: GroupElement = GroupElement::new(&GROUP_ELEMENT_ZERO);

            let Ca = GENERATORS.Gz_attribute.clone() * z.as_ref() + &Ma;
            let Cs = GENERATORS.Gz_script.clone() * z.as_ref() + &Ms;
            let Cx0 = GENERATORS.X0.clone() * z.as_ref() + &U;
            let Cx1 = GENERATORS.X1.clone() * z.as_ref() + &(U * &t);
            let Cv = GENERATORS.Gz_mac.clone() * z.as_ref() + V;

            Ok(RandomizedCoin {
                Ca,
                Cs,
                Cx0,
                Cx1,
                Cv,
            })
        }

        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mint_privkey = privkey();
        let amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None)
            .expect("Couldn't generate MAC");
        let coin = Coin::new(amount_attr, None, mac);
        let randomized_coin = generate_custom_rand(&coin).expect("Expected a randomized coin");
        let proof = MacProof::create(
            &mint_privkey.public_key,
            &coin,
            &randomized_coin,
            &mut client_transcript,
        );
        assert!(!MacProof::verify(
            &mint_privkey,
            &randomized_coin,
            None,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_balance() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let privkey = privkey();
        let inputs = vec![
            AmountAttribute::new(12, None),
            AmountAttribute::new(11, None),
        ];
        let outputs = vec![AmountAttribute::new(23, None)];
        // We assume the inputs were already attributed a MAC previously
        let macs: Vec<MAC> = inputs
            .iter()
            .map(|input| {
                MAC::generate(&privkey, &input.commitment(), None, None).expect("MAC expected")
            })
            .collect();
        let proof = BalanceProof::create(&inputs, &outputs, &mut client_transcript);
        let mut coins: Vec<Coin> = macs
            .into_iter()
            .zip(inputs)
            .map(|(mac, input)| Coin::new(input, None, mac))
            .collect();
        let randomized_coins: Vec<RandomizedCoin> = coins
            .iter_mut()
            .map(|coin| RandomizedCoin::from_coin(coin, false).expect("RandomzedCoin expected"))
            .collect();
        let outputs: Vec<GroupElement> = outputs
            .into_iter()
            .map(|output| output.commitment().clone())
            .collect();
        assert!(BalanceProof::verify(
            &randomized_coins,
            &outputs,
            0,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_wrong_balance() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let privkey = privkey();
        let mut inputs = vec![
            AmountAttribute::new(12, None),
            AmountAttribute::new(11, None),
        ];
        let outputs = vec![AmountAttribute::new(23, None)];
        // We assume the inputs were already attributed a MAC previously
        let macs: Vec<MAC> = inputs
            .iter_mut()
            .map(|input| {
                MAC::generate(&privkey, &input.commitment(), None, None).expect("MAC expected")
            })
            .collect();
        let proof = BalanceProof::create(&inputs, &outputs, &mut client_transcript);
        let mut coins: Vec<Coin> = macs
            .into_iter()
            .zip(inputs)
            .map(|(mac, input)| Coin::new(input, None, mac))
            .collect();
        let randomized_coins: Vec<RandomizedCoin> = coins
            .iter_mut()
            .map(|coin| RandomizedCoin::from_coin(coin, false).expect("RandomzedCoin expected"))
            .collect();
        let outputs: Vec<GroupElement> = outputs
            .into_iter()
            .map(|output| output.commitment().clone())
            .collect();
        assert!(!BalanceProof::verify(
            &randomized_coins,
            &outputs,
            1,
            proof,
            &mut mint_transcript
        ));
    }

    #[test]
    fn test_script_equality() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let script = b"testscript";
        let privkey = privkey();
        let inputs = vec![
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let outputs = vec![
            (
                AmountAttribute::new(6, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let macs: Vec<MAC> = inputs
            .iter()
            .map(|(amount_attr, script_attr)| {
                MAC::generate(
                    &privkey,
                    &amount_attr.commitment(),
                    Some(&script_attr.commitment()),
                    None,
                )
                .expect("")
            })
            .collect();
        let coins: Vec<Coin> = inputs
            .into_iter()
            .zip(macs)
            .map(|((aa, sa), mac)| Coin::new(aa, Some(sa), mac))
            .collect();
        let randomized_coins: Vec<RandomizedCoin> = coins
            .iter()
            .map(|coin| RandomizedCoin::from_coin(coin, false).expect(""))
            .collect();
        let proof = ScriptEqualityProof::create(
            &coins,
            &randomized_coins,
            &outputs,
            client_transcript.as_mut(),
        )
        .expect("");
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|(aa, sa)| (aa.commitment().clone(), sa.commitment().clone()))
            .collect();
        assert!(ScriptEqualityProof::verify(
            &randomized_coins,
            &outputs,
            proof,
            mint_transcript.as_mut()
        ))
    }

    #[test]
    fn test_script_inequality() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let script = b"testscript";
        let privkey = privkey();
        let inputs = vec![
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let outputs = vec![
            (
                AmountAttribute::new(6, None),
                ScriptAttribute::new(b"testscript_", None),
            ),
            (
                AmountAttribute::new(11, None),
                ScriptAttribute::new(script, None),
            ),
            (
                AmountAttribute::new(12, None),
                ScriptAttribute::new(script, None),
            ),
        ];
        let macs: Vec<MAC> = inputs
            .iter()
            .map(|(amount_attr, script_attr)| {
                MAC::generate(
                    &privkey,
                    &amount_attr.commitment(),
                    Some(&script_attr.commitment()),
                    None,
                )
                .expect("")
            })
            .collect();
        let coins: Vec<Coin> = inputs
            .into_iter()
            .zip(macs)
            .map(|((aa, sa), mac)| Coin::new(aa, Some(sa), mac))
            .collect();
        let randomized_coins: Vec<RandomizedCoin> = coins
            .iter()
            .map(|coin| RandomizedCoin::from_coin(coin, false).expect(""))
            .collect();
        let proof = ScriptEqualityProof::create(
            &coins,
            &randomized_coins,
            &outputs,
            client_transcript.as_mut(),
        )
        .expect("");
        let outputs: Vec<(GroupElement, GroupElement)> = outputs
            .into_iter()
            .map(|(aa, sa)| (aa.commitment().clone(), sa.commitment().clone()))
            .collect();
        assert!(!ScriptEqualityProof::verify(
            &randomized_coins,
            &outputs,
            proof,
            mint_transcript.as_mut()
        ))
    }
}
