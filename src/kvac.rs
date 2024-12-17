
use bitcoin::{amount, transaction};

use crate::generators::{hash_to_curve, GENERATORS};
use crate::models::{AmountAttribute, Coin, Equation, MintPrivateKey, Statement, ZKP};
use crate::transcript::CashuTranscript;
use crate::secp::{GroupElement, Scalar, GROUP_ELEMENT_ZERO};

pub struct SchnorrProver<'a> {
    random_terms: Vec<Scalar>,
    secrets: Vec<Scalar>,
    transcript: &'a mut CashuTranscript,
}

impl<'a> SchnorrProver<'a> {
    pub fn new(
        transcript: &'a mut CashuTranscript,
        secrets: Vec<Scalar>,
    ) -> Self {
        SchnorrProver {
            random_terms: vec![Scalar::random(); secrets.len()],
            secrets,
            transcript,                        
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(self, statement: Statement) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(&statement.domain_separator);

        for equation in statement.equations.into_iter() {

            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (k, P) in self.random_terms.iter().zip(row.into_iter())  {
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
            responses.push(
                k + (s * c.as_ref()).as_ref()
            );
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
    pub fn new(
        transcript: &'a mut CashuTranscript,
        proof: ZKP,
    ) -> Self {
        SchnorrVerifier {
            responses: proof.s,
            challenge: proof.c,
            transcript,
        }
    }

    #[allow(non_snake_case)]
    pub fn add_statement(
        self,
        statement: Statement
    ) -> Self {
        // Append proof-specific domain separator to the transcript
        self.transcript.domain_sep(&statement.domain_separator);

        for equation in statement.equations.into_iter() {

            let mut R = GroupElement::new(&GROUP_ELEMENT_ZERO);
            let V = equation.lhs;

            for row in equation.rhs.into_iter() {
                for (s, P) in self.responses.iter().zip(row.into_iter())  {
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
            equations: vec![
                Equation {          // Ma = r*G_blind
                    lhs: amount_commitment.clone(),
                    rhs: vec![vec![GENERATORS.G_blind.clone()]] 
                }
            ]
        }
    }

    pub fn create(amount_attribute: &mut AmountAttribute, transcript: &mut CashuTranscript) -> ZKP {
        let statement = BootstrapProof::statement(amount_attribute.commitment().as_ref());
        SchnorrProver::new(transcript, vec![amount_attribute.r.clone()])
            .add_statement(statement)
            .prove()
    }

    pub fn verify(amount_commitment: &GroupElement, proof: ZKP, transcript: &mut CashuTranscript) -> bool {
        let statement = BootstrapProof::statement(amount_commitment);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }

}

pub struct IParamsProof;

#[allow(non_snake_case)]
impl IParamsProof {

    pub fn statement(mint_publickey: (GroupElement, GroupElement), coin: &mut Coin) -> Statement {
        let O = GroupElement::new(&GROUP_ELEMENT_ZERO);
        let t_tag_bytes: [u8; 32] = coin.mac.t.as_ref().into();
        let t = coin.mac.t.as_ref();
        let U = hash_to_curve(&t_tag_bytes).expect("Couldn't get map MAC tag to GroupElement");
        let V = coin.mac.V.clone();
        let (Cw, I) = mint_publickey;
        let Ma = coin.amount_attribute.commitment();
        let mut Ms = O.clone();
        if let Some(scr_attr) = &mut coin.script_attribute {
            Ms = scr_attr.commitment();
        }
        Statement {
            domain_separator: b"Iparams_Statement_",
            equations: vec![
                Equation {          // Cw = w*W  + w_*W_
                    lhs: Cw,
                    rhs: vec![vec![GENERATORS.W.clone(), GENERATORS.W_.clone()]]
                },
                Equation {          // I = Gz_mac - x0*X0 - x1*X1 - ya*Gz_attribute - ys*Gz_script
                    lhs: I - &GENERATORS.Gz_mac,
                    rhs: vec![vec![
                        O.clone(),
                        O.clone(),
                        -GENERATORS.X0.clone(),
                        -GENERATORS.X1.clone(),
                        -GENERATORS.Gz_attribute.clone(),
                        -GENERATORS.Gz_script.clone(),
                    ]]
                },
                Equation {         // V = w*W + x0*U + x1*t*U + ya*Ma + ys*Ms
                    lhs: V,
                    rhs: vec![vec![
                        GENERATORS.W.clone(),
                        O,
                        U.clone(),
                        U * t.as_ref(),
                        Ma,
                        Ms,
                    ]]
                }
            ]
        }
    }
    
    pub fn new(mint_privkey: &mut MintPrivateKey, coin: &mut Coin, transcript: &mut CashuTranscript) -> ZKP {
        let mint_pubkey = mint_privkey.pubkey();
        let statement = IParamsProof::statement(mint_pubkey, coin);
        SchnorrProver::new(transcript, mint_privkey.to_scalars())
            .add_statement(statement)
            .prove()
    }

    pub fn verify(
        mint_publickey: (GroupElement, GroupElement),
        coin: &mut Coin,
        proof: ZKP,
        transcript: &mut CashuTranscript,
    ) -> bool {
        let statement = IParamsProof::statement(mint_publickey, coin);
        SchnorrVerifier::new(transcript, proof)
            .add_statement(statement)
            .verify()
    }
}

#[cfg(test)]
mod tests{

    use crate::{models::{AmountAttribute, Coin, MintPrivateKey, MAC}, secp::Scalar, transcript::CashuTranscript};

    use super::{BootstrapProof, IParamsProof};

    fn transcripts() -> (CashuTranscript, CashuTranscript) {
        let mint_transcript = CashuTranscript::new();
        let client_transcript = CashuTranscript::new();
        (mint_transcript, client_transcript)
    }

    fn privkey() -> MintPrivateKey {
        let scalars = [
            Scalar::random(),
            Scalar::random(),
            Scalar::random(),
            Scalar::random(),
            Scalar::random(),
            Scalar::random()
        ];
        MintPrivateKey::from_scalars(&scalars)
    }

    #[test]
    fn test_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mut bootstrap_attr = AmountAttribute::new(0, None);
        let proof = BootstrapProof::create(&mut bootstrap_attr, client_transcript.as_mut());
        assert!(BootstrapProof::verify(bootstrap_attr.commitment().as_ref(), proof, &mut mint_transcript))
    }

    #[test]
    fn test_wrong_bootstrap() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mut bootstrap_attr = AmountAttribute::new(1, None);
        let proof = BootstrapProof::create(&mut bootstrap_attr, client_transcript.as_mut());
        assert!(!BootstrapProof::verify(bootstrap_attr.commitment().as_ref(), proof, &mut mint_transcript))
    }

    #[test]
    fn test_iparams() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mut mint_privkey = privkey();
        let mut amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None).expect("Couldn't generate MAC");
        let mut coin = Coin::new(amount_attr, None, mac);
        let proof = IParamsProof::new(&mut mint_privkey, &mut coin, &mut client_transcript);
        assert!(IParamsProof::verify(mint_privkey.pubkey(), &mut coin, proof, &mut mint_transcript));
    }

    #[test]
    fn test_wrong_iparams() {
        let (mut mint_transcript, mut client_transcript) = transcripts();
        let mut mint_privkey = privkey();
        let mut mint_privkey_1 = privkey();
        let mut amount_attr = AmountAttribute::new(12, None);
        let mac = MAC::generate(&mint_privkey, &amount_attr.commitment(), None, None).expect("Couldn't generate MAC");
        let mut coin = Coin::new(amount_attr, None, mac);
        let proof = IParamsProof::new(&mut mint_privkey, &mut coin, &mut client_transcript);
        assert!(!IParamsProof::verify(mint_privkey_1.pubkey(), &mut coin, proof, &mut mint_transcript))
    }
}