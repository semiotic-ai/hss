use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, g1::Config};
use ark_ec::pairing::Pairing;
use ark_ec::{
    AffineRepr,
    hashing::{
        HashToCurve, HashToCurveError, curve_maps::wb::WBMap,
        map_to_curve_hasher::MapToCurveBasedHasher,
    },
};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use ark_std::{UniformRand, Zero, ops::Mul};
use sha2::Sha256;

pub struct PK {
    p: G1Affine,
    q: G2Affine,
    r: G2Affine,
}

fn hash_to_curve(msg: &[u8], domain: &[u8]) -> Result<G1Affine, HashToCurveError> {
    let hasher =
        MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256>, WBMap<Config>>::new(
            domain,
        )?;
    let hash_point: G1Affine = hasher.hash(msg)?;
    Ok(hash_point)
}

pub fn setup() -> (PK, Fr) {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let mut rng = ark_std::test_rng();
    let sk = Fr::rand(&mut rng);
    let r = q.mul(sk);

    (PK { p, q, r: r.into() }, sk)
}

pub fn sign(sk: Fr, pk: &PK, id: &[u8], index: usize, m: Fr) -> Result<G1Affine, HashToCurveError> {
    let hash_point = hash_to_curve(&index.to_le_bytes(), id)?;
    let signature: G1Projective = (hash_point + pk.p.mul(m)).mul(sk);
    Ok(signature.into())
}

pub fn verify(
    pk: &PK,
    id: &[u8],
    index: usize,
    m: Fr,
    signature: G1Affine,
) -> Result<bool, HashToCurveError> {
    let hash_point = hash_to_curve(&index.to_le_bytes(), id)?;
    let left = Bls12_381::pairing(signature, pk.q);
    let right = Bls12_381::pairing(hash_point + pk.p.mul(m), pk.r);
    Ok(left == right)
}

pub fn verify_aggregate(
    pk: &PK,
    id: &[u8],
    weights: Vec<Fr>,
    m: Fr,
    signature: G1Affine,
) -> Result<bool, HashToCurveError> {
    let mut hash_point = G1Projective::zero();
    for (i, w) in weights.iter().enumerate() {
        hash_point += hash_to_curve(&i.to_le_bytes(), id)?.mul(w);
    }
    let left = Bls12_381::pairing(signature, pk.q);
    let right = Bls12_381::pairing(hash_point + pk.p.mul(m), pk.r);
    Ok(left == right)
}

pub fn combine(weights: &Vec<Fr>, signatures: Vec<G1Affine>) -> G1Affine {
    let aggregate_signature = signatures
        .iter()
        .zip(weights)
        .fold(G1Projective::zero(), |acc, (x, w)| acc + x.mul(w));
    aggregate_signature.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        // Generate public key and secret key
        let (pk, sk) = setup();

        // Pick a unique identifier
        let id = b"test";

        // Testing with 8 random messages
        let n = 8;
        let m_vec = vec![Fr::rand(&mut ark_std::test_rng()); n];

        // Sign and verify each message
        let mut signatures = Vec::new();
        for (i, m) in m_vec.iter().enumerate() {
            let signature = sign(sk, &pk, id, i, *m).unwrap();
            assert!(verify(&pk, id, i, m_vec[i], signature).unwrap());
            signatures.push(signature);
        }

        // Generate an aggregate signature and message with random weights
        let mut rng = ark_std::test_rng();
        let weights = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let aggregate_signature = combine(&weights, signatures);
        let aggregate_m = m_vec.iter().zip(&weights).map(|(m, w)| m.mul(w)).sum();

        // Verify the aggregate signature
        assert!(verify_aggregate(&pk, id, weights.clone(), aggregate_m, aggregate_signature).unwrap());

        // Test with wrong message
        let wrong_m = Fr::rand(&mut ark_std::test_rng());
        assert!(!verify_aggregate(&pk, id, weights, wrong_m, aggregate_signature).unwrap());
    }
}
