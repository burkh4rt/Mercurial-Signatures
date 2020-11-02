extern crate mercurial_signatures;

#[allow(non_snake_case, non_camel_case_types)]
fn main() {
    // initialize rng
    let mut rng = mercurial_signatures::prepare_rng();

    // initialize scheme
    let MSS = mercurial_signatures::MercurialSignatureScheme::new(4);

    // test KeyGen(), Sign(), and Verify()
    let (sk, pk) = MSS.KeyGen(&mut rng);
    let M = MSS.randomMessage(&mut rng);
    let sigma = MSS.Sign(&sk, &M, &mut rng);
    assert!(MSS.Verify(&pk, &M, &sigma));

    // test ConvertPK() and ConvertSignature()
    let rho = MSS.randomZp(&mut rng);
    let new_pk = MSS.ConvertPK(pk, &rho);
    let new_sig = MSS.ConvertSignature(sigma, &rho, &mut rng);
    assert!(MSS.Verify(&new_pk, &M, &new_sig));

    // test ChangeRepresentation()
    let mu = MSS.randomZp(&mut rng);
    let (new_M, new_sig) = MSS.ChangeRepresentation(M, new_sig, &mu, &mut rng);
    assert!(MSS.Verify(&new_pk, &new_M, &new_sig));

    // test ConvertSK(), ConvertPK(), and Verify
    let (sk, pk) = MSS.KeyGen(&mut rng);
    let rho = MSS.randomZp(&mut rng);
    let new_pk = MSS.ConvertPK(pk, &rho);
    let new_sk = MSS.ConvertSK(sk, &rho);
    let sigma = MSS.Sign(&new_sk, &new_M, &mut rng);
    assert!(MSS.Verify(&new_pk, &new_M, &sigma));
}
