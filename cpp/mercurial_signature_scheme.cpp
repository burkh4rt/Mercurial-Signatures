
#include <random>
#include <iostream>
#include <chrono>
#include <cassert>

#include "miracl_core_cpp_bn254/pair_BN254.h"
#include "miracl_core_cpp_bn254/big_B256_56.h"

using namespace BN254;
using namespace B256_56;

class MercurialSignatureScheme
{
public:
    /* signature type */
    typedef struct
    {
        ECP Z;
        ECP Y;
        ECP2 Yhat;
    } sigma_t;
    ECP P{};
    ECP2 Phat{};
    BIG r{};
    /* ell is the length of the signatures (and messages) */
    const uint ell;

    /* initialize with constant ell */
    explicit MercurialSignatureScheme(uint el) : ell(el)
    {
        /* P & Phat are generators for G1 & G2 */
        ECP_generator(&(this->P));
        ECP2_generator(&(this->Phat));
        /* r is the order of G1, G2, & GT */
        BIG_rcopy(r, CURVE_Order);
    };

    /* generate public key pk, secret key sk pairing as arrays of length ell */
    void KeyGen(ECP2 *pk, BIG *sk, csprng *rng)
    {
        for (int i = 0; i < ell; i++)
        {
            BIG_randomnum(sk[i], r, rng);
            ECP2_copy(&pk[i], &(this->Phat));
            PAIR_G2mul(&pk[i], sk[i]);
        };
    };

    /* sign a message M with sk */
    void Sign(BIG *sk, ECP *M, sigma_t *sigma, csprng *rng)
    {
        BIG y, y_inv;
        ECP factor;
        BIG_randomnum(y, r, rng);
        BIG_invmodp(y_inv, y, r);
        ECP_copy(&(sigma->Z), &M[0]);
        PAIR_G1mul(&(sigma->Z), sk[0]);
        for (int i = 1; i < ell; i++)
        {
            ECP_copy(&factor, &M[i]);
            PAIR_G1mul(&factor, sk[i]);
            ECP_add(&(sigma->Z), &factor);
        };
        PAIR_G1mul(&(sigma->Z), y);
        ECP_copy(&(sigma->Y), &P);
        ECP2_copy(&(sigma->Yhat), &Phat);
        PAIR_G1mul(&(sigma->Y), y_inv);
        PAIR_G2mul(&(sigma->Yhat), y_inv);
    };

    /* verify that signature sigma is valid for pk and M */
    bool Verify(ECP2 *pk, ECP *M, sigma_t *sigma)
    {
        FP12 q1, q2, q3, q4, factor;
        PAIR_ate(&q1, &pk[0], &M[0]);
        PAIR_fexp(&q1);
        for (int i = 1; i < ell; i++)
        {
            PAIR_ate(&factor, &pk[i], &M[i]);
            PAIR_fexp(&factor);
            FP12_mul(&q1, &factor);
        };
        PAIR_ate(&q2, &(sigma->Yhat), &(sigma->Z));
        PAIR_fexp(&q2);
        PAIR_ate(&q3, &(this->Phat), &(sigma->Y));
        PAIR_fexp(&q3);
        PAIR_ate(&q4, &(sigma->Yhat), &(this->P));
        PAIR_fexp(&q4);
        return (bool)FP12_equals(&q1, &q2) & (bool)FP12_equals(&q3, &q4);
    };

    /* convert sk with randomness rho */
    void ConvertSK(BIG *sk, BIG rho)
    {
        for (int i = 0; i < ell; i++)
        {
            BIG_modmul(sk[i], sk[i], rho, this->r);
        };
    };

    /* convert pk with randomness rho */
    void ConvertPK(ECP2 *pk, BIG rho)
    {
        for (int i = 0; i < ell; i++)
        {
            ECP2_mul(&pk[i], rho);
        };
    };

    /* convert signature sigma */
    void ConvertSig(ECP2 *pk, ECP *M, sigma_t *sigma, BIG rho, csprng *rng)
    {
        BIG psi, psi_inv;
        BIG_randomnum(psi, this->r, rng);
        BIG_invmodp(psi_inv, psi, this->r);
        ECP_mul(&(sigma->Z), rho);
        ECP_mul(&(sigma->Z), psi);
        ECP_mul(&(sigma->Y), psi_inv);
        ECP2_mul(&(sigma->Yhat), psi_inv);
    };

    /* change representation of equivalence class for M & sigma */
    void ChangeRep(ECP2 *pk, ECP *M, sigma_t *sigma, BIG mu, csprng *rng)
    {
        BIG psi, psi_inv;
        BIG_randomnum(psi, this->r, rng);
        BIG_invmodp(psi_inv, psi, this->r);
        for (int i = 0; i < ell; i++)
        {
            ECP_mul(&M[i], mu);
        };
        ECP_mul(&(sigma->Z), mu);
        ECP_mul(&(sigma->Z), psi);
        ECP_mul(&(sigma->Y), psi_inv);
        ECP2_mul(&(sigma->Yhat), psi_inv);
    };
};

int main()
{
    // initialize rng
    csprng RNG;
    char pr[10];
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::independent_bits_engine<std::mt19937, 64, std::uint_fast64_t> g1(seed);
    for (int i = 1; i < 10; i++)
        pr[i] = (char)g1();
    RAND_seed(&RNG, 10, pr);

    // initialize scheme
    uint ell = 3;
    MercurialSignatureScheme MSS(ell);
    ECP2 pk[ell];
    BIG sk[ell];
    MSS.KeyGen(pk, sk, &RNG);

    // allocate signature
    MercurialSignatureScheme::sigma_t sigma;
    sigma.Y = MSS.P;
    sigma.Yhat = MSS.Phat;
    sigma.Z = MSS.P;

    // generate random message
    ECP M[ell];
    BIG rand;
    for (int j = 0; j < ell; j++)
    {
        ECP_copy(&M[j], &MSS.P);
        BIG_randomnum(rand, MSS.r, &RNG);
        PAIR_G1mul(&M[j], rand);
    }

    // test KeyGen(), Sign(), and Verify()
    MSS.Sign(sk, M, &sigma, &RNG);
    assert(MSS.Verify(pk, M, &sigma));

    // test ConvertPK() and ConvertSig()
    BIG rho;
    BIG_randomnum(rho, MSS.r, &RNG);
    MSS.ConvertPK(pk, rho);
    MSS.ConvertSig(pk, M, &sigma, rho, &RNG);
    assert(MSS.Verify(pk, M, &sigma));

    // test ChangeRep()
    BIG mu;
    BIG_randomnum(mu, MSS.r, &RNG);
    MSS.ChangeRep(pk, M, &sigma, mu, &RNG);
    assert(MSS.Verify(pk, M, &sigma));

    // test ConvertSK(), ConvertPK(), and Verify
    MSS.KeyGen(pk, sk, &RNG);
    BIG_randomnum(rho, MSS.r, &RNG);
    MSS.ConvertPK(pk, rho);
    MSS.ConvertSK(sk, rho);
    MSS.Sign(sk, M, &sigma, &RNG);
    assert(MSS.Verify(pk, M, &sigma));

    return 0;
}