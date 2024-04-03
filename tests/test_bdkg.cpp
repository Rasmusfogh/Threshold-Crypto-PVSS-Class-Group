#include "../src/application/bdkg.hpp"
#include <assert.h>
#include <chrono>
#include <memory>
#include <nizk_sh_ext.hpp>
#include <secp256k1.h>

using namespace Application;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace NIZK;

int main(int argc, char* argv[]) {
    Mpz seed;
    SecLevel seclevel(128);
    RandGen randgen;

    ECGroup ec_group_(seclevel);

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    Mpz q(ec_group_.order());

    HashAlgo H(seclevel);

    size_t n(10UL);
    size_t t(5UL);

    BDKG bdkg(seclevel, H, randgen, ec_group_, q, 1, n, t);

    // Setup
    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    vector<unique_ptr<NizkDL>> keygen_pf(n);
    vector<unique_ptr<EncSharesExt>> enc_sh(n);

    vector<Mpz> tsks;
    tsks.reserve(n);

    vector<ECPoint> tpks;
    tpks.reserve(n);
    generate_n(back_inserter(tpks), n, [&] { return ECPoint(ec_group_); });

    /********************* 1 Round DKG *************************/

    for (size_t i = 0; i < n; i++) {
        sks[i] = bdkg.keyGen(randgen);
        pks[i] = bdkg.keyGen(*sks[i]);
        keygen_pf[i] = bdkg.keyGen(*pks[i], *sks[i]);
    }

    // parties verifies key
    for (size_t i = 0; i < n; i++)
        if (!bdkg.verifyKey(*pks[i], *keygen_pf[i]))
            return EXIT_FAILURE;

    // parties share random secret
    for (size_t j = 0; j < n; j++) {
        Mpz s_j = (randgen.random_mpz(q));
        enc_sh[j] = bdkg.dist(s_j, pks);
    }

    auto start = std::chrono::system_clock::now();

    // parties verify shares
    for (size_t j = 0; j < n; j++) {
        if (!(enc_sh[j]->pf_->verify(pks, *enc_sh[j]->Bs_, *enc_sh[j]->Ds_,
                enc_sh[j]->R_))) {
            return EXIT_FAILURE;
        }
    }

    auto stop = std::chrono::system_clock::now();
    auto ms_int = duration_cast<milliseconds>(stop - start);
    cout << "verifying shares: " << ms_int.count() << endl;

    /********************* Output sharing *************************/

    vector<vector<shared_ptr<QFI>>> shared_Bs;
    shared_Bs.reserve(n);

    vector<QFI> shared_Rs;
    shared_Rs.reserve(n);

    // Simulate sharing of Bs and Rs between parties
    for (size_t i = 0; i < n; i++) {
        shared_Bs.emplace_back(vector<shared_ptr<QFI>>());
        shared_Bs[i].reserve(n);

        shared_Rs.emplace_back(enc_sh[i]->R_);

        for (size_t j = 0; j < n; j++)
            shared_Bs[i].emplace_back(enc_sh[j]->Bs_->at(i));
    }

    /********************* GLOBAL OUTPUT *************************/

    // |Q| = n as all proofs verifies above
    size_t Q = n;

    start = std::chrono::system_clock::now();

    // Compute tpks[i]
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < Q; j++)
            ec_group_.ec_add(tpks[i], tpks[i], *enc_sh[j]->Ds_->at(i));
    }

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "computing n tpk_i's: " << ms_int.count() << endl;

    start = std::chrono::system_clock::now();

    // Compute global public key
    unique_ptr<ECPoint> tpk = move(bdkg.compute_tpk(tpks));

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "computing global tpk: " << ms_int.count() << endl;

    /********************* PRIVATE OUTPUT *************************/

    start = std::chrono::system_clock::now();

    // Compute private key share 0
    tsks.emplace_back(bdkg.compute_tsk_i(shared_Bs[0], shared_Rs, *sks[0]));

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "computing 1 tsk: " << ms_int.count() << endl;

    // Compute private key share
    for (size_t i = 1; i < n; i++)
        tsks.emplace_back(bdkg.compute_tsk_i(shared_Bs[i], shared_Rs, *sks[i]));

    /********************* VERIFY OUTPUT *************************/

    // Verify tsk[i] relates to tpk[i]
    if (!bdkg.verify_partial_keypairs(tsks, tpks))
        return EXIT_FAILURE;

    // Verify tsk relates to tpk
    Mpz tsk = bdkg.compute_tsk(tsks);
    if (!bdkg.verify_global_keypair(tsk, *tpk))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}