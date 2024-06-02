#include "bdkg.hpp"
#include "nizk_sh_ext.hpp"
#include <chrono>
#include <memory>

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

    size_t n(50);
    size_t t(25);

    BDKG bdkg(seclevel, H, randgen, ec_group_, q, 1, n, t);

    vector<unique_ptr<EncSharesExt>> enc_sh(n);

    vector<Mpz> tsks;
    tsks.reserve(t + 1);

    vector<ECPoint> tpks;
    tpks.reserve(t + 1);
    generate_n(back_inserter(tpks), t + 1, [&] { return ECPoint(ec_group_); });

    /********************* 1 Round DKG *************************/

    // parties share random secret
    for (size_t j = 0; j < t + 1; j++) {
        Mpz s_j = (randgen.random_mpz(q));
        enc_sh[j] = bdkg.dist(s_j, bdkg.pks_);
    }

    auto start = std::chrono::system_clock::now();

    // parties verify shares
    for (size_t j = 0; j < t + 1; j++) {
        if (!(enc_sh[j]->pf_->verify(bdkg.pks_, *enc_sh[j]->Bs_,
                *enc_sh[j]->Ds_, enc_sh[j]->R_))) {
            return EXIT_FAILURE;
        }
    }

    auto stop = std::chrono::system_clock::now();
    auto ms_int = duration_cast<milliseconds>(stop - start);
    cout << "verifying shares: " << ms_int.count() << endl;

    /********************* Output sharing *************************/

    vector<vector<shared_ptr<QFI>>> Bs_transpose;
    Bs_transpose.reserve(t + 1);

    vector<QFI> Rs_transpose;
    Rs_transpose.reserve(t + 1);

    // Simulate sharing of Bs and Rs between parties
    for (size_t i = 0; i < t + 1; i++) {
        Bs_transpose.emplace_back(vector<shared_ptr<QFI>>());
        Bs_transpose[i].reserve(t + 1);

        for (size_t j = 0; j < t + 1; j++)
            Bs_transpose[i].emplace_back(enc_sh[j]->Bs_->at(i));
    }

    for (size_t i = 0; i < t + 1; i++)
        Rs_transpose.emplace_back(enc_sh[i]->R_);

    /********************* GLOBAL OUTPUT *************************/

    // |Q| = n as all proofs verifies above
    size_t Q = t + 1;

    start = std::chrono::system_clock::now();

    // Compute tpks[i]
    for (size_t i = 0; i < t + 1; i++) {
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
    tsks.emplace_back(
        bdkg.compute_tsk_i(Bs_transpose[0], Rs_transpose, *bdkg.sks_[0]));

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "computing 1 tsk: " << ms_int.count() << endl;

    // Compute private key share
    for (size_t i = 1; i < t + 1; i++)
        tsks.emplace_back(
            bdkg.compute_tsk_i(Bs_transpose[i], Rs_transpose, *bdkg.sks_[i]));

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