#include "pvss_reshare.hpp"
#include "nizk_resh.hpp"
#include <chrono>

using namespace std::chrono;
using namespace Application;
using namespace NIZK;

PVSS_Reshare::PVSS_Reshare(const SecLevel& seclevel, HashAlgo& hash,
    RandGen& rand, const Mpz& q, const size_t n0, const size_t t0,
    const size_t n1, const size_t t1)
    : QCLPVSS(seclevel, hash, rand, q, 1, n0, t0), sks(n0), pks(n0),
      keygen_pf(n0), n0_(n0), t0_(t0), n1_(n1), t1_(t1) {

    lambdas_.reserve(n0);
    generate_n(back_inserter(lambdas_), n0, [] { return Mpz(1UL); });
    compute_lambdas(lambdas_, n0, t0, q);

    Vis_reshare_.reserve(n0 + 1);
    generate_n(back_inserter(Vis_reshare_), n0 + 1, [] { return Mpz(1UL); });
    this->computeSCRAPEvis(Vis_reshare_, n0 + 1, 0, q_);

    for (size_t i = 0; i < n0_; i++) {
        sks[i] = this->keyGen(randgen_);
        pks[i] = this->keyGen(*sks[i]);
        keygen_pf[i] = this->keyGen(*pks[i], *sks[i]);

        if (!this->verifyKey(*pks[i], *keygen_pf[i]))
            throw std::invalid_argument("Verifying  key pair failed.");
    }

    secret_ = Mpz(9898UL);

    enc_shares = this->dist(secret_, pks);
}

unique_ptr<EncShares> PVSS_Reshare::reshare(const EncShares& enc_shares) {

    vector<EncSharesResh> enc_sh_resh;
    enc_sh_resh.reserve(n0_);

    auto start = std::chrono::system_clock::now();

    for (size_t j = 0; j < n0_; j++) {
        unique_ptr<DecShare> dec_share = this->decShare(*pks[j], *sks[j],
            enc_shares.R_, *enc_shares.Bs_->at(j), j);

        auto shares = this->sss_.shareSecret(dec_share->sh_->y(), t1_, n1_, q_);

        auto enc_shares_j = this->EncryptShares(*shares, pks);

        auto witness = tie(*sks[j], enc_shares_j->r_, *shares);

        unique_ptr<NizkResh> pf = unique_ptr<NizkResh>(new NizkResh(hash_,
            randgen_, *this, seclevel_, n1_, n1_ - t1_ - 1, q_, Vis_reshare_));

        pf->prove(witness, pks, *pks[j], enc_shares.R_, *enc_shares.Bs_->at(j),
            enc_shares_j->R_, *enc_shares_j->Bs_);

        enc_sh_resh.emplace_back(EncSharesResh(*enc_shares_j, move(pf)));
    }

    auto stop = std::chrono::system_clock::now();
    auto ms_int = duration_cast<milliseconds>(stop - start);
    cout << "Reshare: " << ms_int.count() << endl;

    start = std::chrono::system_clock::now();

    for (size_t j = 0; j < n0_; j++) {

        bool verified = enc_sh_resh[j].pf_->verify(pks, *pks[j], enc_shares.R_,
            *enc_shares.Bs_->at(j), enc_sh_resh[j].R_, *enc_sh_resh[j].Bs_);

        if (!verified)
            throw std::invalid_argument(
                "Failed verifying proof for correct resharing.");
    }

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "Verify Reshare: " << ms_int.count() << endl;

    unique_ptr<EncShares> enc_sh_output(new EncShares(n1_));

    start = std::chrono::system_clock::now();

    QFI temp;
    for (size_t j = 0; j < t0_ + 1; j++) {
        EncSharesResh& sh = enc_sh_resh[j];

        this->Cl_Delta().nupow(temp, sh.R_, lambdas_[j]);
        this->Cl_Delta().nucomp(enc_sh_output->R_, enc_sh_output->R_, temp);
    }

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "Compute R: " << ms_int.count() << endl;

    start = std::chrono::system_clock::now();

    for (size_t i = 0; i < n1_; i++) {
        for (size_t j = 0; j < t0_ + 1; j++) {
            this->Cl_Delta().nupow(temp, *enc_sh_resh[j].Bs_->at(i),
                lambdas_[j]);
            this->Cl_Delta().nucomp(*enc_sh_output->Bs_->at(i),
                *enc_sh_output->Bs_->at(i), temp);
        }
    }

    stop = std::chrono::system_clock::now();
    ms_int = duration_cast<milliseconds>(stop - start);
    cout << "Compute Bs: " << ms_int.count() << endl;

    return enc_sh_output;
}

bool PVSS_Reshare::verifyResharing(const EncShares& enc_shares) const {

    vector<unique_ptr<DecShare>> dec_shares(n1_);
    vector<unique_ptr<const Share>> rec_shares;
    rec_shares.reserve(n1_);

    for (size_t i = 0; i < n1_; i++) {

        dec_shares[i] = this->decShare(*pks[i], *sks[i], enc_shares.R_,
            *enc_shares.Bs_->at(i), i);
    }

    for (const auto& dec_share : dec_shares)
        if (dec_share->sh_)
            rec_shares.push_back(
                unique_ptr<const Share>(new Share(*dec_share->sh_)));

    auto s_rec = this->rec(rec_shares);

    return *s_rec == secret_;
}

void PVSS_Reshare::compute_lambdas(vector<Mpz>& lambdas, const size_t n,
    const size_t t, const Mpz& q) {

    for (size_t i = 1; i < n + 1; i++) {
        Mpz numerator(1UL), denominator(1UL), ai(i);

        for (size_t k = 1; k < t + 1; k++) {
            if (i == k)
                continue;

            Mpz ak(k);
            Mpz::mul(numerator, numerator, ak);
            Mpz::sub(ak, ak, ai);
            Mpz::mul(denominator, denominator, ak);
        }

        Mpz::mod_inverse(denominator, denominator, q);
        Mpz::mul(numerator, numerator, denominator);
        Mpz::mod(lambdas[i - 1], numerator, q);
    }
}
