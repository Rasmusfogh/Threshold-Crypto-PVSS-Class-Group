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
    this->computeSCRAPEcoeffs(Vis_reshare_, n0 + 1, 0, q_);

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

unique_ptr<vector<EncSharesResh>> PVSS_Reshare::reshare(
    const EncShares& enc_shares) const {

    unique_ptr<vector<EncSharesResh>> enc_sh_resh(new vector<EncSharesResh>());
    enc_sh_resh->reserve(t0_ + 1);

    for (size_t j = 0; j < t0_ + 1; j++) {
        unique_ptr<DecShare> dec_share = this->decShare(*pks[j], *sks[j],
            enc_shares.R_, *enc_shares.Bs_->at(j), j);

        auto shares = this->sss_.shareSecret(dec_share->sh_->y(), t1_, n1_, q_);

        auto enc_shares_j = this->EncryptShares(*shares, pks);

        auto witness = tie(*sks[j], enc_shares_j->r_, *shares);

        unique_ptr<NizkResh> pf = unique_ptr<NizkResh>(new NizkResh(hash_,
            randgen_, *this, seclevel_, n1_, n1_ - t1_ - 1, q_, Vis_reshare_));

        pf->prove(witness, pks, *pks[j], enc_shares.R_, *enc_shares.Bs_->at(j),
            enc_shares_j->R_, *enc_shares_j->Bs_);

        enc_sh_resh->emplace_back(EncSharesResh(*enc_shares_j, move(pf)));
    }

    return enc_sh_resh;
}

bool PVSS_Reshare::verifyReshare(const vector<EncSharesResh>& enc_sh_resh,
    const EncShares& enc_shares) const {

    for (size_t j = 0; j < t0_; j++)
        if (!enc_sh_resh[j].pf_->verify(pks, *pks[j], enc_shares.R_,
                *enc_shares.Bs_->at(j), enc_sh_resh[j].R_, *enc_sh_resh[j].Bs_))
            return false;

    return true;
}

unique_ptr<EncShares> PVSS_Reshare::distReshare(
    const vector<EncSharesResh>& enc_sh_resh) const {

    unique_ptr<EncShares> enc_sh_output(new EncShares(n1_));

    size_t T = t0_ + 1;

    ThreadPool* pool = ThreadPool::GetInstance();

    vector<QFI> R_exp(T);

    vector<future<void>> R_exp_futures;
    vector<future<void>> futures;

    for (size_t j = 0; j < T; j++) {
        R_exp_futures.emplace_back(pool->enqueue([&, j]() {
            this->Cl_Delta().nupow(R_exp[j], enc_sh_resh[j].R_, lambdas_[j]);
        }));
    }

    for (size_t i = 0; i < n1_; i++) {
        futures.emplace_back(pool->enqueue([&, i]() {
            QFI temp;

            for (size_t j = 0; j < T; j++) {
                this->Cl_Delta().nupow(temp, *enc_sh_resh[j].Bs_->at(i),
                    lambdas_[j]);
                this->Cl_Delta().nucomp(*enc_sh_output->Bs_->at(i),
                    *enc_sh_output->Bs_->at(i), temp);
            }
        }));
    }

    for (auto& ft : R_exp_futures)
        ft.get();

    futures.emplace_back(pool->enqueue([&]() {
        for (size_t j = 0; j < T; j++)
            this->Cl_Delta().nucomp(enc_sh_output->R_, enc_sh_output->R_,
                R_exp[j]);
    }));

    for (auto& ft : futures)
        ft.get();

    return enc_sh_output;
}

bool PVSS_Reshare::verifyDistReshare(const EncShares& enc_share) const {

    vector<unique_ptr<DecShare>> dec_shares(n1_);
    vector<unique_ptr<const Share>> rec_shares;

    for (size_t i = 0; i < n1_; i++)
        dec_shares[i] = this->decShare(*pks[i], *sks[i], enc_share.R_,
            *enc_share.Bs_->at(i), i);

    // Simulate parties reconstructing by providing their share
    for (const auto& dec_share : dec_shares)
        if (dec_share->sh_)
            rec_shares.push_back(
                unique_ptr<const Share>(new Share(*dec_share->sh_)));

    auto secret_rec = this->sss_.reconstructSecret(rec_shares, t1_ + 1, q_);
    return secret_ == *secret_rec;
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
