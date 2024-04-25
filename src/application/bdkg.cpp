#include "bdkg.hpp"

using namespace Application;

BDKG::BDKG(SecLevel& seclevel, HashAlgo& hash, RandGen& rand,
    const ECGroup& ec_group, Mpz& q, const size_t k, const size_t n,
    const size_t t)
    : QCLPVSS(seclevel, hash, rand, q, k, n, t), ec_group_(ec_group), sks_(n),
      pks_(n), keygen_pf_(n) {

    lambdas_.reserve(n);
    generate_n(back_inserter(lambdas_), n, [] { return Mpz(1UL); });
    compute_lambdas(lambdas_, n, t, q);

    for (size_t i = 0; i < n; i++) {
        sks_[i] = this->keyGen(rand);
        pks_[i] = this->keyGen(*sks_[i]);
        keygen_pf_[i] = this->keyGen(*pks_[i], *sks_[i]);
    }

    // parties verifies key
    for (size_t i = 0; i < n; i++)
        if (!this->verifyKey(*pks_[i], *keygen_pf_[i]))
            throw std::invalid_argument("Verifying keygen proof failed.");
}

unique_ptr<EncSharesExt> BDKG::dist(const Mpz& s,
    vector<unique_ptr<const PublicKey>>& pks) const {

    auto shares = this->sss_.shareSecret(s, t_, n_, q_);
    auto enc_shares = this->EncryptShares(*shares, pks);

    unique_ptr<vector<shared_ptr<ECPoint>>> Ds(new vector<shared_ptr<ECPoint>>);
    Ds->reserve(n_);

    for (size_t i = 0; i < n_; i++)
        Ds->emplace_back(unique_ptr<ECPoint>(
            new ECPoint(ec_group_, BN((*shares)[i]->second))));

    unique_ptr<NizkExtSH> pf(new NizkExtSH(hash_, randgen_, *this, seclevel_,
        ec_group_, n_, n_ - t_ - 2, q_, Vis_));

    pair<vector<unique_ptr<const Share>>&, Mpz> witness(*shares,
        enc_shares->r_);

    pf->prove(witness, pks, *enc_shares->Bs_, *Ds, enc_shares->R_);

    return unique_ptr<EncSharesExt>(
        new EncSharesExt(*enc_shares, move(Ds), move(pf)));
}

Mpz BDKG::compute_tsk(const vector<Mpz>& tsks) const {
    Mpz tsk(0UL), temp(1UL);

    for (size_t i = 0; i < t_; i++) {

        Mpz::mul(temp, tsks[i], lambdas_[i]);
        Mpz::add(tsk, tsk, temp);
    }

    Mpz::mod(tsk, tsk, q_);
    return tsk;
}

unique_ptr<ECPoint> BDKG::compute_tpk(const vector<ECPoint>& tpks) const {

    unique_ptr<ECPoint> tpk(new ECPoint(ec_group_));
    ECPoint temp(ec_group_);

    for (size_t i = 0; i < t_; i++) {

        // tpk_i^(lambda_i)
        ec_group_.scal_mul(temp, BN(lambdas_[i]), tpks[i]);
        // Product(tpk_i)
        ec_group_.ec_add(*tpk, *tpk, temp);
    }

    return tpk;
}

const Mpz BDKG::compute_tsk_i(const vector<shared_ptr<QFI>>& Bs,
    const vector<QFI>& Rs, const SecretKey& sk) const {
    QFI B, R, fi;

    size_t sizeof_Q = Bs.size();

    vector<future<void>> futures;

    ThreadPool* pool = ThreadPool::GetInstance();

    futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < sizeof_Q; i++) {
            this->Cl_Delta().nucomp(B, B, *Bs[i]);
        }
    }));

    futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < sizeof_Q; i++) {
            this->Cl_Delta().nucomp(R, R, Rs[i]);    // always the same
        }
    }));

    for (auto& ft : futures)
        ft.get();

    this->Cl_Delta().nupow(fi, R, sk);
    this->Cl_Delta().nucompinv(fi, B, fi);

    return this->dlog_in_F(fi);
}

bool BDKG::verify_partial_keypairs(const vector<Mpz>& tsks,
    const vector<ECPoint>& tpks) const {

    size_t key_pairs = tsks.size();

    for (size_t i = 0; i < key_pairs; i++) {

        ECPoint pk(ec_group_);
        ec_group_.scal_mul_gen(pk, BN(tsks[i]));

        if (!(ec_group_.ec_point_eq(pk, tpks[i])))
            return false;
    }

    return true;
}

bool BDKG::verify_global_keypair(const Mpz& tsk, const ECPoint& tpk) const {

    ECPoint pk(ec_group_);
    ec_group_.scal_mul_gen(pk, BN(tsk));

    return ec_group_.ec_point_eq(pk, tpk);
}

void BDKG::compute_lambdas(vector<Mpz>& lambdas, const size_t n, const size_t t,
    const Mpz& q) {

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