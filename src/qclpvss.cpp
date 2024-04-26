#include "qclpvss.hpp"
#include <thread>

using namespace QCLPVSS_;
using namespace NIZK;
using namespace SSS_;
using namespace BICYCL;
using namespace OpenSSL;
using namespace DATATYPE;

QCLPVSS::QCLPVSS(const SecLevel& seclevel, HashAlgo& hash, RandGen& randgen,
    const Mpz& q, const size_t k, const size_t n, const size_t t)
    : CL_HSMqk(q, k, seclevel, randgen, false), sss_(SSS(randgen)),
      seclevel_(seclevel), randgen_(randgen), hash_(hash), k_(k), n_(n), t_(t),
      q_(q) {
    /* Checks */
    if (Mpz(n + k) > q)
        throw std::invalid_argument("n + k must be less than or equal to q");
    if (t_ + k > n_)
        throw std::invalid_argument("k + t must be less than or equal to n");

    Vis_.reserve(n);
    generate_n(back_inserter(Vis_), n, [] { return Mpz(1UL); });
    computeSCRAPEcoeffs(Vis_, n, 1, q_);
}

unique_ptr<const SecretKey> QCLPVSS::keyGen(RandGen& randgen) const {
    return unique_ptr<const SecretKey>(new SecretKey(*this, randgen));
}

unique_ptr<const PublicKey> QCLPVSS::keyGen(const SecretKey& sk) const {
    return unique_ptr<const PublicKey>(new PublicKey(*this, sk));
}

unique_ptr<NizkDL> QCLPVSS::keyGen(const PublicKey& pk,
    const SecretKey& sk) const {
    unique_ptr<NizkDL> pf(new NizkDL(hash_, randgen_, *this, seclevel_));
    pf->prove(sk, pk);
    return pf;
}

bool QCLPVSS::verifyKey(const PublicKey& pk, const NizkDL& pf) const {
    return pf.verify(pk);
}

unique_ptr<EncShares> QCLPVSS::dist(const Mpz& s,
    vector<unique_ptr<const PublicKey>>& pks) const {
    auto shares = createShares(s);
    auto enc_shares = EncryptShares(*shares, pks);
    computeSHNizk(pks, *enc_shares);
    return enc_shares;
}

bool QCLPVSS::verifySharing(const EncShares& sh,
    vector<unique_ptr<const PublicKey>>& pks) const {
    return sh.pf_->verify(pks, *sh.Bs_, sh.R_);
}

unique_ptr<DecShare> QCLPVSS::decShare(const PublicKey& pk, const SecretKey& sk,
    const QFI& R, const QFI& B, size_t i) const {
    QFI fi, Mi;

    unique_ptr<DecShare> dec_share(new DecShare());
    this->Cl_G().nupow(fi, R, sk);
    this->Cl_Delta().nucompinv(fi, B, fi);
    this->Cl_Delta().nucompinv(Mi, B, fi);

    // return Ai on the form of a share <i, Ai>
    dec_share->sh_ =
        unique_ptr<const Share>(new Share(i + 1, Mpz(this->dlog_in_F(fi))));
    dec_share->pf_ =
        unique_ptr<NizkDLEQ>(new NizkDLEQ(hash_, randgen_, *this, seclevel_));

    vector<Mpz> w { sk };
    vector<vector<QFI>> X { vector<QFI> { this->h() }, vector<QFI> { R } };
    vector<QFI> Y { pk.get(), Mi };

    dec_share->pf_->prove(w, X, Y);
    return dec_share;
}

unique_ptr<const Mpz> QCLPVSS::rec(vector<unique_ptr<const Share>>& Ais) const {
    // |T| < t + k
    if (Ais.size() < t_ + k_)
        return nullptr;

    return sss_.reconstructSecret(Ais, t_ + k_, q_);
}

bool QCLPVSS::verifyDec(const DecShare& dec_share, const PublicKey& pki,
    const QFI& R, const QFI& B) const {
    QFI Mi(this->power_of_f(dec_share.sh_->y()));
    this->Cl_Delta().nucompinv(Mi, B, Mi);

    vector<vector<QFI>> X { vector<QFI> { this->h() }, vector<QFI> { R } };
    vector<QFI> Y { pki.get(), Mi };

    return dec_share.pf_->verify(X, Y);
}

unique_ptr<vector<unique_ptr<const Share>>> QCLPVSS::createShares(
    const Mpz& s) const {
    return sss_.shareSecret(s, t_, n_, q_);
}

unique_ptr<EncShares> QCLPVSS::EncryptShares(
    vector<unique_ptr<const Share>>& shares,
    const vector<unique_ptr<const PublicKey>>& pks) const {
    unique_ptr<EncShares> enc_sh(new EncShares(n_));

    // encrypt_randomness_bound() = exponent_bound = 2^(distance_-2) times
    // Cl_Delta_.class_number_bound_, where distance is a statistical security
    // parameter
    enc_sh->r_ = randgen_.random_mpz(this->encrypt_randomness_bound());

    // Compute R
    this->power_of_h(enc_sh->R_, enc_sh->r_);

    vector<thread> threads;

    // Compute B_i's
    for (size_t i = 0; i < n_; i++) {

        threads.push_back(thread([&, i]() {
            QFI f, pkr;

            // f^p(a_i)
            f = this->power_of_f(shares[i]->y());
            //(pk_i)^r
            pks[i]->exponentiation(*this, pkr, enc_sh->r_);
            // B_i = (pk_i)^r * f^p(a_i)

            this->Cl_Delta().nucomp(*enc_sh->Bs_->at(i), pkr, f);
        }));
    }

    for (auto& th : threads)
        th.join();

    return enc_sh;
}

void QCLPVSS::computeSHNizk(vector<unique_ptr<const PublicKey>>& pks,
    EncShares& enc_shares) const {
    enc_shares.pf_ = unique_ptr<NizkSH>(new NizkSH(hash_, randgen_, *this,
        seclevel_, n_, n_ - t_ - 2, q_, Vis_));

    enc_shares.pf_->prove(enc_shares.r_, pks, *enc_shares.Bs_, enc_shares.R_);
}

void QCLPVSS::computeSCRAPEcoeffs(vector<Mpz>& vis, const size_t n,
    const size_t offset, const Mpz& q) {

    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            if (i == j)
                continue;

            Mpz sub((signed long)((i + offset) - (j + offset)));
            Mpz::mul(vis[i], vis[i], sub);
        }
        Mpz::mod_inverse(vis[i], vis[i], q);
    }
}