#include "nizk_linear_cl.hpp"

using namespace NIZK;

NizkLinCL::NizkLinCL(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : BaseNizkLinCL(hash, rand, cl, seclevel) {}

void NizkLinCL::prove(const vector<Mpz>& w, const vector<vector<QFI>>& X,
    const vector<QFI>& Y) {

    size_t n = X.size();
    size_t m = w.size();

    vector<Mpz> r;
    r.reserve(m);

    for (size_t i = 0; i < m; i++)
        r.emplace_back(rand_.random_mpz(A_));

    vector<QFI> T(n);
    QFI temp;

    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < m; j++) {
            cl_.Cl_Delta().nupow(temp, X[i][j], r[j]);
            cl_.Cl_Delta().nucomp(T[i], T[i], temp);
        }
    }

    init_random_oracle(X, Y, T);
    c_ = query_random_oracle(C_);

    u_.reserve(m);

    for (size_t i = 0; i < m; i++) {
        u_.emplace_back(r[i]);
        Mpz::addmul(u_[i], c_, w[i]);
    }
}

bool NizkLinCL::verify(const vector<vector<QFI>>& X,
    const vector<QFI>& Y) const {

    size_t n = X.size();
    size_t m = u_.size();

    for (size_t i = 0; i < m; i++)
        if (u_[i] > SCA_)
            return false;

    vector<QFI> T(n);
    QFI temp;

    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < m; j++) {
            cl_.Cl_Delta().nupow(temp, X[i][j], u_[j]);
            cl_.Cl_Delta().nucomp(T[i], T[i], temp);
        }

        cl_.Cl_Delta().nupow(temp, Y[i], c_);
        cl_.Cl_Delta().nucompinv(T[i], T[i], temp);
    }

    init_random_oracle(X, Y, T);
    return c_ == query_random_oracle(C_);
}