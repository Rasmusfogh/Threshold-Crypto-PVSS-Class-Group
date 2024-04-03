#ifndef NIZK_SH_BASE_HPP__
#define NIZK_SH_BASE_HPP__

#include "bicycl.hpp"
#include "utils/qclpvss_utils.hpp"
#include <memory>
#include <nizk_base.hpp>

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK {
    template <typename Witness, typename... Statement>
    class BaseNizkSH : public BaseNizk<Witness, Statement...> {

      protected:
        Mpz C_;    // Is set from inheriting class
        const SecLevel& seclevel_;
        const Mpz& q_;
        const size_t n_, t_, degree_;
        const vector<Mpz>& Vis_;

      public:
        BaseNizkSH(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const SecLevel& seclevel, const Mpz& q, const size_t n,
            const size_t t, const vector<Mpz>& Vis)
            : BaseNizk<Witness, Statement...>(hash, rand, cl), q_(q), n_(n),
              t_(t), degree_(n - t - 1 - 1), Vis_(Vis), seclevel_(seclevel) {}

      protected:
        Mpz evaluatePolynomial(size_t x, const vector<Mpz>& coeffs) const {
            Mpz res(coeffs[0]), temp;

            // Evaluate polynomial m*
            for (size_t j = 1; j < degree_; j++) {
                Mpz::pow_mod(temp, Mpz(x), Mpz(j), q_);
                Mpz::addmul(res, temp, coeffs[j]);
            }
            Mpz::mod(res, res, q_);
            return res;
        }

        Mpz computeWi(size_t i, const vector<Mpz>& coeffs) const {

            Mpz res = evaluatePolynomial(i + 1, coeffs);

            Mpz::mul(res, res, Vis_[i]);
            Mpz::mod(res, res, q_);
            return res;
        }

        void computeUV(QFI& U_ref, QFI& V_ref,
            const vector<unique_ptr<const PublicKey>>& pks,
            const vector<shared_ptr<QFI>>& Bs,
            const vector<Mpz>& coeffs) const {
            QFI exp;
            Mpz temp;

            for (size_t i = 0; i < n_; i++) {
                temp = computeWi(i, coeffs);

                // compute wi' = wi
                Mpz ci(this->query_random_oracle(C_));
                Mpz::addmul(temp, ci, q_);

                // compute U
                (*pks[i]).exponentiation(this->cl_, exp, temp);
                this->cl_.Cl_Delta().nucomp(U_ref, U_ref, exp);

                // compute V
                this->cl_.Cl_Delta().nupow(exp, *Bs[i], temp);
                this->cl_.Cl_Delta().nucomp(V_ref, V_ref, exp);
            }
        }

        void computeUVusingWis(QFI& U_ref, QFI& V_ref,
            const vector<unique_ptr<const PublicKey>>& pks,
            const vector<shared_ptr<QFI>>& Bs, const vector<Mpz>& wis) const {
            QFI exp;
            Mpz temp;

            for (size_t i = 0; i < n_; i++) {
                // compute wi' = wi
                Mpz ci(this->query_random_oracle(C_));
                Mpz::mul(temp, ci, q_);
                Mpz::add(temp, wis[i], temp);

                // compute U
                (*pks[i]).exponentiation(this->cl_, exp, temp);
                this->cl_.Cl_Delta().nucomp(U_ref, U_ref, exp);

                // compute V
                this->cl_.Cl_Delta().nupow(exp, *Bs[i], temp);
                this->cl_.Cl_Delta().nucomp(V_ref, V_ref, exp);
            }
        }

        void generateCoefficients(vector<Mpz>& coeffs, size_t t) const {
            for (size_t _ = 0; _ < t; _++)
                coeffs.emplace_back(this->query_random_oracle(q_));
        }
    };
}    // namespace NIZK

#endif