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
    class Nizk_SH_base : public Nizk_base<Witness, Statement...> {

      protected:
        const Mpz& q_;
        const size_t n_, t_, degree_;
        const vector<Mpz>& Vis_;

      public:
        Nizk_SH_base(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const Mpz& q, const size_t n, const size_t t,
            const vector<Mpz>& Vis)
            : Nizk_base<Witness, Statement...>(hash, rand, cl), q_(q), n_(n),
              t_(t), degree_(n - t - 1 - 1), Vis_(Vis) {}

      protected:
        void computeUV(QFI& U_ref, QFI& V_ref,
            const vector<unique_ptr<const PublicKey>>& pks,
            const vector<unique_ptr<QFI>>& Bs,
            const vector<Mpz>& coeffs) const {
            QFI exp;
            Mpz temp, poly_eval;

            for (size_t i = 0; i < n_; i++) {
                poly_eval = coeffs[0];    // coefficient 0 aka secret

                // Evaluate polynomial m*
                for (size_t j = 1; j < degree_; j++) {
                    Mpz::pow_mod(temp, Mpz(i + 1), Mpz(j), q_);
                    Mpz::addmul(poly_eval, temp,
                        coeffs[j]);    // remaining coefficients
                }

                Mpz::mod(poly_eval, poly_eval, q_);

                // compute wi = temp
                Mpz::mul(temp, poly_eval, Vis_[i]);
                Mpz::mod(temp, temp, q_);

                // compute wi' = temp
                Mpz ci(this->queryRandomOracle(q_));    // ci using RNG
                Mpz::addmul(temp, ci, q_);

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
                coeffs.emplace_back(this->queryRandomOracle(q_));
        }
    };
}    // namespace NIZK

#endif