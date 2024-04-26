#ifndef NIZK_SH_BASE_HPP__
#define NIZK_SH_BASE_HPP__

#include "nizk_base.hpp"
#include <bicycl.hpp>
#include <memory>
#include <thread>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace UTILS;

namespace NIZK {
    template <typename Witness, typename... Statement>
    class BaseNizkSH : public BaseNizk<Witness, Statement...> {

      protected:
        Mpz C_;    // Is set from inheriting class
        const SecLevel& seclevel_;
        const Mpz& q_;
        const size_t n_, t_;
        const vector<Mpz>& Vis_;

      public:
        BaseNizkSH(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const SecLevel& seclevel, const Mpz& q, const size_t n,
            const size_t t, const vector<Mpz>& Vis)
            : BaseNizk<Witness, Statement...>(hash, rand, cl), q_(q), n_(n),
              t_(t), Vis_(Vis), seclevel_(seclevel) {}

      protected:
        Mpz evaluatePolynomial(size_t x, const vector<Mpz>& coeffs) const {
            // res = a0
            Mpz res(coeffs[0]), temp;

            // Evaluate polynomial m* as res = a0 + a1*x + a2*x^2 + ... + at*x^t
            for (size_t j = 1; j <= t_; j++) {
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

            vector<future<void>> futures;
            vector<Mpz> wi_prime(n_);
            vector<Mpz> c;
            c.reserve(n_);

            vector<QFI> U_exp(n_);
            vector<QFI> V_exp(n_);

            for (size_t i = 0; i < n_; i++)
                c.emplace_back(this->query_random_oracle(C_));

            for (size_t i = 0; i < n_; i++) {
                futures.emplace_back(this->pool->enqueue([&, i]() {
                    wi_prime[i] = computeWi(i, coeffs);
                    Mpz::addmul(wi_prime[i], c[i], q_);

                    // compute U exponents
                    (*pks[i]).exponentiation(this->cl_, U_exp[i], wi_prime[i]);
                    // compute V exponents
                    this->cl_.Cl_Delta().nupow(V_exp[i], *Bs[i], wi_prime[i]);
                }));
            }

            for (auto& ft : futures)
                ft.get();

            vector<future<void>> UV_futures;

            // compute U
            UV_futures.emplace_back(this->pool->enqueue([&]() {
                for (size_t i = 0; i < n_; i++)
                    this->cl_.Cl_Delta().nucomp(U_ref, U_ref, U_exp[i]);
            }));

            // compute V
            UV_futures.emplace_back(this->pool->enqueue([&]() {
                for (size_t i = 0; i < n_; i++)
                    this->cl_.Cl_Delta().nucomp(V_ref, V_ref, V_exp[i]);
            }));

            for (auto& ft : UV_futures)
                ft.get();
        }

        void computeUVusingWis(QFI& U_ref, QFI& V_ref,
            const vector<unique_ptr<const PublicKey>>& pks,
            const vector<shared_ptr<QFI>>& Bs, vector<Mpz>& wis) const {

            vector<Mpz> c;
            c.reserve(n_);

            for (size_t i = 0; i < n_; i++)
                c.emplace_back(this->query_random_oracle(C_));

            vector<QFI> U_exp(n_);
            vector<QFI> V_exp(n_);

            vector<future<void>> futures;

            for (size_t i = 0; i < n_; i++) {
                futures.emplace_back(this->pool->enqueue([&, i]() {
                    // wi'
                    Mpz::addmul(wis[i], c[i], q_);

                    // compute U exponents
                    (*pks[i]).exponentiation(this->cl_, U_exp[i], wis[i]);
                    // compute V exponents
                    this->cl_.Cl_Delta().nupow(V_exp[i], *Bs[i], wis[i]);
                }));
            }

            for (auto& ft : futures)
                ft.get();

            vector<future<void>> UV_futures;

            // compute U
            UV_futures.emplace_back(this->pool->enqueue([&]() {
                for (size_t i = 0; i < n_; i++)
                    this->cl_.Cl_Delta().nucomp(U_ref, U_ref, U_exp[i]);
            }));

            // compute V
            UV_futures.emplace_back(this->pool->enqueue([&]() {
                for (size_t i = 0; i < n_; i++)
                    this->cl_.Cl_Delta().nucomp(V_ref, V_ref, V_exp[i]);
            }));

            for (auto& ft : UV_futures)
                ft.get();
        }

        void generateCoefficients(vector<Mpz>& coeffs) const {
            // t_ + 1 due to generating a_0 alongside [a_1 ... a_t]
            coeffs.reserve(t_ + 1);

            for (size_t _ = 0; _ <= t_; _++)
                coeffs.emplace_back(this->query_random_oracle(q_));
        }
    };
}    // namespace NIZK

#endif