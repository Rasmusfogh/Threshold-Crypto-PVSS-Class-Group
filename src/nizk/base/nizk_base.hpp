#ifndef NIZK_BASE_HPP__
#define NIZK_BASE_HPP__

#include "bicycl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    template <typename Witness, typename... Statement>
    class Nizk_base {

        protected:
            HashAlgo& hash_;
            RandGen& rand_;
            const CL_HSMqk& cl_;

        public:
            Nizk_base(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl)
                : hash_(hash), rand_(rand), cl_(cl) {}

            virtual void prove(const Witness& w, const Statement& ... s) = 0;
            virtual bool verify(const Statement& ... s) const = 0;

            //Random Oracle
            template <typename... Args>
            void initRandomOracle (const Args & ...args) const {
                Mpz seed(hash_(args ...));
                rand_.set_seed(seed);
            }
    
            const Mpz queryRandomOracle (const Mpz& v) const {
                return rand_.random_mpz(v);
            }
    };
}

#endif