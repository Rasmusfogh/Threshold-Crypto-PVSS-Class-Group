#ifndef NIZK_BASE_HPP__
#define NIZK_BASE_HPP__

#include "qclpvss_utils.hpp"
#include "threadpool.hpp"
#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace UTILS;

namespace NIZK {
    template <typename Witness, typename... Statement>
    class BaseNizk {

      protected:
        HashAlgo& hash_;
        RandGen& rand_;
        const CL_HSMqk& cl_;

        ThreadPool* pool;

      public:
        BaseNizk(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl)
            : hash_(hash), rand_(rand), cl_(cl),
              pool(ThreadPool::GetInstance()) {}

        virtual void prove(const Witness& w, const Statement&... s) = 0;
        virtual bool verify(const Statement&... s) const = 0;

      protected:
        // Random Oracle
        template <typename... Args>
        void init_random_oracle(const Args&... args) const {
            Mpz seed(hash_(args...));
            rand_.set_seed(seed);
        }

        const Mpz query_random_oracle(const Mpz& v) const {
            return rand_.random_mpz(v);
        }
    };
}    // namespace NIZK

#endif