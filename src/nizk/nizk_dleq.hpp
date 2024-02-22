#ifndef NIZK_DLEQ_HPP__
#define NIZK_DLEQ_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

namespace NIZK
{
    class Nizk_DLEQ {

        protected:
        Mpz A_;
        HashAlgo & h_;
        std::vector<Mpz> b_, u_;

        public:

        Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
            const SecLevel & seclevel, const PublicKey &x, const SecretKey &w);

        bool Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const;
    };

}
#endif