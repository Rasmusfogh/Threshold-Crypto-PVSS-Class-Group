#ifndef NIZK_DLEQ_HPP__
#define NIZK_DLEQ_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    class Nizk_DLEQ {

        protected:
        Mpz A_;
        HashAlgo & h_;
        std::vector<Mpz> u_, c_;

        public:

        Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
            const SecLevel & seclevel, vector<QFI>& Us, const QFI& R, vector<QFI>& Vs, const Mpz& r);

        bool verify(const CL_HSMqk &cl_hsm, vector<QFI>& Us, QFI& R, vector<QFI>& Vs, Mpz& r) const;
    };

}
#endif