#ifndef NIZK_DLEQ_HPP__
#define NIZK_DLEQ_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk/nizk_sh.hpp"

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

        Nizk_DLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&, vector<QFI>& Us, 
            const QFI& R, vector<QFI>& Vs, const Mpz& r);

        Nizk_DLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,const QFI& R, 
            const PublicKey& pki, QFI& Mi, const SecretKey& sk);

        bool verify(const CL_HSMqk &cl_hsm, vector<QFI>& Us, QFI& R, vector<QFI>& Vs, Nizk_SH& pf) const;
    };

}
#endif