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
    //Forward declaration
    class Nizk_SH;
    
    class Nizk_DLEQ {

        protected:
        Mpz A_;
        HashAlgo & h_;
        Mpz u_, c_;

        public:

        Nizk_DLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const QFI& U, 
            const QFI& R, const QFI& V, const Mpz& r);

        Nizk_DLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const QFI& R, 
            const PublicKey& pki, QFI& Mi, const SecretKey& sk);

        bool verify(const CL_HSMqk &cl_hsm, const QFI& U, const QFI& R, const QFI& V) const;
        bool verify(const CL_HSMqk &cl_hsm, QFI& R, const PublicKey& pki, QFI& Mi) const;
    };

}
#endif