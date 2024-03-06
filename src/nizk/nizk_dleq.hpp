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
        const CL_HSMqk& CL_;
        Mpz A_;
        HashAlgo & hash_;
        Mpz u_, c_;

        public:

        Nizk_DLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const QFI& X2, 
            const QFI& Y1, const QFI& Y2, const Mpz& w); //CL contains computation for X1

        bool verify(const QFI& X2, const QFI& Y1, const QFI& Y2) const;
    };

}
#endif