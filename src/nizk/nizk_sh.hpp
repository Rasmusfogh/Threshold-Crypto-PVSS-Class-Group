#ifndef NIZK_SH_HPP__
#define NIZK_SH_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    class Nizk_SH {

        protected:
        Mpz A_;
        HashAlgo & h_;

        public:

        Nizk_SH(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&, const PublicKey&, 
            const QFI& B, const QFI& R, const size_t n, const size_t t, const Mpz& q, const size_t ci);

        bool Verify(const CL_HSMqk&, const PublicKey&) const;

        private:
        void RandomOracle(RandGen&, const PublicKey&, const QFI& R, 
            const QFI& B, size_t t, const Mpz& q, vector<Mpz>& coefficients) const;
    };
}

#endif