#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include <bicycl.hpp>
#include <memory>
#include <nizk_sh.hpp>
#include <nizk_sh_ext.hpp>
#include <sss.hpp>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;

namespace DATATYPE
{
    class EncShares
    {
        public:
            Mpz r;
            QFI R;
            vector<QFI> Bs;
            unique_ptr<Nizk_SH> pf;

            EncShares(size_t n);
    };

    class EncSharesExt
    {
         public:
            Mpz r;
            QFI R;
            vector<QFI> Bs;
            vector<Mpz> Ds;
            unique_ptr<Nizk_SH_ext> pf;

            EncSharesExt(size_t n);
    };

    class DecShare
    {
        public:
            unique_ptr<const Share> sh;
            unique_ptr<Nizk_DLEQ> pf;

            DecShare();
    };
}

#endif