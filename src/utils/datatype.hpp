#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include "nizk_dl.hpp"
#include "nizk_sh.hpp"
#include "nizk_sh_ext.hpp"
#include "sss.hpp"
#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;

namespace DATATYPE {
    class EncShares {
      public:
        Mpz r;
        QFI R;
        unique_ptr<vector<shared_ptr<QFI>>> Bs;
        unique_ptr<NizkSH> pf;

        EncShares(size_t n);
    };

    class EncSharesExt {
      public:
        Mpz r_;
        QFI R_;
        unique_ptr<vector<shared_ptr<QFI>>> Bs_;
        unique_ptr<vector<shared_ptr<ECPoint>>> Ds_;
        unique_ptr<NizkExtSH> pf_;

        EncSharesExt(size_t n);
        EncSharesExt(size_t, EncShares& enc_sh);
    };

    class DecShare {
      public:
        unique_ptr<const Share> sh;
        unique_ptr<NizkDLEQ> pf;

        DecShare();
    };

    class KeyPair {
      public:
        unique_ptr<const PublicKey> pk_;
        unique_ptr<const SecretKey> sk_;
        unique_ptr<NizkDL> pf_;

        KeyPair();
    };

}    // namespace DATATYPE

#endif