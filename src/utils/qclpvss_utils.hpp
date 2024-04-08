#ifndef QCLPVSS_UTILS_HPP__
#define QCLPVSS_UTILS_HPP__

#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace std;

namespace UTILS {

    class SecretKey : public Mpz {
      public:
        /* constructors */
        SecretKey(const CL_HSMqk&, RandGen&);
    };

    class PublicKey {
      protected:
        /** The actual public key: a QFI */
        QFI pk_;
        /** Precomputation data: a positive integer */
        size_t d_;
        size_t e_;
        /** Precomputation data: pk_^(2^e_), pk_^(2^d_), pk_^(d_+e_) */
        QFI pk_e_precomp_;
        QFI pk_d_precomp_;
        QFI pk_de_precomp_;

      public:
        /* constructors */
        PublicKey(const CL_HSMqk&, const SecretKey&);

        /* getters */
        const QFI& get() const;

        /* */
        void exponentiation(const CL_HSMqk&, QFI&, const Mpz&) const;
    };
}    // namespace UTILS

#endif