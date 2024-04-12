#ifndef NIZK_DLEQ_HPP__
#define NIZK_DLEQ_HPP__

#include "nizk_linear_cl.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK {
    class NizkDLEQ : public NizkLinCL {

      public:
        NizkDLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);
    };
}    // namespace NIZK
#endif