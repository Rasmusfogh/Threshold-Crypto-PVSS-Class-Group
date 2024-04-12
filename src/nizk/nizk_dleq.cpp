#include "nizk_dleq.hpp"
using namespace NIZK;

NizkDLEQ::NizkDLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : NizkLinCL(hash, randgen, cl, seclevel) {}
