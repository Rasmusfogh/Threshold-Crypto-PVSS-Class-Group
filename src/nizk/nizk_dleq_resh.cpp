#include "nizk_dleq_resh.hpp"

using namespace NIZK;

NizkDLEQResh::NizkDLEQResh(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : BaseNizkDLEQ(hash, rand, cl, seclevel) {}

void NizkDLEQResh::prove(const tuple<const Mpz&, const SecretKey&>& W,
    const QFI& U, const QFI& R0_, const QFI& B0_, const QFI& V, const QFI& h,
    const PublicKey& pk_, const QFI& R) {}

bool NizkDLEQResh::verify(const QFI& U, const QFI& R0_, const QFI& B0_,
    const QFI& V, const QFI& h, const PublicKey& pk_, const QFI& R) const {}