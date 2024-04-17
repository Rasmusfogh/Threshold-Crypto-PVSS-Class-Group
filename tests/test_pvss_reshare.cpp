#include "pvss_reshare.hpp"
#include <chrono>
#include <memory>

using namespace Application;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

int main(int argc, char* argv[]) {

    Mpz seed;
    SecLevel seclevel(128);
    RandGen randgen;
    HashAlgo H(seclevel);

    size_t n(20UL);
    size_t t(10UL);

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    Mpz q(randgen.random_prime(256));

    PVSS_Reshare pvss_reshare(seclevel, H, randgen, q, n, t, n, t);

    auto enc_sh_resh = pvss_reshare.reshare(*pvss_reshare.enc_shares);

    if (!pvss_reshare.verifyReshare(*enc_sh_resh, *pvss_reshare.enc_shares))
        return EXIT_FAILURE;

    auto enc_shares = pvss_reshare.distReshare(*enc_sh_resh);

    if (!pvss_reshare.verifyDistReshare(*enc_shares))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}