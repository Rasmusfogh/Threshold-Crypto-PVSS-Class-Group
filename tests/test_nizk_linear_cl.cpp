#include "nizk_linear_cl.hpp"
#include "qclpvss.hpp"

using namespace QCLPVSS_;
using namespace std;

int main(int argc, char* argv[]) {

    SecLevel seclevel(128);
    RandGen randgen;
    Mpz q(randgen.random_prime(256));
    HashAlgo H(seclevel);

    size_t n = 10;
    size_t t = 5;

    // Make qclpvss base class protected again
    QCLPVSS pvss(seclevel, H, randgen, q, 2, n, t);

    NizkLinCL uut(H, randgen, pvss, seclevel);

    unique_ptr<const SecretKey> sk1 = pvss.keyGen(randgen);
    unique_ptr<const PublicKey> pk1 = pvss.keyGen(*sk1);

    unique_ptr<const SecretKey> sk2 = pvss.keyGen(randgen);
    unique_ptr<const PublicKey> pk2 = pvss.keyGen(*sk2);

    QFI pk12;
    pvss.Cl_Delta().nucomp(pk12, pk1->get(), pk2->get());

    vector<Mpz> w { *sk1, *sk2 };

    vector<vector<QFI>> X { vector<QFI> { pvss.h(), QFI() },
        vector<QFI> { QFI(), pvss.h() }, vector<QFI> { pvss.h(), pvss.h() } };

    vector<QFI> Y { pk1->get(), pk2->get(), pk12 };

    uut.prove(w, X, Y);

    cout << uut.verify(X, Y) << endl;

    return 1;
}