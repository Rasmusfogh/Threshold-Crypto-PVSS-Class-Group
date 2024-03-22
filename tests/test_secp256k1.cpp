#include <chrono>
#include <secp256k1.h>
#include <assert.h>
#include <memory>
#include <secp256k1_wrapper.hpp>

using namespace std;
using namespace std::chrono;
using namespace EC;

int main (int argc, char *argv[])
{
    Secp256k1 uut;
    Mpz e(120000UL);

    Mpz e1 = uut.exponent(e);
    Mpz e2 = uut.exponent(e);


    if(e1 != e2)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}