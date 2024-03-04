#include <bicycl.hpp>
#include <iostream>
#include <chrono>
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

const int K = 10000;
const int N = K*3;

int main (int argc, char *argv[])
{
    Mpz seed, temp;
    RandGen randgen;
    vector<Mpz> coefficients(K);
    auto T = system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());

    randgen.set_seed (seed);

    Mpz q(randgen.random_prime(129));

    auto start = high_resolution_clock::now();

    /** TEST - What is most expensive. Call randgen.random_mpz(q) K times total in time complexity O(K+N*K)
     *  OR call randgen.random_mpz(q) N*K times in time complexity  O(N*k)
    */

    //Generate poly
    for (size_t i = 0; i < K; i++)
        coefficients[i] = randgen.random_mpz(q); 

    //Eval poly
    for(size_t i = 0; i < N; i++)
    {
        temp = coefficients[0];

        for(size_t j = 1; j < K; j++)
        {
        Mpz::pow_mod(temp, Mpz(i), Mpz(j), q);
        Mpz::mul(temp, temp, coefficients[j]);
        Mpz::add(temp, temp, temp);
        }
        Mpz::mod(temp, temp, q);
    }

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << duration.count() << endl;

    auto start2 = high_resolution_clock::now();

    for(size_t i = 0; i < N; i++)
    {
        randgen.set_seed (seed);
        temp = randgen.random_mpz(q);

        for(size_t j = 1; j < K; j++)
        {
        Mpz::pow_mod(temp, Mpz(i), Mpz(j), q);
        Mpz::mul(temp, temp, randgen.random_mpz(q));
        Mpz::add(temp, temp, temp);
        }
        Mpz::mod(temp, temp, q);
    }

    auto stop2 = high_resolution_clock::now();
    auto duration2 = duration_cast<microseconds>(stop2 - start2);
    cout << duration2.count() << endl;

    return EXIT_SUCCESS;
}