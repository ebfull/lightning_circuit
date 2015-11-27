#include <stdlib.h>
#include <iostream>

#include "snark.hpp"

using namespace libsnark;
using namespace std;

int main()
{
    default_r1cs_ppzksnark_pp::init_public_params();
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    std::vector<bool> h1(256, false);

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, h1);

    assert(verify_proof(keypair.vk, proof, h1));
}