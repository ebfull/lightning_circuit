#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"

using namespace libsnark;

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair();

template<typename ppzksnark_ppT>
r1cs_ppzksnark_proof<ppzksnark_ppT> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                   const bit_vector &h1,
                                                   const bit_vector &h2,
                                                   const bit_vector &x,
                                                   const bit_vector &r1,
                                                   const bit_vector &r2
                                                   );

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const bit_vector &h1,
                  const bit_vector &h2,
                  const bit_vector &x
                  // ...
                 );

#include "snark.tcc"
