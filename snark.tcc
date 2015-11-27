#include "gadget.hpp"

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_proof<ppzksnark_ppT> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                   const bit_vector &h1,
                                                   const bit_vector &h2,
                                                   const bit_vector &x,
                                                   const bit_vector &r1,
                                                   const bit_vector &r2
                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(h1, h2, x, r1, r2);

    assert(pb.is_satisfied());

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const bit_vector &h1,
                  const bit_vector &h2,
                  const bit_vector &x
                  // ...
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1, h2, x);

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}