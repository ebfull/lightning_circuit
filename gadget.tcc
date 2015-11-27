template<typename FieldT>
example_gadget<FieldT>::example_gadget(protoboard<FieldT> &pb) :
        gadget<FieldT>(pb, FMT(annotation_prefix, " example_gadget"))
{
    // Allocate space for the verifier input.
    const size_t input_size_in_bits = sha256_digest_len * 3;
    {
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
        this->pb.set_input_sizes(input_size_in_field_elements);
    }

    h1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h1"));
    h2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h2"));
    x_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "x"));
    r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r1"));
    r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r2"));
    input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
    input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
    input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());

    // Multipacking
    assert(input_as_bits.size() == input_size_in_bits);
    unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

    pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

    h_r1_block.reset(new block_variable<FieldT>(pb, {
        r1_var->bits,
        r1_var->bits
    }, "h_r1_block"));

    h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                              IV,
                                                              h_r1_block->bits,
                                                              *h1_var,
                                                              "h_r1"));

    h_r2_block.reset(new block_variable<FieldT>(pb, {
        r2_var->bits,
        r2_var->bits
    }, "h_r2_block"));

    h_r2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                              IV,
                                                              h_r2_block->bits,
                                                              *h2_var,
                                                              "h_r2"));
}

template<typename FieldT>
void example_gadget<FieldT>::generate_r1cs_constraints()
{
    unpack_inputs->generate_r1cs_constraints(true);
    h1_var->generate_r1cs_constraints();
    h2_var->generate_r1cs_constraints();
    x_var->generate_r1cs_constraints();
    r1_var->generate_r1cs_constraints();
    r2_var->generate_r1cs_constraints();

    h_r1->generate_r1cs_constraints();
    h_r2->generate_r1cs_constraints();
}

template<typename FieldT>
void example_gadget<FieldT>::generate_r1cs_witness(const bit_vector &h1,
                                                   const bit_vector &h2,
                                                   const bit_vector &x,
                                                   const bit_vector &r1,
                                                   const bit_vector &r2
                                                  )
{
    h1_var->bits.fill_with_bits(this->pb, h1);
    h2_var->bits.fill_with_bits(this->pb, h2);
    x_var->bits.fill_with_bits(this->pb, x);
    r1_var->bits.fill_with_bits(this->pb, r1);
    r2_var->bits.fill_with_bits(this->pb, r2);

    h_r1->generate_r1cs_witness();
    h_r2->generate_r1cs_witness();

    unpack_inputs->generate_r1cs_witness_from_bits();
}

template<typename FieldT>
r1cs_primary_input<FieldT> example_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                             const bit_vector &x
                                            )
{
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);
    assert(x.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    input_as_bits.insert(input_as_bits.end(), x.begin(), x.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}