template<typename FieldT>
l_gadget<FieldT>::l_gadget(protoboard<FieldT> &pb) :
        gadget<FieldT>(pb, FMT(annotation_prefix, " l_gadget"))
{
    // Allocate space for the verifier input.
    const size_t input_size_in_bits = sha256_digest_len * 3;
    {
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
        this->pb.set_input_sizes(input_size_in_field_elements);
    }

    padding_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "padding"));
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

    // IV for SHA256
    pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

    // Initialize the block gadget for r1's hash
    h_r1_block.reset(new block_variable<FieldT>(pb, {
        r1_var->bits,
        padding_var->bits
    }, "h_r1_block"));

    // Initialize the hash gadget for r1's hash
    h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                              IV,
                                                              h_r1_block->bits,
                                                              *h1_var,
                                                              "h_r1"));

    // Initialize the block gadget for r2's hash
    h_r2_block.reset(new block_variable<FieldT>(pb, {
        r2_var->bits,
        padding_var->bits
    }, "h_r2_block"));

    // Initialize the hash gadget for r2's hash
    h_r2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                              IV,
                                                              h_r2_block->bits,
                                                              *h2_var,
                                                              "h_r2"));
}

template<typename FieldT>
void l_gadget<FieldT>::generate_r1cs_constraints()
{
    // Multipacking constraints (for input validation)
    unpack_inputs->generate_r1cs_constraints(true);

    // Ensure bitness of the digests
    padding_var->generate_r1cs_constraints();
    h1_var->generate_r1cs_constraints();
    h2_var->generate_r1cs_constraints();
    x_var->generate_r1cs_constraints();
    r1_var->generate_r1cs_constraints();
    r2_var->generate_r1cs_constraints();

    for (unsigned int i = 0; i < sha256_digest_len; i++) {
        // SHA256 has a length padding at the end, which
        // is a variable in our protoboard. We need to
        // constrain the padding so a malicious user
        // cannot demonstrate a witness of a different
        // padding.
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                { padding_var->bits[i] },
                { 1 },
                { sha256_padding[i] ? 1 : 0 }),
            FMT(this->annotation_prefix, " constrain_padding_%zu", i));

        // This is the constraint that R1 = R2 ^ X.
        // (2*b)*c = b+c - a
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                { r2_var->bits[i] * 2 }, // 2*b
                { x_var->bits[i] }, // c
                { r2_var->bits[i], x_var->bits[i], r1_var->bits[i] * (-1) }), // b+c - a
            FMT(this->annotation_prefix, " xor_%zu", i));
    }

    // These are the constraints to ensure the hashes validate.
    h_r1->generate_r1cs_constraints();
    h_r2->generate_r1cs_constraints();
}

template<typename FieldT>
void l_gadget<FieldT>::generate_r1cs_witness(const bit_vector &h1,
                                                   const bit_vector &h2,
                                                   const bit_vector &x,
                                                   const bit_vector &r1,
                                                   const bit_vector &r2
                                                  )
{
    // Fill our digests with our witnessed data
    h1_var->bits.fill_with_bits(this->pb, h1);
    h2_var->bits.fill_with_bits(this->pb, h2);
    x_var->bits.fill_with_bits(this->pb, x);
    r1_var->bits.fill_with_bits(this->pb, r1);
    r2_var->bits.fill_with_bits(this->pb, r2);

    // Fill the padding
    for (unsigned int i = 0; i < sha256_digest_len; i++) {
        this->pb.val(padding_var->bits[i]) = sha256_padding[i] ? 1 : 0;
    }

    // Generate witnesses as necessary in our other gadgets
    h_r1->generate_r1cs_witness();
    h_r2->generate_r1cs_witness();
    unpack_inputs->generate_r1cs_witness_from_bits();
}

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                             const bit_vector &x
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
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