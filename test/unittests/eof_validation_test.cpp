// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

namespace
{
inline EOFValidationErrror validate_eof(
    std::string_view code_hex, evmc_revision rev = EVMC_SHANGHAI) noexcept
{
    return ::validate_eof(rev, from_hex(code_hex));
}
}  // namespace

TEST(eof_validation, validate_empty_code)
{
    EXPECT_EQ(validate_eof(""), EOFValidationErrror::invalid_prefix);
}

TEST(eof_validation, validate_EOF_prefix)
{
    EXPECT_EQ(validate_eof("00"), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof("FE"), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof("EF"), EOFValidationErrror::invalid_prefix);

    EXPECT_EQ(validate_eof("EF0101"), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof("EFEF01"), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof("EFFF01"), EOFValidationErrror::invalid_prefix);

    EXPECT_EQ(validate_eof("EF00"), EOFValidationErrror::eof_version_unknown);

    EXPECT_EQ(validate_eof("EF0001"), EOFValidationErrror::section_headers_not_terminated);

    // valid except for magic
    EXPECT_EQ(validate_eof("EFFF01 010003 020004 00 600000 AABBCCDD"),
        EOFValidationErrror::invalid_prefix);
}

TEST(eof_validation, validate_EOF_version)
{
    EXPECT_EQ(validate_eof("EF0002"), EOFValidationErrror::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF"), EOFValidationErrror::eof_version_unknown);

    // valid except version
    EXPECT_EQ(validate_eof("EF00000 10003 020004 00 600000 AABBCCDD"),
        EOFValidationErrror::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00020 10003 020004 00 600000 AABBCCDD"),
        EOFValidationErrror::eof_version_unknown);
    EXPECT_EQ(validate_eof("EF00FF0 10003 020004 00 600000 AABBCCDD"),
        EOFValidationErrror::eof_version_unknown);
}

TEST(eof_validation, valid_EOF1_code_pre_shanghai)
{
    EXPECT_EQ(
        validate_eof("EF0001 010001 00 FE", EVMC_PARIS), EOFValidationErrror::eof_version_unknown);
}

TEST(eof_validation, minimal_valid_EOF1_code)
{
    EXPECT_EQ(validate_eof("EF0001 010001 00 FE"), EOFValidationErrror::success);
}

TEST(eof_validation, minimal_valid_EOF1_code_with_data)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020001 00 FE DA"), EOFValidationErrror::success);
}

TEST(eof_validation, EOF1_code_section_missing)
{
    EXPECT_EQ(validate_eof("EF0001 00"), EOFValidationErrror::code_section_missing);
    EXPECT_EQ(validate_eof("EF0001 020001 DA"), EOFValidationErrror::code_section_missing);
}

TEST(eof_validation, EOF1_code_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010000 00"), EOFValidationErrror::zero_section_size);
    EXPECT_EQ(validate_eof("EF0001 010000 020001 00 DA"), EOFValidationErrror::zero_section_size);
}

TEST(eof_validation, EOF1_data_section_0_size)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020000 00 FE"), EOFValidationErrror::zero_section_size);
}

TEST(eof_validation, EOF1_multiple_code_sections)
{
    EXPECT_EQ(
        validate_eof("EF0001 010001 010001 00 FE FE"), EOFValidationErrror::multiple_code_sections);
    EXPECT_EQ(validate_eof("EF0001 010001 010001 020001 00 FE FE DA"),
        EOFValidationErrror::multiple_code_sections);
}

TEST(eof_validation, EOF1_data_section_before_code_section)
{
    EXPECT_EQ(
        validate_eof("EF0001 020001 010001 00 AA FE"), EOFValidationErrror::code_section_missing);
}

TEST(eof_validation, EOF1_multiple_data_sections)
{
    EXPECT_EQ(validate_eof("EF0001 010001 020001 020001 00 FE DA DA"),
        EOFValidationErrror::multiple_data_sections);
}

TEST(eof_validation, EOF1_unknown_section)
{
    EXPECT_EQ(validate_eof("EF0001 030001 00 FE"), EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 FF0001 00 FE"), EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(
        validate_eof("EF0001 010001 030001 00 FE 00"), EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(
        validate_eof("EF0001 010001 FF0001 00 FE 00"), EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 030001 00 FE AA 00"),
        EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 FF0001 00 FE AA 00"),
        EOFValidationErrror::unknown_section_id);
}

TEST(eof_validation, EOF1_incomplete_section_size)
{
    EXPECT_EQ(validate_eof("EF0001 0100"), EOFValidationErrror::incomplete_section_size);
    EXPECT_EQ(validate_eof("EF0001 010001 0200"), EOFValidationErrror::incomplete_section_size);
}

TEST(eof_validation, EOF1_header_not_terminated)
{
    EXPECT_EQ(validate_eof("EF0001 01"), EOFValidationErrror::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001"), EOFValidationErrror::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001 FE"), EOFValidationErrror::unknown_section_id);
    EXPECT_EQ(
        validate_eof("EF0001 010001 02"), EOFValidationErrror::section_headers_not_terminated);
    EXPECT_EQ(
        validate_eof("EF0001 010001 020001"), EOFValidationErrror::section_headers_not_terminated);
    EXPECT_EQ(validate_eof("EF0001 010001 020001 FE AA"), EOFValidationErrror::unknown_section_id);
}

TEST(eof_validation, EOF1_truncated_section)
{
    EXPECT_EQ(validate_eof("EF0001 010002 00"), EOFValidationErrror::invalid_section_bodies_size);
    EXPECT_EQ(
        validate_eof("EF0001 010002 00 FE"), EOFValidationErrror::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE"),
        EOFValidationErrror::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE AA"),
        EOFValidationErrror::invalid_section_bodies_size);
}

TEST(eof_validation, EOF1_trailing_bytes)
{
    EXPECT_EQ(validate_eof("EF0001 010001 00 FE DEADBEEF"),
        EOFValidationErrror::invalid_section_bodies_size);
    EXPECT_EQ(validate_eof("EF0001 010001 020002 00 FE AABB DEADBEEF"),
        EOFValidationErrror::invalid_section_bodies_size);
}
