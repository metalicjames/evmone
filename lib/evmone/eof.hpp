// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>
#include <cstddef>
#include <cstdint>
#include <string>

namespace evmone
{
using bytes_view = std::basic_string_view<uint8_t>;

struct EOF1Header
{
    size_t code_size = 0;
    size_t data_size = 0;

    /// Returns offset of code section start.
    [[nodiscard]] EVMC_EXPORT size_t code_begin() const noexcept;
};

/// Checks if code starts with EOF FORMAT + MAGIC, doesn't validate the format.
[[nodiscard]] EVMC_EXPORT bool is_eof_code(bytes_view code) noexcept;

/// Reads the section sizes assuming that code has valid format.
/// (must be true for all EOF contracts on-chain)
[[nodiscard]] EVMC_EXPORT EOF1Header read_valid_eof1_header(
    bytes_view::const_iterator code) noexcept;

enum class EOFValidationErrror
{
    success,
    starts_with_format,
    invalid_prefix,
    eof_version_mismatch,
    eof_version_unknown,

    incomplete_section_size,
    code_section_missing,
    multiple_code_sections,
    multiple_data_sections,
    unknown_section_id,
    zero_section_size,
    section_headers_not_terminated,
    invalid_section_bodies_size,

    impossible,
};

/// Determines the EOF version of the code by inspecting code's EOF prefix.
/// If the prefix is missing or invalid, 0 is returned meaning legacy code.
[[nodiscard]] uint8_t get_eof_version(bytes_view code) noexcept;

/// Validates whether given code is a valid EOF code according to the rules of given revision.
[[nodiscard]] EVMC_EXPORT EOFValidationErrror validate_eof(
    evmc_revision rev, bytes_view code) noexcept;
}  // namespace evmone
