// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "instructions_traits.hpp"

#include <array>
#include <cassert>
#include <limits>
#include <vector>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC = 0x00;
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
constexpr uint8_t MAX_SECTION = DATA_SECTION;

using EOFSectionHeaders = std::array<size_t, MAX_SECTION + 1>;

std::pair<EOFSectionHeaders, EOFValidationErrror> validate_eof_headers(bytes_view code) noexcept
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    EOFSectionHeaders section_headers{};
    const auto code_end = code.end();
    auto it = code.begin() + sizeof(MAGIC) + 2;  // FORMAT + MAGIC + VERSION
    while (it != code_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it;
            switch (section_id)
            {
            case TERMINATOR:
                if (section_headers[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_headers[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                if (section_headers[DATA_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (section_headers[CODE_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_code_sections};
                state = State::section_size;
                break;
            default:
                return {{}, EOFValidationErrror::unknown_section_id};
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it;
            ++it;
            if (it == code_end)
                return {{}, EOFValidationErrror::incomplete_section_size};
            const auto size_lo = *it;
            const auto section_size = static_cast<size_t>(size_hi << 8) | size_lo;
            if (section_size == 0)
                return {{}, EOFValidationErrror::zero_section_size};

            section_headers[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return {{}, EOFValidationErrror::impossible};
        }

        ++it;
    }

    if (state != State::terminated)
        return {{}, EOFValidationErrror::section_headers_not_terminated};

    const auto section_bodies_size = section_headers[CODE_SECTION] + section_headers[DATA_SECTION];
    const auto remaining_code_size = static_cast<size_t>(code_end - it);
    if (section_bodies_size != remaining_code_size)
        return {{}, EOFValidationErrror::invalid_section_bodies_size};

    return {section_headers, EOFValidationErrror::success};
}

EOFValidationErrror validate_instructions(evmc_revision rev, bytes_view code) noexcept
{
    assert(code.size() > 0);  // guaranteed by EOF headers validation

    size_t i = 0;
    uint8_t op = 0;
    while (i < code.size())
    {
        op = code[i];
        const auto& since = instr::traits[op].since;
        if (!since.has_value() || *since > rev)
            return EOFValidationErrror::undefined_instruction;

        i += instr::traits[op].immediate_size;
        ++i;
    }

    if (!instr::traits[op].is_terminating)
        return EOFValidationErrror::missing_terminating_instruction;

    return EOFValidationErrror::success;
}

bool validate_rjump_destinations(const EOF1Header& header, bytes_view::const_iterator code) noexcept
{
    // Collect relative jump destinations and immediate locations
    std::vector<size_t> rjumpdests;
    std::vector<bool> immediate_map(header.code_end());
    for (auto i = header.code_begin(); i < header.code_end(); ++i)
    {
        const auto op = code[i];

        if (op == OP_RJUMP || op == OP_RJUMPI)
        {
            const auto offset_hi = code[i + 1];
            const auto offset_lo = code[i + 2];
            const auto offset = static_cast<int16_t>((offset_hi << 8) + offset_lo);
            const auto jumpdest = static_cast<int32_t>(i) + 3 + offset;
            if (jumpdest < static_cast<int32_t>(header.code_begin()) ||
                jumpdest >= static_cast<int32_t>(header.code_end()))
                return false;
            rjumpdests.push_back(static_cast<size_t>(jumpdest));
        }

        const auto imm_size = instr::traits[op].immediate_size;
        std::fill_n(immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, imm_size, true);
        i += imm_size;
    }

    // Check relative jump destinations against immediate locations.
    for (const auto rjumpdest : rjumpdests)
        if (immediate_map[rjumpdest])
            return false;

    return true;
}

std::pair<EOF1Header, EOFValidationErrror> validate_eof1(
    evmc_revision rev, bytes_view code) noexcept
{
    const auto [section_headers, error_header] = validate_eof_headers(code);
    if (error_header != EOFValidationErrror::success)
        return {{}, error_header};

    EOF1Header header{section_headers[CODE_SECTION], section_headers[DATA_SECTION]};

    const auto error_instr =
        validate_instructions(rev, {&code[header.code_begin()], header.code_size});
    if (error_instr != EOFValidationErrror::success)
        return {{}, error_instr};

    if (!validate_rjump_destinations(header, code.begin()))
        return {{}, EOFValidationErrror::invalid_rjump_destination};

    return {header, EOFValidationErrror::success};
}
}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return 7;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + TERMINATOR
    else
        return 10;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + SECTION_ID + SIZE + TERMINATOR
}

size_t EOF1Header::code_end() const noexcept
{
    return code_begin() + code_size;
}

bool is_eof_code(bytes_view code) noexcept
{
    return code.size() > 1 && code[0] == FORMAT && code[1] == MAGIC;
}

EOF1Header read_valid_eof1_header(bytes_view::const_iterator code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = 4;  // FORMAT + MAGIC + VERSION + CODE_SECTION_ID
    header.code_size = (size_t{code[code_size_offset]} << 8) | code[code_size_offset + 1];
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = (size_t{code[data_size_offset]} << 8) | code[data_size_offset + 1];
    }
    return header;
}

uint8_t get_eof_version(bytes_view code) noexcept
{
    return (code.size() >= 3 && code[0] == FORMAT && code[1] == MAGIC) ? code[2] : 0;
}

EOFValidationErrror validate_eof(evmc_revision rev, bytes_view code) noexcept
{
    if (!is_eof_code(code))
        return EOFValidationErrror::invalid_prefix;

    const auto version = get_eof_version(code);

    if (version == 1)
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationErrror::eof_version_unknown;
        return validate_eof1(rev, code).second;
    }
    else
        return EOFValidationErrror::eof_version_unknown;
}


}  // namespace evmone
