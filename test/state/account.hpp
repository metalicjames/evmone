// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>

namespace evmone::state
{
struct Account
{
    /// The account nonce.
    int nonce = 0;

    /// The account code.
    evmc::bytes code;

    /// The code hash. Can be a value not related to the actual code.
    evmc::bytes32 codehash;

    /// The account balance.
    evmc::uint256be balance;

    /// The account storage map.
    std::unordered_map<evmc::bytes32, evmc::storage_value> storage;

    /// Helper method for setting balance by numeric type.
    void set_balance(uint64_t x) noexcept
    {
        balance = evmc::uint256be{};
        for (std::size_t i = 0; i < sizeof(x); ++i)
            balance.bytes[sizeof(balance) - 1 - i] = static_cast<uint8_t>(x >> (8 * i));
    }
};

using namespace evmc::literals;

// Temporary needed up here to hock RLP encoding of an Account.
constexpr auto emptyTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr auto emptyCodeHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;
}  // namespace evmone::state
