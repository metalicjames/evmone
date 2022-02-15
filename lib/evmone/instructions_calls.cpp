// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "instructions.hpp"

namespace evmone::instr::core
{
template <evmc_opcode Op>
int64_t call_impl(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    static_assert(
        Op == OP_CALL || Op == OP_CALLCODE || Op == OP_DELEGATECALL || Op == OP_STATICCALL);

    const auto gas = stack.pop();
    const auto dst = intx::be::trunc<evmc::address>(stack.pop());
    const auto value = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? 0 : stack.pop();
    const auto has_value = value != 0;
    const auto input_offset = stack.pop();
    const auto input_size = stack.pop();
    const auto output_offset = stack.pop();
    const auto output_size = stack.pop();

    stack.push(0);  // Assume failure.

    if (state.rev >= EVMC_BERLIN && state.host.access_account(dst) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return gas_left;
    }

    if (gas_left = check_memory(state, gas_left, input_offset, input_size); gas_left < 0)
        return gas_left;


    if (gas_left = check_memory(state, gas_left, output_offset, output_size); gas_left < 0)
        return gas_left;

    auto msg = evmc_message{};
    msg.kind = (Op == OP_DELEGATECALL) ? EVMC_DELEGATECALL :
               (Op == OP_CALLCODE)     ? EVMC_CALLCODE :
                                         EVMC_CALL;
    msg.flags = (Op == OP_STATICCALL) ? uint32_t{EVMC_STATIC} : state.msg->flags;
    msg.depth = state.msg->depth + 1;
    msg.recipient = (Op == OP_CALL || Op == OP_STATICCALL) ? dst : state.msg->recipient;
    msg.code_address = dst;
    msg.sender = (Op == OP_DELEGATECALL) ? state.msg->sender : state.msg->recipient;
    msg.value =
        (Op == OP_DELEGATECALL) ? state.msg->value : intx::be::store<evmc::uint256be>(value);

    if (size_t(input_size) > 0)
    {
        msg.input_data = &state.memory[size_t(input_offset)];
        msg.input_size = size_t(input_size);
    }

    auto cost = has_value ? 9000 : 0;

    if constexpr (Op == OP_CALL)
    {
        if (has_value && state.msg->flags & EVMC_STATIC)
            return -1;

        if ((has_value || state.rev < EVMC_SPURIOUS_DRAGON) && !state.host.account_exists(dst))
            cost += 25000;
    }

    if ((gas_left -= cost) < 0)
        return gas_left;

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas < msg.gas)
        msg.gas = static_cast<int64_t>(gas);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)  // TODO: Always true for STATICCALL.
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)
        return -1;

    if (has_value)
    {
        msg.gas += 2300;  // Add stipend.
        gas_left += 2300;
    }

    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return gas_left;

    if (has_value && intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < value)
        return gas_left;

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(size_t(output_size), result.output_size); copy_size > 0)
        std::memcpy(&state.memory[size_t(output_offset)], result.output_data, copy_size);

    const auto gas_used = msg.gas - result.gas_left;
    gas_left -= gas_used;
    return gas_left;
}

template int64_t call_impl<OP_CALL>(StackTop stack, int64_t, ExecutionState& state) noexcept;
template int64_t call_impl<OP_STATICCALL>(StackTop stack, int64_t, ExecutionState& state) noexcept;
template int64_t call_impl<OP_DELEGATECALL>(
    StackTop stack, int64_t, ExecutionState& state) noexcept;
template int64_t call_impl<OP_CALLCODE>(StackTop stack, int64_t, ExecutionState& state) noexcept;


template <evmc_opcode Op>
int64_t create_impl(StackTop stack, int64_t gas_left, ExecutionState& state) noexcept
{
    static_assert(Op == OP_CREATE || Op == OP_CREATE2);

    if (state.msg->flags & EVMC_STATIC)
        return -1;

    const auto endowment = stack.pop();
    const auto init_code_offset = stack.pop();
    const auto init_code_size = stack.pop();

    if (gas_left = check_memory(state, gas_left, init_code_offset, init_code_size); gas_left < 0)
        return gas_left;

    auto salt = uint256{};
    if constexpr (Op == OP_CREATE2)
    {
        salt = stack.pop();
        auto salt_cost = num_words(static_cast<size_t>(init_code_size)) * 6;
        if ((gas_left -= salt_cost) < 0)
            return gas_left;
    }

    stack.push(0);
    state.return_data.clear();

    if (state.msg->depth >= 1024)
        return gas_left;

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment)
        return gas_left;

    auto msg = evmc_message{};
    msg.gas = gas_left;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    msg.kind = (Op == OP_CREATE) ? EVMC_CREATE : EVMC_CREATE2;
    if (size_t(init_code_size) > 0)
    {
        msg.input_data = &state.memory[size_t(init_code_offset)];
        msg.input_size = size_t(init_code_size);
    }
    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);

    const auto result = state.host.call(msg);
    gas_left -= msg.gas - result.gas_left;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = intx::be::load<uint256>(result.create_address);

    return gas_left;
}

template int64_t create_impl<OP_CREATE>(StackTop stack, int64_t, ExecutionState& state) noexcept;
template int64_t create_impl<OP_CREATE2>(StackTop stack, int64_t, ExecutionState& state) noexcept;
}  // namespace evmone::instr::core
