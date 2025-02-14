// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#define MAP_OPCODE_TO_IDENTIFIER         \
    X(OP_STOP, stop)                     \
    X(OP_ADD, add)                       \
    X(OP_MUL, mul)                       \
    X(OP_SUB, sub)                       \
    X(OP_DIV, div)                       \
    X(OP_SDIV, sdiv)                     \
    X(OP_MOD, mod)                       \
    X(OP_SMOD, smod)                     \
    X(OP_ADDMOD, addmod)                 \
    X(OP_MULMOD, mulmod)                 \
    X(OP_EXP, exp)                       \
    X(OP_SIGNEXTEND, signextend)         \
    X(OP_LT, lt)                         \
    X(OP_GT, gt)                         \
    X(OP_SLT, slt)                       \
    X(OP_SGT, sgt)                       \
    X(OP_EQ, eq)                         \
    X(OP_ISZERO, iszero)                 \
    X(OP_AND, and_)                      \
    X(OP_OR, or_)                        \
    X(OP_XOR, xor_)                      \
    X(OP_NOT, not_)                      \
    X(OP_BYTE, byte)                     \
    X(OP_SHL, shl)                       \
    X(OP_SHR, shr)                       \
    X(OP_SAR, sar)                       \
    X(OP_KECCAK256, keccak256)           \
    X(OP_ADDRESS, address)               \
    X(OP_BALANCE, balance)               \
    X(OP_ORIGIN, origin)                 \
    X(OP_CALLER, caller)                 \
    X(OP_CALLVALUE, callvalue)           \
    X(OP_CALLDATALOAD, calldataload)     \
    X(OP_CALLDATASIZE, calldatasize)     \
    X(OP_CALLDATACOPY, calldatacopy)     \
    X(OP_CODESIZE, codesize)             \
    X(OP_CODECOPY, codecopy)             \
    X(OP_GASPRICE, gasprice)             \
    X(OP_EXTCODESIZE, extcodesize)       \
    X(OP_EXTCODECOPY, extcodecopy)       \
    X(OP_RETURNDATASIZE, returndatasize) \
    X(OP_RETURNDATACOPY, returndatacopy) \
    X(OP_EXTCODEHASH, extcodehash)       \
    X(OP_BLOCKHASH, blockhash)           \
    X(OP_COINBASE, coinbase)             \
    X(OP_TIMESTAMP, timestamp)           \
    X(OP_NUMBER, number)                 \
    X(OP_PREVRANDAO, prevrandao)         \
    X(OP_GASLIMIT, gaslimit)             \
    X(OP_CHAINID, chainid)               \
    X(OP_SELFBALANCE, selfbalance)       \
    X(OP_BASEFEE, basefee)               \
    X(OP_POP, pop)                       \
    X(OP_MLOAD, mload)                   \
    X(OP_MSTORE, mstore)                 \
    X(OP_MSTORE8, mstore8)               \
    X(OP_SLOAD, sload)                   \
    X(OP_SSTORE, sstore)                 \
    X(OP_JUMP, jump)                     \
    X(OP_JUMPI, jumpi)                   \
    X(OP_PC, pc)                         \
    X(OP_MSIZE, msize)                   \
    X(OP_GAS, gas)                       \
    X(OP_JUMPDEST, jumpdest)             \
    X(OP_PUSH0, push0)                   \
    X(OP_PUSH1, push<1>)                 \
    X(OP_PUSH2, push<2>)                 \
    X(OP_PUSH3, push<3>)                 \
    X(OP_PUSH4, push<4>)                 \
    X(OP_PUSH5, push<5>)                 \
    X(OP_PUSH6, push<6>)                 \
    X(OP_PUSH7, push<7>)                 \
    X(OP_PUSH8, push<8>)                 \
    X(OP_PUSH9, push<9>)                 \
    X(OP_PUSH10, push<10>)               \
    X(OP_PUSH11, push<11>)               \
    X(OP_PUSH12, push<12>)               \
    X(OP_PUSH13, push<13>)               \
    X(OP_PUSH14, push<14>)               \
    X(OP_PUSH15, push<15>)               \
    X(OP_PUSH16, push<16>)               \
    X(OP_PUSH17, push<17>)               \
    X(OP_PUSH18, push<18>)               \
    X(OP_PUSH19, push<19>)               \
    X(OP_PUSH20, push<20>)               \
    X(OP_PUSH21, push<21>)               \
    X(OP_PUSH22, push<22>)               \
    X(OP_PUSH23, push<23>)               \
    X(OP_PUSH24, push<24>)               \
    X(OP_PUSH25, push<25>)               \
    X(OP_PUSH26, push<26>)               \
    X(OP_PUSH27, push<27>)               \
    X(OP_PUSH28, push<28>)               \
    X(OP_PUSH29, push<29>)               \
    X(OP_PUSH30, push<30>)               \
    X(OP_PUSH31, push<31>)               \
    X(OP_PUSH32, push<32>)               \
    X(OP_DUP1, dup<1>)                   \
    X(OP_DUP2, dup<2>)                   \
    X(OP_DUP3, dup<3>)                   \
    X(OP_DUP4, dup<4>)                   \
    X(OP_DUP5, dup<5>)                   \
    X(OP_DUP6, dup<6>)                   \
    X(OP_DUP7, dup<7>)                   \
    X(OP_DUP8, dup<8>)                   \
    X(OP_DUP9, dup<9>)                   \
    X(OP_DUP10, dup<10>)                 \
    X(OP_DUP11, dup<11>)                 \
    X(OP_DUP12, dup<12>)                 \
    X(OP_DUP13, dup<13>)                 \
    X(OP_DUP14, dup<14>)                 \
    X(OP_DUP15, dup<15>)                 \
    X(OP_DUP16, dup<16>)                 \
    X(OP_SWAP1, swap<1>)                 \
    X(OP_SWAP2, swap<2>)                 \
    X(OP_SWAP3, swap<3>)                 \
    X(OP_SWAP4, swap<4>)                 \
    X(OP_SWAP5, swap<5>)                 \
    X(OP_SWAP6, swap<6>)                 \
    X(OP_SWAP7, swap<7>)                 \
    X(OP_SWAP8, swap<8>)                 \
    X(OP_SWAP9, swap<9>)                 \
    X(OP_SWAP10, swap<10>)               \
    X(OP_SWAP11, swap<11>)               \
    X(OP_SWAP12, swap<12>)               \
    X(OP_SWAP13, swap<13>)               \
    X(OP_SWAP14, swap<14>)               \
    X(OP_SWAP15, swap<15>)               \
    X(OP_SWAP16, swap<16>)               \
    X(OP_LOG0, log<0>)                   \
    X(OP_LOG1, log<1>)                   \
    X(OP_LOG2, log<2>)                   \
    X(OP_LOG3, log<3>)                   \
    X(OP_LOG4, log<4>)                   \
    X(OP_CREATE, create)                 \
    X(OP_CALL, call)                     \
    X(OP_CALLCODE, callcode)             \
    X(OP_RETURN, return_)                \
    X(OP_DELEGATECALL, delegatecall)     \
    X(OP_CREATE2, create2)               \
    X(OP_STATICCALL, staticcall)         \
    X(OP_INVALID, invalid)               \
    X(OP_REVERT, revert)                 \
    X(OP_SELFDESTRUCT, selfdestruct)
