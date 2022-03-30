// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2014-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.


#pragma once

#include "vector_ref.h"

#include <utility>
#include <cstdint>

namespace evmone
{

using byte = uint8_t;
using bytevec = std::vector<byte>;
using bytesRef = vector_ref<byte>;
using bytesConstRef = vector_ref<byte const>;

std::pair<bool, bytevec> alt_bn128_pairing_product(bytesConstRef _in);
std::pair<bool, bytevec> alt_bn128_G1_add(bytesConstRef _in);
std::pair<bool, bytevec> alt_bn128_G1_mul(bytesConstRef _in);

}
