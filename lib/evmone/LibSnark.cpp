// Aleth: Ethereum C++ client, tools and libraries.
// Copyright 2017-2019 Aleth Authors.
// Licensed under the GNU General Public License, Version 3.
#include "LibSnark.h"
#include "FixedHash.h"

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <optional>

using namespace std;
using namespace evmone;

namespace
{

using bytes = bytevec;

void initLibSnark() noexcept
{
	static bool s_initialized = []() noexcept
	{
		libff::inhibit_profiling_info = true;
		libff::inhibit_profiling_counters = true;
		libff::alt_bn128_pp::init_public_params();
		return true;
	}();
	(void)s_initialized;
}

libff::bigint<libff::alt_bn128_q_limbs> toLibsnarkBigint(h256 const& _x)
{
	libff::bigint<libff::alt_bn128_q_limbs> b;
	auto const N = b.N;
	constexpr size_t L = sizeof(b.data[0]);
	static_assert(sizeof(mp_limb_t) == L, "Unexpected limb size in libff::bigint.");
	for (size_t i = 0; i < N; i++)
		for (size_t j = 0; j < L; j++)
			b.data[N - 1 - i] |= mp_limb_t(_x[i * L + j]) << (8 * (L - 1 - j));
	return b;
}

h256 fromLibsnarkBigint(libff::bigint<libff::alt_bn128_q_limbs> const& _b)
{
	static size_t const N = static_cast<size_t>(_b.N);
	static size_t const L = sizeof(_b.data[0]);
	static_assert(sizeof(mp_limb_t) == L, "Unexpected limb size in libff::bigint.");
	h256 x;
	for (size_t i = 0; i < N; i++)
		for (size_t j = 0; j < L; j++)
			x[i * L + j] = uint8_t(_b.data[N - 1 - i] >> (8 * (L - 1 - j)));
	return x;
}

std::optional<libff::alt_bn128_Fq> decodeFqElement(evmone::bytesConstRef _data)
{
	// h256::AlignLeft ensures that the h256 is zero-filled on the right if _data
	// is too short.
	h256 xbin(_data, h256::AlignLeft);
	// TODO: Consider using a compiler time constant for comparison.
	if (u256(xbin) >= u256(fromLibsnarkBigint(libff::alt_bn128_Fq::mod)))
		return std::nullopt;
	return toLibsnarkBigint(xbin);
}

std::optional<libff::alt_bn128_G1> decodePointG1(evmone::bytesConstRef _data)
{
	auto x = decodeFqElement(_data.cropped(0));
	if(!x.has_value()) {
		return std::nullopt;
	}
	auto y = decodeFqElement(_data.cropped(32));
	if(!y.has_value()) {
		return std::nullopt;
	}
	if (*x == libff::alt_bn128_Fq::zero() && *y == libff::alt_bn128_Fq::zero())
		return libff::alt_bn128_G1::zero();
	libff::alt_bn128_G1 p(*x, *y, libff::alt_bn128_Fq::one());
	if (!p.is_well_formed())
		return std::nullopt;
	return p;
}

/// Concatenate the contents of a container onto a vector.
template <class T, class U>
inline std::vector<T>& operator+=(std::vector<T>& _a, U const& _b)
{
    _a.insert(_a.end(), std::begin(_b), std::end(_b));
    return _a;
}

/// Concatenate the contents of a container onto a vector
template <class T, class U> std::vector<T> operator+(std::vector<T> _a, U const& _b)
{
	return _a += _b;
}

bytes encodePointG1(libff::alt_bn128_G1 _p)
{
	if (_p.is_zero())
		return bytes(64, 0);
	_p.to_affine_coordinates();
	return
		fromLibsnarkBigint(_p.X.as_bigint()).asBytes() +
		fromLibsnarkBigint(_p.Y.as_bigint()).asBytes();
}

std::optional<libff::alt_bn128_Fq2> decodeFq2Element(evmone::bytesConstRef _data)
{
	// Encoding: c1 (256 bits) c0 (256 bits)
	// "Big endian", just like the numbers
	auto c1 = decodeFqElement(_data.cropped(32));
	if(!c1.has_value()) {
		return std::nullopt;
	}
	auto c0 = decodeFqElement(_data.cropped(0));
	if(!c0.has_value()) {
		return std::nullopt;
	}
	return libff::alt_bn128_Fq2(
		*c1,
		*c0
	);
}

std::optional<libff::alt_bn128_G2> decodePointG2(evmone::bytesConstRef _data)
{
	auto const x = decodeFq2Element(_data);
	if(!x.has_value()) {
		return std::nullopt;
	}
	auto const y = decodeFq2Element(_data.cropped(64));
	if(!y.has_value()) {
		return std::nullopt;
	}
	if (*x == libff::alt_bn128_Fq2::zero() && *y == libff::alt_bn128_Fq2::zero())
		return libff::alt_bn128_G2::zero();
	libff::alt_bn128_G2 p(*x, *y, libff::alt_bn128_Fq2::one());
	if (!p.is_well_formed())
		return std::nullopt;
	return p;
}

}

pair<bool, bytes> evmone::alt_bn128_pairing_product(evmone::bytesConstRef _in)
{
	// Input: list of pairs of G1 and G2 points
	// Output: 1 if pairing evaluates to 1, 0 otherwise (left-padded to 32 bytes)

	size_t constexpr pairSize = 2 * 32 + 2 * 64;
	size_t const pairs = _in.size() / pairSize;
	if (pairs * pairSize != _in.size())
		// Invalid length.
		return {false, bytes{}};

	initLibSnark();
	libff::alt_bn128_Fq12 x = libff::alt_bn128_Fq12::one();
	for (size_t i = 0; i < pairs; ++i)
	{
		bytesConstRef const pair = _in.cropped(i * pairSize, pairSize);
		auto const g1 = decodePointG1(pair);
		if(!g1.has_value()) {
			return {false, bytes{}};
		}
		auto const p = decodePointG2(pair.cropped(2 * 32));
		if(!p.has_value()) {
			return {false, bytes{}};
		}
		if (-libff::alt_bn128_G2::scalar_field::one() * *p + *p != libff::alt_bn128_G2::zero())
			// p is not an element of the group (has wrong order)
			return {false, bytes()};
		if (p->is_zero() || g1->is_zero())
			continue; // the pairing is one
		x = x * libff::alt_bn128_miller_loop(
			libff::alt_bn128_precompute_G1(*g1),
			libff::alt_bn128_precompute_G2(*p)
		);
	}
	bool const result = libff::alt_bn128_final_exponentiation(x) == libff::alt_bn128_GT::one();
	return {true, h256{result}.asBytes()};
}

pair<bool, bytes> evmone::alt_bn128_G1_add(evmone::bytesConstRef _in)
{
	initLibSnark();
	auto const p1 = decodePointG1(_in);
	if(!p1.has_value()) {
		return {false, bytes{}};
	}
	auto const p2 = decodePointG1(_in.cropped(32 * 2));
	if(!p2.has_value()) {
		return {false, bytes{}};
	}
	return {true, encodePointG1(*p1 + *p2)};
}

pair<bool, bytes> evmone::alt_bn128_G1_mul(evmone::bytesConstRef _in)
{
	initLibSnark();
	auto const p = decodePointG1(_in.cropped(0));
	if(!p.has_value()) {
		return {false, bytes{}};
	}
	libff::alt_bn128_G1 const result = toLibsnarkBigint(h256(_in.cropped(64), h256::AlignLeft)) * *p;
	return {true, encodePointG1(result)};
}
