// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <cassert>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace evmone::rlp
{
using bytes = std::basic_string<uint8_t>;
using bytes_view = std::basic_string_view<uint8_t>;

namespace internal
{
template <uint8_t ShortBase, uint8_t LongBase>
inline bytes encode_length(size_t l)
{
    static constexpr auto short_cutoff = 55;
    static_assert(ShortBase + short_cutoff <= 0xff);
    assert(l <= 0xffffff);

    if (l <= short_cutoff)
        return {static_cast<uint8_t>(ShortBase + l)};
    else if (const auto l0 = static_cast<uint8_t>(l); l <= 0xff)
        return {LongBase + 1, l0};
    else if (const auto l1 = static_cast<uint8_t>(l >> 8); l <= 0xffff)
        return {LongBase + 2, l1, l0};
    else
        return {LongBase + 3, static_cast<uint8_t>(l >> 16), l1, l0};
}

inline bytes wrap_list(const bytes& content)
{
    return internal::encode_length<192, 247>(content.size()) + content;
}

template <typename InputIterator>
inline bytes encode_container(InputIterator begin, InputIterator end);
}  // namespace internal

inline bytes_view trim(bytes_view b) noexcept
{
    b.remove_prefix(std::min(b.find_first_not_of(uint8_t{0x00}), b.size()));
    return b;
}

template <typename T>
inline decltype(rlp_encode(std::declval<T>())) encode(const T& v)
{
    return rlp_encode(v);
}

inline bytes encode(bytes_view data)
{
    static constexpr uint8_t short_base = 128;
    if (data.size() == 1 && data[0] < short_base)
        return {data[0]};

    return internal::encode_length<short_base, 183>(data.size()) += data;  // Op + not available.
}

inline bytes encode(uint64_t x)
{
    uint8_t b[sizeof(x)];
    intx::be::store(b, x);
    return encode(trim({b, sizeof(b)}));
}

inline bytes encode(const intx::uint256& x)
{
    uint8_t b[sizeof(x)];
    intx::be::store(b, x);
    return encode(trim({b, sizeof(b)}));
}

template <typename T>
inline bytes encode(const std::vector<T>& v)
{
    return internal::encode_container(v.begin(), v.end());
}

template <typename T, size_t N>
inline bytes encode(const T (&v)[N])
{
    return internal::encode_container(std::begin(v), std::end(v));
}

/// Encodes the fixed-size collection of heterogeneous values as RLP list.
template <typename... Types>
inline bytes encode_tuple(const Types&... elements)
{
    return internal::wrap_list((encode(elements) + ...));
}

/// Encodes the container as RLP list.
///
/// @tparam InputIterator  Type of the input iterator.
/// @param  begin          Begin iterator.
/// @param  end            End iterator.
/// @return                Bytes of the RLP list.
template <typename InputIterator>
inline bytes internal::encode_container(InputIterator begin, InputIterator end)
{
    bytes content;
    for (auto it = begin; it != end; ++it)
        content += encode(*it);
    return wrap_list(content);
}

namespace
{
template <typename T>
inline T load(bytes_view input, std::false_type)
{
    if (input.size() > sizeof(T))
        throw std::out_of_range("load: input too big");

    T x{};
    std::memcpy(&intx::as_bytes(x)[sizeof(T) - input.size()], input.data(), input.size());
    return x;
}

template <typename T>
inline T load(bytes_view input, std::true_type)
{
    if (input.size() > sizeof(T))
        throw std::runtime_error("load: input too big");

    T x{};
    std::memcpy(&intx::as_bytes(x)[sizeof(T) - input.size()], input.data(), input.size());
    x = intx::to_big_endian(x);
    return x;
}
}  // namespace

template <typename T>
inline T load(bytes_view input)
{
    constexpr auto is_integral = std::bool_constant < std::is_integral<T>() || std::is_same_v < T,
                   intx::uint256 >> ();
    return load<T>(input, is_integral);
}

// RLP decoding implementation based on
// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition

namespace
{
// <<offset, data_length>, type(false == string, true == list)>
inline std::pair<std::pair<size_t, size_t>, bool> decode_length(bytes_view input)
{
    const auto length = input.size();

    if (length == 0)
        throw std::runtime_error("rlp: input is null");

    const uint8_t prefix = input[0];

    if (prefix <= 0x7f)
        return {{0, 1}, false};
    else if (prefix <= 0xb7)
    {
        if (prefix - 0x80 >= length)
            throw std::runtime_error("rlp: decoding error");
        return {{1, prefix - 0x80}, false};
    }
    else if (prefix <= 0xbf)
    {
        const uint8_t len_of_str_len = prefix - 0xb7;
        if (len_of_str_len >= length)
            throw std::runtime_error("rlp: decoding error");
        const auto str_len = evmone::rlp::load<uint64_t>(input.substr(1, len_of_str_len));
        if (str_len >= length)
            throw std::runtime_error("rlp: decoding error");
        return {{1 + len_of_str_len, str_len}, false};
    }
    else if (prefix <= 0xf7)
    {
        const uint8_t list_len = prefix - 0xc0;
        if (list_len >= length)
            throw std::runtime_error("rlp: decoding error");
        return {{1, list_len}, true};
    }
    else if (prefix <= 0xff)
    {
        const uint8_t len_of_list_len = prefix - 0xf7;
        if (len_of_list_len >= length)
            throw std::runtime_error("rlp: decoding error");
        const auto list_len = evmone::rlp::load<uint64_t>(input.substr(1, len_of_list_len));
        if (list_len >= length)
            throw std::runtime_error("rlp: decoding error");
        return {{1 + len_of_list_len, list_len}, true};
    }

    // Impossible.
    return {};
}
}  // namespace

struct RLPElement
{
    bool is_list;
    bytes_view data;
};

template <typename T>
inline T decode(const bytes_view& input)
{
    T t{};
    if (rlp_decode(t, input))
        return t;
    throw std::runtime_error("rlp: decoding error");
}

/// Decodes RLP primitives
inline std::vector<RLPElement> decode(bytes_view input)
{
    if (input.size() == 0)
        return {};

    std::vector<RLPElement> output;

    const auto [offset_size, is_list] = decode_length(input);
    const auto [offset, size] = offset_size;

    if (!is_list)
        output.push_back(RLPElement{false, input.substr(offset, size)});
    else
        output.push_back(RLPElement{true, input.substr(offset, size)});

    const auto rest = decode(input.substr(offset + size));
    output.insert(output.end(), rest.begin(), rest.end());

    return output;
}

}  // namespace evmone::rlp
