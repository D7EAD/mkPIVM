#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace mkpivm {
    class Error : public std::runtime_error {
        public:
            using std::runtime_error::runtime_error;
    };

    template <typename T, typename = std::enable_if_t<std::is_trivially_copyable_v<T>>>
    inline void write_le(std::vector<std::uint8_t>& out, T value) {
        const auto pos = out.size();
        out.resize(pos + sizeof(T));
        std::memcpy(out.data() + pos, &value, sizeof(T));
    }

    template <typename T, typename = std::enable_if_t<std::is_trivially_copyable_v<T>>>
    inline void poke_le(std::vector<std::uint8_t>& out, std::size_t offset, T value) {
        if (offset + sizeof(T) > out.size()) {
            throw Error("poke_le: out of bounds");
        }
        std::memcpy(out.data() + offset, &value, sizeof(T));
    }

    template <typename T, typename = std::enable_if_t<std::is_trivially_copyable_v<T>>>
    inline T peek_le(const std::vector<std::uint8_t>& in, std::size_t offset) {
        if (offset + sizeof(T) > in.size()) {
            throw Error("peek_le: out of bounds");
        }

        T v{};
        std::memcpy(&v, in.data() + offset, sizeof(T));
        return v;
    }

    inline std::string hex_dump(const std::vector<std::uint8_t>& bytes, std::size_t cols = 16) {
        static const char digits[] = "0123456789abcdef";
        std::string s;
        s.reserve(bytes.size() * 3 + bytes.size() / cols + 8);

        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (i && (i % cols == 0)) s.push_back('\n');
            else if (i) s.push_back(' ');
            const auto b = bytes[i];
            s.push_back(digits[b >> 4]);
            s.push_back(digits[b & 0xF]);
        }

        return s;
    }

    template <typename Container, typename Rng>
    inline void shuffle_in_place(Container& c, Rng& rng) {
        const auto n = c.size();
        if (n < 2) return;

        for (std::size_t i = n - 1; i > 0; --i) {
            const auto j = static_cast<std::size_t>(rng.uniform(0, static_cast<std::uint64_t>(i)));
            using std::swap;
            swap(c[i], c[j]);
        }
    }

    template <typename T>
    struct Span { // C++17>>>
        const T* data{nullptr};
        std::size_t size{0};

        constexpr const T* begin() const noexcept { return data; }
        constexpr const T* end()   const noexcept { return data + size; }
        constexpr const T& operator[](std::size_t i) const noexcept { return data[i]; }
        constexpr bool empty() const noexcept { return size == 0; }
    };

    template <typename T>
    Span(const T*, std::size_t) -> Span<T>;

    template <typename T>
    Span<T> as_span(const std::vector<T>& v) { return Span<T>{v.data(), v.size()}; }
}