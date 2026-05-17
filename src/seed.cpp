#include "mkpivm/seed.h"

#include <cstring>

namespace mkpivm {
    std::uint64_t SeedRng::splitmix64(std::uint64_t& x) noexcept {
        x += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    void SeedRng::reseed(std::uint64_t seed) noexcept {
        std::uint64_t s = seed ? seed : 0xA5A5A5A5DEADBEEFULL;
        for (auto& w : state_) w = splitmix64(s);
    }

    static inline std::uint64_t rotl(std::uint64_t x, int k) noexcept {
        return (x << k) | (x >> (64 - k));
    }

    std::uint64_t SeedRng::next() noexcept {
        const std::uint64_t result = rotl(state_[1] * 5ULL, 7) * 9ULL;
        const std::uint64_t t = state_[1] << 17;
        state_[2] ^= state_[0];
        state_[3] ^= state_[1];
        state_[1] ^= state_[2];
        state_[0] ^= state_[3];
        state_[2] ^= t;
        state_[3] = rotl(state_[3], 45);
        return result;
    }

    std::uint64_t SeedRng::uniform(std::uint64_t lo, std::uint64_t hi) noexcept {
        if (hi <= lo) return lo;

        const std::uint64_t range = hi - lo + 1ULL;
        if (range == 0) return next();

        // modulo with rejection. bias technically here but who cares, we're picking
        // register slots and opcode bytes, not crypto material so idgaf
        const std::uint64_t threshold = (0ULL - range) % range;
        while (true) {
            const std::uint64_t x = next();
            if (x >= threshold) return lo + (x % range);
        }
    }

    bool SeedRng::chance(std::uint32_t p_num, std::uint32_t p_den) noexcept {
        if (p_den == 0) return false;
        return uniform(0, p_den - 1) < p_num;
    }

    SeedRng SeedRng::derive(std::string_view tag) const noexcept {
        std::uint64_t s = state_[0] ^ rotl(state_[1], 13) ^ rotl(state_[2], 27) ^ rotl(state_[3], 41);
        s ^= hash_string(tag);
        return SeedRng(s);
    }

    std::uint64_t SeedRng::hash_string(std::string_view s) noexcept {
        // fnv-1a with a finalizer mix tacked on
        std::uint64_t h = 0xCBF29CE484222325ULL;
        for (unsigned char c : s) {
            h ^= c;
            h *= 0x100000001B3ULL;
        }
        h ^= h >> 33;
        h *= 0xFF51AFD7ED558CCDULL;
        h ^= h >> 33;
        h *= 0xC4CEB9FE1A85EC53ULL;
        h ^= h >> 33;
        return h;
    }
}