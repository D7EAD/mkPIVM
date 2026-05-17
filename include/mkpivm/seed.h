#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace mkpivm {
    // xoshiro256**. fast, good enough, deterministic. all per-seed
    // randomness flows through this.
    class SeedRng {
        public:
            explicit SeedRng(std::uint64_t seed) noexcept { reseed(seed); }
            explicit SeedRng(std::string_view text) noexcept { reseed(hash_string(text)); }

            void reseed(std::uint64_t seed) noexcept;

            std::uint64_t next() noexcept;

            // inclusive both ends
            std::uint64_t uniform(std::uint64_t lo, std::uint64_t hi) noexcept;

            // p_num out of p_den
            bool chance(std::uint32_t p_num, std::uint32_t p_den) noexcept;

            // pick from 0..n-1
            std::uint32_t pick(std::uint32_t n) noexcept {
                return static_cast<std::uint32_t>(uniform(0, n - 1));
            }

            // sub-rng so passes can draw without poisoning the master state
            SeedRng derive(std::string_view tag) const noexcept;

            static std::uint64_t hash_string(std::string_view s) noexcept;

        private:
            std::array<std::uint64_t, 4> state_{};
            static std::uint64_t splitmix64(std::uint64_t& x) noexcept;
    };
}