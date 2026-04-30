#pragma once

#include <cstdint>

namespace pc::pcap {

inline constexpr std::uint32_t kLinkTypeEthernet = 1U;
inline constexpr std::uint32_t kLinkTypeLinuxSll = 113U;
inline constexpr std::uint32_t kLinkTypeLinuxSll2 = 276U;

}  // namespace pc::pcap

