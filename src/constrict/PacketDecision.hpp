#pragma once

#include <cstddef>
#include <string>

namespace pc::constrict {

struct PacketTruncationDecision {
    bool truncate {false};
    std::size_t new_caplen {0};
    std::string reason {"passthrough"};
};

}  // namespace pc::constrict

