#pragma once

#include <arpa/inet.h>

#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/local_info/local_info.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/message_validator_impl.h"

#include "absl/numeric/int128.h"
#include "cilium/api/nphds.pb.h"
#include "cilium/api/nphds.pb.validate.h"

// std::hash specialization for Abseil uint128, needed for unordered_map key.
namespace std {
template <> struct hash<absl::uint128> {
  size_t operator()(const absl::uint128& x) const {
    return hash<uint64_t>{}(absl::Uint128Low64(x)) ^
           (hash<uint64_t>{}(absl::Uint128High64(x)) << 1);
  }
};
} // namespace std

namespace Envoy {
namespace Cilium {

template <typename I> I ntoh(I);
template <> inline uint32_t ntoh(uint32_t addr) { return ntohl(addr); }
template <> inline absl::uint128 ntoh(absl::uint128 addr) {
  return Network::Utility::Ip6ntohl(addr);
}
template <typename I> I hton(I);
template <> inline uint32_t hton(uint32_t addr) { return htonl(addr); }
template <> inline absl::uint128 hton(absl::uint128 addr) {
  return Network::Utility::Ip6htonl(addr);
}

template <typename I> I masked(I addr, unsigned int plen) {
  const unsigned int PLEN_MAX = sizeof(I) * 8;
  return plen == 0 ? I(0) : addr & ~hton((I(1) << (PLEN_MAX - plen)) - 1);
};

enum ID : uint64_t {
  UNKNOWN = 0,
  WORLD = 2,
  // LocalIdentityFlag is the bit in the numeric identity that identifies
  // a numeric identity to have local scope
  LocalIdentityFlag = 1 << 24,
};

} // namespace Cilium
} // namespace Envoy
