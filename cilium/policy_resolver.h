#pragma once

#include <stdint.h>

#include <string>

#include "envoy/common/pure.h"
#include "envoy/network/address.h"

#include "cilium/network_policy.h"

namespace Envoy {
namespace Cilium {

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstance& getPolicy(const std::string&) const PURE;
};

} // namespace Cilium
} // namespace Envoy
