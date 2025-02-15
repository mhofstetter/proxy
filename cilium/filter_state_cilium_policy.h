#pragma once

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/pure.h"
#include "envoy/network/address.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "cilium/network_policy.h"
#include "cilium/policy_id.h"

namespace Envoy {
namespace Cilium {

class PolicyResolver {
public:
  virtual ~PolicyResolver() = default;

  virtual uint32_t resolvePolicyId(const Network::Address::Ip*) const PURE;
  virtual const PolicyInstance& getPolicy(const std::string&) const PURE;
};

// FilterState that holds relevant connection & policy information that can be retrieved
// by the Cilium network- and HTTP policy filters via filter state.
class CiliumPolicyFilterState : public StreamInfo::FilterState::Object,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  CiliumPolicyFilterState(uint32_t ingress_source_identity, uint32_t source_identity, bool ingress,
                          bool l7lb, uint16_t port, std::string&& pod_ip,
                          const std::weak_ptr<PolicyResolver>& policy_resolver, uint32_t proxy_id,
                          absl::string_view sni)
      : ingress_source_identity_(ingress_source_identity), source_identity_(source_identity),
        ingress_(ingress), is_l7lb_(l7lb), port_(port), pod_ip_(std::move(pod_ip)),
        proxy_id_(proxy_id), sni_(sni), policy_resolver_(policy_resolver) {
    ENVOY_LOG(debug,
              "Cilium CiliumPolicyFilterState(): source_identity: {}, "
              "ingress: {}, port: {}, pod_ip: {}, proxy_id: {}, sni: \"{}\"",
              source_identity_, ingress_, port_, pod_ip_, proxy_id_, sni_);
  }

  uint32_t resolvePolicyId(const Network::Address::Ip* ip) const {
    const auto resolver = policy_resolver_.lock();
    if (resolver)
      return resolver->resolvePolicyId(ip);
    return Cilium::ID::WORLD; // default to WORLD policy ID if resolver is no longer available
  }

  const PolicyInstance& getPolicy() const {
    const auto resolver = policy_resolver_.lock();
    if (resolver)
      return resolver->getPolicy(pod_ip_);
    return NetworkPolicyMap::GetDenyAllPolicy();
  }

  // policyUseUpstreamDestinationAddress returns 'true' if policy enforcement should be done on the
  // basis of the upstream destination address.
  bool policyUseUpstreamDestinationAddress() const { return is_l7lb_; }

  static const std::string& key();

  // Additional ingress policy enforcement is performed if ingress_source_identity is non-zero
  uint32_t ingress_source_identity_;
  uint32_t source_identity_;
  bool ingress_;
  bool is_l7lb_;
  uint16_t port_;
  std::string pod_ip_;
  uint32_t proxy_id_;
  std::string sni_;

private:
  const std::weak_ptr<PolicyResolver> policy_resolver_;
};
} // namespace Cilium
} // namespace Envoy
