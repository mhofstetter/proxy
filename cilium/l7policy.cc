#include "cilium/l7policy.h"

#include <string>

#include "envoy/registry/registry.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/config/utility.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/utility.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_subject_alt_names.h"
#include "source/extensions/filters/http/common/factory_base.h"

#include "cilium/api/l7policy.pb.validate.h"
#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {

class CiliumAccessFilterFactory
    : public Extensions::HttpFilters::Common::DualFactoryBase<::cilium::L7Policy> {
public:
  CiliumAccessFilterFactory() : DualFactoryBase("cilium.l7policy") {}

private:
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProtoTyped(const ::cilium::L7Policy& proto_config, const std::string&,
                                    DualInfo dual_info,
                                    Server::Configuration::ServerFactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(proto_config, context.timeSource(),
                                                   dual_info.scope, dual_info.is_upstream);
    return [config](Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }
};

using UpstreamCiliumAccessFilterFactory = CiliumAccessFilterFactory;

/**
 * Static registration for this filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumAccessFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);
REGISTER_FACTORY(UpstreamCiliumAccessFilterFactory,
                 Server::Configuration::UpstreamHttpFilterConfigFactory);

Config::Config(const std::string& access_log_path, const std::string& denied_403_body,
               TimeSource& time_source, Stats::Scope& scope, bool is_upstream)
    : time_source_(time_source), stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(scope, "cilium"))},
      denied_403_body_(denied_403_body), is_upstream_(is_upstream), access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path, time_source);
  }
  if (denied_403_body_.length() == 0) {
    denied_403_body_ = "Access denied";
  }
  size_t len = denied_403_body_.length();
  if (len < 2 || denied_403_body_[len - 2] != '\r' || denied_403_body_[len - 1] != '\n') {
    denied_403_body_.append("\r\n");
  }
}

Config::Config(const ::cilium::L7Policy& config, TimeSource& time_source, Stats::Scope& scope,
               bool is_upstream)
    : Config(config.access_log_path(), config.denied_403_body(), time_source, scope, is_upstream) {}

void Config::Log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

void AccessFilter::sendLocalError(absl::string_view details) {
  ENVOY_LOG(warn, details);
  callbacks_->sendLocalReply(Http::Code::InternalServerError, "", nullptr, absl::nullopt,
                             StringUtil::replaceAllEmptySpace(details));
}

void AccessFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;

  // Create log entry if not already in filter state
  log_entry_ =
      callbacks_->streamInfo().filterState()->getDataMutable<AccessLog::Entry>(AccessLogKey);
  if (log_entry_ == nullptr) {
    auto log_entry = std::make_unique<AccessLog::Entry>();
    log_entry_ = log_entry.get();
    callbacks_->streamInfo().filterState()->setData(AccessLogKey, std::move(log_entry),
                                                    StreamInfo::FilterState::StateType::Mutable,
                                                    StreamInfo::FilterState::LifeSpan::Request);
  }

  if (config_->is_upstream_) {
    callbacks_->upstreamCallbacks()->addUpstreamCallbacks(*this);
  }
}

void AccessFilter::onUpstreamConnectionEstablished() {
  if (latched_end_stream_.has_value()) {
    const bool end_stream = *latched_end_stream_;
    latched_end_stream_.reset();
    ENVOY_LOG(debug, "cilium.l7policy: RESUMING after upstream connection has been established");
    Http::FilterHeadersStatus status = decodeHeaders(*latched_headers_, end_stream);
    if (status == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    }
  }
}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                      bool end_stream) {
  StreamInfo::StreamInfo& stream_info = callbacks_->streamInfo();

  // Pause upstream decoding until connection has been established
  if (config_->is_upstream_) {
    // Skip enforcement or logging on shadows
    if (stream_info.isShadow()) {
      return Http::FilterHeadersStatus::Continue;
    }

    ASSERT(callbacks_->upstreamCallbacks());
    if (!callbacks_->upstreamCallbacks()->upstream()) {
      latched_headers_ = headers;
      latched_end_stream_ = end_stream;
      ENVOY_LOG(debug, "cilium.l7policy: PAUSING until upstream connection has been established");
      return Http::FilterHeadersStatus::StopAllIterationAndWatermark;
    }
  }

  ENVOY_LOG(debug, "cilium.l7policy: {} decodeHeaders()",
            config_->is_upstream_ ? "upstream" : "downstream");

  const auto& conn = callbacks_->connection();

  if (!conn) {
    sendLocalError("cilium.l7policy: No connection");
    return Http::FilterHeadersStatus::StopIteration;
  }

  const Network::Socket::OptionsSharedPtr socketOptions = conn->socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (!option) {
    sendLocalError("cilium.l7policy: Cilium Socket Option not found");
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Destination may have changed due to upstream routing and load balancing.
  // Use original destination address for policy enforcement when not L7 LB, even if the actual
  // destination may have changed. This can happen with custom Envoy Listeners.
  const Network::Address::InstanceConstSharedPtr& dst_address =
      config_->is_upstream_ ? stream_info.upstreamInfo()->upstreamHost()->address()
                            : stream_info.downstreamAddressProvider().localAddress();

  if (nullptr == dst_address) {
    sendLocalError("cilium.l7policy: No destination address");
    return Http::FilterHeadersStatus::StopIteration;
  }

  const auto dip = dst_address->ip();
  if (!dip) {
    sendLocalError(
        fmt::format("cilium.l7policy: Non-IP destination address: {}", dst_address->asString()));
    return Http::FilterHeadersStatus::StopIteration;
  }

  uint32_t destination_port = dip->port();
  uint32_t destination_identity = option->resolvePolicyId(dip);

  // Policy may have changed since the connection was established, get fresh policy
  const auto& policy = option->getPolicy();
  if (!policy) {
    sendLocalError(fmt::format("cilium.l7policy: No policy found for pod {}", option->pod_ip_));
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (log_entry_ == nullptr) {
    sendLocalError("cilium.l7policy: No log entry");
    return Http::FilterHeadersStatus::StopIteration;
  }

  bool denied = false;
  // Enforce Ingress policy only in the downstream filter
  if (!config_->is_upstream_) {
    log_entry_->InitFromRequest(
        option->pod_ip_, option->proxy_id_, option->ingress_, option->identity_,
        callbacks_->streamInfo().downstreamAddressProvider().remoteAddress(), 0,
        callbacks_->streamInfo().downstreamAddressProvider().localAddress(),
        callbacks_->streamInfo(), headers);

    if (option->ingress_source_identity_ != 0) {
      allowed_ = policy->allowed(true, option->ingress_source_identity_, option->port_, headers,
                                 *log_entry_);
      ENVOY_LOG(debug,
                "cilium.l7policy: Ingress from {} policy lookup for endpoint {} for port {}: {}",
                option->ingress_source_identity_, option->pod_ip_, option->port_,
                allowed_ ? "ALLOW" : "DENY");
      denied = !allowed_;
    }

    // Downstream filter leaves L7 LB enforcement and access logging to the upstream
    // filter
    if (!denied && option->is_l7lb_) {
      return Http::FilterHeadersStatus::Continue;
    }
  }

  if (!denied) {
    allowed_ = policy->allowed(option->ingress_,
                               option->ingress_ ? option->identity_ : destination_identity,
                               destination_port, headers, *log_entry_);
  }
  ENVOY_LOG(debug, "cilium.l7policy: {} ({}->{}) {} policy lookup for endpoint {} for port {}: {}",
            option->ingress_ ? "ingress" : "egress", option->identity_, destination_identity,
            config_->is_upstream_ ? "upstream" : "downstream", option->pod_ip_, destination_port,
            allowed_ ? "ALLOW" : "DENY");

  // Update the log entry with the chosen destination address and current headers, as remaining
  // filters, upstream, and/or policy may have altered headers.
  log_entry_->UpdateFromRequest(destination_identity, dst_address, headers);

  if (!allowed_) {
    callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_, nullptr,
                               absl::nullopt, absl::string_view());
    config_->Log(*log_entry_, ::cilium::EntryType::Denied);
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Log as a forwarded request
  config_->Log(*log_entry_, ::cilium::EntryType::Request);
  return Http::FilterHeadersStatus::Continue;
}

void AccessFilter::onStreamComplete() {
  // Request may have been left unlogged due to an error and/or missing local reply
  if (log_entry_ && !log_entry_->request_logged_) {
    config_->Log(*log_entry_, ::cilium::EntryType::Request);
  }
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  ENVOY_LOG(debug, "cilium.l7policy: {} encodeHeaders()",
            config_->is_upstream_ ? "upstream" : "downstream");

  // Nothing to do in the upstream filter
  if (config_->is_upstream_) {
    return Http::FilterHeadersStatus::Continue;
  }

  if (log_entry_ == nullptr) {
    return Http::FilterHeadersStatus::Continue;
  }

  // Request may have been left unlogged due to an error or L3/4 deny
  if (!log_entry_->request_logged_) {
    // Default logging local errors as "forwarded".
    // The response log will contain the locally generated HTTP error code.
    auto logType = ::cilium::EntryType::Request;

    if (headers.Status()->value() == "403") {
      // Log as a denied request.
      logType = ::cilium::EntryType::Denied;
      config_->stats_.access_denied_.inc();
    }
    config_->Log(*log_entry_, logType);
  }

  // Log the response
  log_entry_->UpdateFromResponse(headers, config_->time_source_);
  config_->Log(*log_entry_, ::cilium::EntryType::Response);
  return Http::FilterHeadersStatus::Continue;
}

} // namespace Cilium
} // namespace Envoy
