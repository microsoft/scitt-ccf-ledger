// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "did/document.h"
#include "visit_each_entry_in_value.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/cose_signatures_config_interface.h>
#include <ccf/crypto/verifier.h>
#include <ccf/endpoint.h>
#include <ccf/http_accept.h>
#include <ccf/json_handler.h>
#include <ccf/service/tables/service.h>

namespace scitt
{
  static GetServiceParameters::Out certificate_to_service_parameters(
    const std::vector<uint8_t>& certificate_der)
  {
    auto service_id = ccf::crypto::Sha256Hash(certificate_der).hex_str();

    // TODO: extend to support multiple tree hash algorithms once CCF
    // supports them

    GetServiceParameters::Out out;
    out.service_id = service_id;
    out.tree_algorithm = "CCF";
    out.signature_algorithm = JOSE_ALGORITHM_ES256;
    out.service_certificate = ccf::crypto::b64_from_raw(certificate_der);
    return out;
  }

  /**
   * An indexing strategy collecting service keys used to sign receipts.
   */
  class ServiceKeyIndexingStrategy
    : public VisitEachEntryInValueTyped<ccf::Service>
  {
  public:
    ServiceKeyIndexingStrategy() :
      VisitEachEntryInValueTyped(ccf::Tables::SERVICE)
    {}

    nlohmann::json get_jwks() const
    {
      std::lock_guard guard(lock);

      std::vector<nlohmann::json> jwks;
      for (const auto& service_certificate : service_certificates)
      {
        auto verifier = ccf::crypto::make_unique_verifier(service_certificate);
        auto kid =
          ccf::crypto::Sha256Hash(verifier->public_key_der()).hex_str();
        nlohmann::json json_jwk = verifier->public_key_jwk();
        json_jwk["kid"] = kid;
        jwks.emplace_back(std::move(json_jwk));
      }
      nlohmann::json jwks_json;
      jwks_json["keys"] = jwks;
      return jwks_json;
    }

  protected:
    void visit_entry(
      const ccf::TxID& tx_id, const ccf::ServiceInfo& service_info) override
    {
      std::lock_guard guard(lock);

      // It is possible for multiple entries in the ServiceInfo table to contain
      // the same certificate, eg. if the service status changes. Using an
      // std::set removes duplicates.
      service_certificates.insert(service_info.cert);
    }

  private:
    mutable std::mutex lock;

    std::set<ccf::crypto::Pem> service_certificates;
  }; /**
      * An indexing strategy collecting all past and present service
      * certificates and makes them immediately available.
      */
  class ServiceCertificateIndexingStrategy
    : public VisitEachEntryInValueTyped<ccf::Service>
  {
  public:
    ServiceCertificateIndexingStrategy() :
      VisitEachEntryInValueTyped(ccf::Tables::SERVICE)
    {}

    std::vector<GetServiceParameters::Out> get_service_parameters() const
    {
      std::lock_guard guard(lock);

      std::vector<GetServiceParameters::Out> out;
      for (const auto& certificate : service_certificates)
      {
        out.push_back(certificate_to_service_parameters(certificate));
      }
      return out;
    }

  protected:
    void visit_entry(
      const ccf::TxID& tx_id, const ccf::ServiceInfo& service_info) override
    {
      std::lock_guard guard(lock);

      auto service_cert_der = ccf::crypto::cert_pem_to_der(service_info.cert);

      // It is possible for multiple entries in the ServiceInfo table to contain
      // the same certificate, eg. if the service status changes. Using an
      // std::set removes duplicates.
      service_certificates.insert(service_cert_der);
    }

  private:
    mutable std::mutex lock;

    // Set of DER-encoded certificates
    std::set<std::vector<uint8_t>> service_certificates;
  };

  namespace endpoints
  {
    static GetServiceParameters::Out get_service_parameters(
      ccf::endpoints::EndpointContext& ctx, nlohmann::json&& params)
    {
      auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
      auto service_info = service->get().value();
      auto service_cert_der = ccf::crypto::cert_pem_to_der(service_info.cert);
      return certificate_to_service_parameters(service_cert_der);
    }

    static GetHistoricServiceParameters::Out get_historic_service_parameters(
      const std::shared_ptr<ServiceCertificateIndexingStrategy>& index,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      GetHistoricServiceParameters::Out out;
      out.parameters = index->get_service_parameters();
      return out;
    }

    static Configuration get_configuration(
      ccf::endpoints::EndpointContext& ctx, nlohmann::json&& params)
    {
      return ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
        ->get()
        .value_or(Configuration{});
    };

    static GetVersion::Out get_version(
      ccf::endpoints::EndpointContext& ctx, nlohmann::json&& params)
    {
      GetVersion::Out out;
      out.version = SCITT_VERSION;
      return out;
    };

    static nlohmann::json get_jwks(
      const std::shared_ptr<ServiceKeyIndexingStrategy>& index,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      // FIXME: this is not right when the indexer is not up to date
      return index->get_jwks();
    }
  }

  static void register_service_endpoints(
    ccf::AbstractNodeContext& context, ccf::BaseEndpointRegistry& registry)
  {
    using namespace std::placeholders;

    const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};

    auto service_certificate_index =
      std::make_shared<ServiceCertificateIndexingStrategy>();

    auto service_key_index = std::make_shared<ServiceKeyIndexingStrategy>();

    context.get_indexing_strategies().install_strategy(
      service_certificate_index);

    context.get_indexing_strategies().install_strategy(service_key_index);

    auto get_transparency_config =
      [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        auto subsystem =
          context.get_subsystem<ccf::cose::AbstractCOSESignaturesConfig>();
        if (!subsystem)
        {
          throw InternalCborError("COSE signatures subsystem not available");
        }
        auto cfg = subsystem->get_cose_signatures_config();

        nlohmann::json config;
        config["issuer"] = cfg.issuer;
        config["jwks_uri"] = fmt::format("https://{}/jwks", cfg.issuer);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::CBOR);
        ctx.rpc_ctx->set_response_body(nlohmann::json::to_cbor(config));
        return;
      };

    registry
      .make_endpoint(
        "/parameters",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_service_parameters),
        no_authn_policy)
      .set_auto_schema<void, GetServiceParameters::Out>()
      .install();

    registry
      .make_endpoint(
        "/parameters/historic",
        HTTP_GET,
        ccf::json_adapter(std::bind(
          endpoints::get_historic_service_parameters,
          service_certificate_index,
          _1,
          _2)),
        no_authn_policy)
      .set_auto_schema<void, GetHistoricServiceParameters::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .install();

    registry
      .make_endpoint(
        "/configuration",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_configuration),
        no_authn_policy)
      .set_auto_schema<void, Configuration>()
      .install();

    registry
      .make_endpoint(
        "/version",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_version),
        no_authn_policy)
      .set_auto_schema<void, GetVersion::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .install();

    // FIXME: /jwks should return CBOR errors by default
    registry
      .make_endpoint(
        "/jwks",
        HTTP_GET,
        ccf::json_adapter(
          std::bind(endpoints::get_jwks, service_key_index, _1, _2)),
        no_authn_policy)
      .install();

    registry
      .make_read_only_endpoint(
        "/.well-known/transparency-configuration",
        HTTP_GET,
        get_transparency_config,
        no_authn_policy)
      .install();
  }
}
