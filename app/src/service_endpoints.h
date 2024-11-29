// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "did/document.h"
#include "visit_each_entry_in_value.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/crypto/verifier.h>
#include <ccf/endpoint.h>
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
    out.tree_algorithm = TREE_ALGORITHM_CCF;
    out.signature_algorithm = JOSE_ALGORITHM_ES256;
    out.service_certificate = ccf::crypto::b64_from_raw(certificate_der);
    return out;
  }

  static did::DidVerificationMethod certificate_to_verification_method(
    std::string_view service_identifier,
    const std::vector<uint8_t>& certificate_der)
  {
    auto verifier = ccf::crypto::make_unique_verifier(certificate_der);
    auto key_id = ccf::crypto::Sha256Hash(certificate_der).hex_str();

    // We roundtrip via JSON to convert from CCF's JWK type to our own.
    did::Jwk jwk = nlohmann::json(verifier->public_key_jwk());
    jwk.x5c = {{ccf::crypto::b64_from_raw(certificate_der)}};
    return did::DidVerificationMethod{
      .id = fmt::format("{}#{}", service_identifier, key_id),
      .type = std::string(did::VERIFICATION_METHOD_TYPE_JWK),
      .controller = std::string(service_identifier),
      .public_key_jwk = jwk,
    };
  }

  /**
   * An indexing strategy collecting all past and present service certificates
   * and makes them immediately available.
   */
  class ServiceCertificateIndexingStrategy
    : public VisitEachEntryInValueTyped<ccf::Service>
  {
  public:
    ServiceCertificateIndexingStrategy() :
      VisitEachEntryInValueTyped(ccf::Tables::SERVICE)
    {}

    did::DidDocument get_did_document(std::string_view service_identifier) const
    {
      std::lock_guard guard(lock);

      did::DidDocument doc;
      doc.id = std::string(service_identifier);
      for (const auto& certificate : service_certificates)
      {
        doc.assertion_method.push_back(
          certificate_to_verification_method(service_identifier, certificate));
      }
      return doc;
    }

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
      out.scitt_version = SCITT_VERSION;
      return out;
    };

    static did::DidDocument get_did_document(
      const std::shared_ptr<ServiceCertificateIndexingStrategy>& index,
      ccf::endpoints::EndpointContext& ctx,
      nlohmann::json&& params)
    {
      auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                   ->get()
                   .value_or(Configuration{});

      if (!cfg.service_identifier.has_value())
      {
        throw NotFoundError(errors::NotFound, "DID is not enabled");
      }

      return index->get_did_document(*cfg.service_identifier);
    }
  }

  static void register_service_endpoints(
    ccf::AbstractNodeContext& context, ccf::BaseEndpointRegistry& registry)
  {
    using namespace std::placeholders;

    const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};

    auto service_certificate_index =
      std::make_shared<ServiceCertificateIndexingStrategy>();

    context.get_indexing_strategies().install_strategy(
      service_certificate_index);

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

    registry
      .make_endpoint(
        "/.well-known/did.json",
        HTTP_GET,
        ccf::json_adapter(std::bind(
          endpoints::get_did_document, service_certificate_index, _1, _2)),
        {ccf::empty_auth_policy})
      .install();

    // The DID document used to be served under this endpoint only, until we
    // added the .well-known path above. As a transitional measure, we keep
    // both of them around for a bit.
    registry
      .make_endpoint(
        "/scitt/did.json",
        HTTP_GET,
        ccf::json_adapter(std::bind(
          endpoints::get_did_document, service_certificate_index, _1, _2)),
        {ccf::empty_auth_policy})
      .install();
  }
}
