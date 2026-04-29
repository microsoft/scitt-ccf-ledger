// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cbor.h"
#include "did/document.h"
#include "visit_each_entry_in_value.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/cose_signatures_config_interface.h>
#include <ccf/crypto/verifier.h>
#include <ccf/endpoint.h>
#include <ccf/http_accept.h>
#include <ccf/json_handler.h>
#include <ccf/network_identity_interface.h>
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
        auto pub_pem = verifier->public_key_pem();
        auto kid =
          ccf::crypto::Sha256Hash(verifier->public_key_der()).hex_str();
        nlohmann::json json_jwk;
        try
        {
          json_jwk =
            ccf::crypto::make_ec_public_key(pub_pem)->public_key_jwk(kid);
        }
        catch (const std::exception& ec_error)
        {
          try
          {
            json_jwk =
              ccf::crypto::make_rsa_public_key(pub_pem)->public_key_jwk(kid);
          }
          catch (const std::exception& rsa_error)
          {
            throw std::runtime_error(
              std::string("Unable to parse service public key as EC or RSA. ") +
              "EC parse failed: " + ec_error.what() +
              ". RSA parse failed: " + rsa_error.what());
          }
        }
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
  };

  /**
   * Compute a kid from a public key using SHA-256 hash of the DER encoding.
   *
   * Note: CCF has an equivalent internal function ccf::crypto::kid_from_key()
   * in src/crypto/public_key.h. If it gets exposed in the public API with an
   * ECPublicKeyPtr overload, we should switch to using it.
   * See: https://github.com/microsoft/CCF/blob/main/src/crypto/public_key.cpp
   */
  static std::string kid_from_key(const ccf::crypto::ECPublicKeyPtr& key)
  {
    auto der = key->public_key_der();
    return ccf::crypto::Sha256Hash(der).hex_str();
  }

  /**
   * Encode an EC public key as a COSE_Key with kid.
   */
  static std::vector<uint8_t> key_to_cose_key(
    const ccf::crypto::ECPublicKeyPtr& key, const std::string& kid)
  {
    auto coords = key->coordinates();
    auto crv = cbor::curve_id_to_cose_crv(key->get_curve_id());
    return cbor::ec_cose_key_with_kid_to_cbor(crv, coords.x, coords.y, kid);
  }

  static void set_cbor_response(
    ccf::endpoints::ReadOnlyEndpointContext& ctx,
    ccf::http_status status,
    std::vector<uint8_t>&& body)
  {
    ctx.rpc_ctx->set_response_status(status);
    ctx.rpc_ctx->set_response_header(
      ccf::http::headers::CONTENT_TYPE,
      ccf::http::headervalues::contenttype::CBOR);
    ctx.rpc_ctx->set_response_body(std::move(body));
  }

  /**
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
      // TODO: this is not right when the indexer is not up to date
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

    /**
     * The endpoint exposes the current service parameters.
     */
    registry
      .make_endpoint(
        "/parameters",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_service_parameters),
        no_authn_policy)
      .set_auto_schema<void, GetServiceParameters::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * The endpoint exposes older service parameters.
     * Parameters can change in the case of a
     * disaster recovery.
     */
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
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * Convenience endpoint to provide the service configuration.
     * The configuration includes the policy script used to validate
     * the submitted statements.
     */
    registry
      .make_endpoint(
        "/configuration",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_configuration),
        no_authn_policy)
      .set_auto_schema<void, Configuration>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * Convenience endpoint to provide the version of the SCITT service.
     * The version is used to find the correct source control version
     * it was built from.
     */
    registry
      .make_endpoint(
        "/version",
        HTTP_GET,
        ccf::json_adapter(endpoints::get_version),
        no_authn_policy)
      .set_auto_schema<void, GetVersion::Out>()
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * This endpoint is indirectly mentioned in the RFC,
     * through the "jwks_uri" field in the transparency configuration.
     * See 2.1.1. Transparency Configuration
     * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/
     */
    registry
      .make_endpoint(
        "/jwks",
        HTTP_GET,
        ccf::json_adapter(
          std::bind(endpoints::get_jwks, service_key_index, _1, _2)),
        no_authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * See Section 2.1 of draft-ietf-scitt-scrapi-08.
     * Returns all trusted service keys as a COSE_Key_Set in
     * application/cbor format.
     */
    auto get_scitt_keys = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      auto network_identity =
        context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
      if (!network_identity)
      {
        set_cbor_response(
          ctx,
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          cbor::cbor_error(
            "InternalError", "Network identity subsystem not available"));
        return;
      }

      auto trusted_keys = network_identity->get_trusted_keys();
      std::vector<std::vector<uint8_t>> cose_keys;
      for (const auto& [seq_no, key] : trusted_keys)
      {
        cose_keys.push_back(key_to_cose_key(key, kid_from_key(key)));
      }

      set_cbor_response(
        ctx, HTTP_STATUS_OK, cbor::cose_key_set_to_cbor(cose_keys));
    };

    registry
      .make_read_only_endpoint(
        "/.well-known/scitt-keys", HTTP_GET, get_scitt_keys, no_authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * See Section 2.2 of draft-ietf-scitt-scrapi-08.
     * Returns a single trusted service key by kid value
     * as a COSE_Key in application/cbor format.
     */
    auto get_scitt_key_by_kid =
      [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
        auto kid_value = ctx.rpc_ctx->get_request_path_params().at("kid_value");

        auto network_identity =
          context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
        if (!network_identity)
        {
          set_cbor_response(
            ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            cbor::cbor_error(
              "InternalError", "Network identity subsystem not available"));
          return;
        }

        auto trusted_keys = network_identity->get_trusted_keys();
        for (const auto& [seq_no, key] : trusted_keys)
        {
          auto kid = kid_from_key(key);
          if (kid == kid_value)
          {
            // Return a single COSE Key (map), not a COSE Key Set (array)
            // per Section 2.2 of draft-ietf-scitt-scrapi-09
            set_cbor_response(ctx, HTTP_STATUS_OK, key_to_cose_key(key, kid));
            return;
          }
        }

        set_cbor_response(
          ctx,
          HTTP_STATUS_NOT_FOUND,
          cbor::cbor_error(
            "No such key",
            fmt::format(
              "No key could be found for this '{}' value", kid_value)));
      };

    registry
      .make_read_only_endpoint(
        "/.well-known/scitt-keys/{kid_value}",
        HTTP_GET,
        get_scitt_key_by_kid,
        no_authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * See 2.1.1. Transparency Configuration
     * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi-08/
     */
    registry
      .make_read_only_endpoint(
        "/.well-known/transparency-configuration",
        HTTP_GET,
        get_transparency_config,
        no_authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();
  }
}
