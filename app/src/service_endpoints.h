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
   * Set a CBOR error response with the correct
   * application/concise-problem-details+cbor content type per RFC 9290.
   */
  static void set_cbor_error_response(
    ccf::endpoints::ReadOnlyEndpointContext& ctx,
    ccf::http_status status,
    std::vector<uint8_t>&& body)
  {
    ctx.rpc_ctx->set_response_status(status);
    ctx.rpc_ctx->set_response_header(
      ccf::http::headers::CONTENT_TYPE, cbor::CBOR_ERROR_CONTENT_TYPE);
    ctx.rpc_ctx->set_response_body(std::move(body));
  }

  namespace endpoints
  {
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
  }

  static void register_service_endpoints(
    ccf::AbstractNodeContext& context, ccf::BaseEndpointRegistry& registry)
  {
    using namespace std::placeholders;

    const ccf::AuthnPolicies no_authn_policy = {ccf::empty_auth_policy};

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
    auto get_jwks = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      auto network_identity =
        context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
      if (!network_identity)
      {
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::JSON);
        nlohmann::json error;
        error["error"] = "InternalError";
        error["message"] = "Service keys temporarily unavailable";
        ctx.rpc_ctx->set_response_body(error.dump());
        return;
      }

      auto trusted_keys = network_identity->get_trusted_keys();
      std::vector<nlohmann::json> jwks;
      for (const auto& [seq_no, key] : trusted_keys)
      {
        auto kid = kid_from_key(key);
        auto jwk = key->public_key_jwk(kid);
        nlohmann::json json_jwk;
        to_json(json_jwk, jwk);
        jwks.emplace_back(std::move(json_jwk));
      }

      nlohmann::json jwks_json;
      jwks_json["keys"] = jwks;

      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_TYPE,
        ccf::http::headervalues::contenttype::JSON);
      ctx.rpc_ctx->set_response_body(jwks_json.dump());
    };

    registry
      .make_read_only_endpoint("/jwks", HTTP_GET, get_jwks, no_authn_policy)
      .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
      .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::None)
      .install();

    /**
     * See Section 2.1 of draft-ietf-scitt-scrapi-09.
     * Returns all trusted service keys as a COSE_Key_Set in
     * application/cbor format.
     */
    auto get_scitt_keys = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      auto network_identity =
        context.get_subsystem<ccf::NetworkIdentitySubsystemInterface>();
      if (!network_identity)
      {
        set_cbor_error_response(
          ctx,
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          cbor::cbor_error(
            "InternalError", "Service keys temporarily unavailable"));
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
     * See Section 2.2 of draft-ietf-scitt-scrapi-09.
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
          set_cbor_error_response(
            ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            cbor::cbor_error(
              "InternalError", "Service keys temporarily unavailable"));
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

        set_cbor_error_response(
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
     * https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi-09/
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
