// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "did/document.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/crypto/verifier.h>
#include <ccf/endpoint.h>
#include <ccf/json_handler.h>
#include <ccf/service/tables/service.h>

namespace scitt
{
  did::DidDocument service_info_to_did_document(
    std::string_view service_identifier, const ccf::ServiceInfo& service_info)
  {
    auto verifier = crypto::make_unique_verifier(service_info.cert);
    auto service_cert_der = verifier->cert_der();
    auto key_id = crypto::Sha256Hash(service_cert_der).hex_str();

    // We roundtrip via JSON to convert from CCF's JWK type to our own.
    did::Jwk jwk = nlohmann::json(verifier->public_key_jwk());
    jwk.x5c = {{
      crypto::b64_from_raw(service_cert_der),
    }};

    did::DidDocument doc;
    doc.id = std::string(service_identifier);
    doc.assertion_method.push_back(did::DidVerificationMethod{
      .id = fmt::format("{}#{}", service_identifier, key_id),
      .type = std::string(did::VERIFICATION_METHOD_TYPE_JWK),
      .controller = std::string(service_identifier),
      .public_key_jwk = jwk,
    });
    return doc;
  }

  did::DidDocument get_did_document(
    ccf::endpoints::EndpointContext& ctx, nlohmann::json&& params)
  {
    auto cfg = ctx.tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE)
                 ->get()
                 .value_or(Configuration{});

    if (!cfg.service_identifier.has_value())
    {
      throw NotFoundError(errors::NotFound, "DID is not enabled");
    }

    auto service = ctx.tx.template ro<ccf::Service>(ccf::Tables::SERVICE);
    auto service_info = service->get().value();

    return service_info_to_did_document(*cfg.service_identifier, service_info);
  }

  void register_service_endpoints(ccf::BaseEndpointRegistry& registry)
  {
    // A top-level DID (eg. did:web:example.com) would require serving the DID
    // document at `/.well-known/did.json`, which CCF does not yet support:
    // https://github.com/microsoft/CCF/issues/4810
    //
    // As a workaround, we currently use `did:web:example.com:scitt` as the DID.
    registry
      .make_endpoint(
        "/scitt/did.json",
        HTTP_GET,
        error_adapter(ccf::json_adapter(get_did_document)),
        {ccf::empty_auth_policy})
      .install();
  }
}
