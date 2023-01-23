// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "did/document.h"

#include <ccf/base_endpoint_registry.h>
#include <ccf/crypto/verifier.h>
#include <ccf/endpoint.h>
#include <ccf/indexing/strategies/visit_each_entry_in_map.h>
#include <ccf/json_handler.h>
#include <ccf/service/tables/service.h>

namespace scitt
{
  /**
   * A wrapper around VisitEachEntryInMap that works with any kv::TypedValue,
   * providing access to the deserialized value.
   */
  template <typename M>
  class VisitEachEntryInValueTyped
    : public ccf::indexing::strategies::VisitEachEntryInMap
  {
  public:
    using VisitEachEntryInMap::VisitEachEntryInMap;

  protected:
    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) final
    {
      visit_entry(tx_id, M::ValueSerialiser::from_serialised(v));
    }

    virtual void visit_entry(
      const ccf::TxID& tx_id, const typename M::Value& value) = 0;
  };

  /**
   * An indexing strategy collecting all past and present service identities and
   * making them immediately available.
   */
  class ServiceIdentityIndexingStrategy
    : public VisitEachEntryInValueTyped<ccf::Service>
  {
  public:
    ServiceIdentityIndexingStrategy() :
      VisitEachEntryInValueTyped(ccf::Tables::SERVICE)
    {}

    did::DidDocument get_did_document(std::string_view service_identifier) const
    {
      std::lock_guard guard(lock);

      did::DidDocument doc;
      doc.id = std::string(service_identifier);
      for (const auto& [key_id, jwk] : service_keys)
      {
        doc.assertion_method.push_back(did::DidVerificationMethod{
          .id = fmt::format("{}#{}", service_identifier, key_id),
          .type = std::string(did::VERIFICATION_METHOD_TYPE_JWK),
          .controller = std::string(service_identifier),
          .public_key_jwk = jwk,
        });
      }
      return doc;
    }

  protected:
    void visit_entry(
      const ccf::TxID& tx_id, const ccf::ServiceInfo& service_info) override
    {
      std::lock_guard guard(lock);

      auto verifier = crypto::make_unique_verifier(service_info.cert);
      auto service_cert_der = verifier->cert_der();
      auto key_id = crypto::Sha256Hash(service_cert_der).hex_str();

      // We roundtrip via JSON to convert from CCF's JWK type to our own.
      did::Jwk jwk = nlohmann::json(verifier->public_key_jwk());
      jwk.x5c = {{
        crypto::b64_from_raw(service_cert_der),
      }};

      // It is possible for multiple entries in the ServiceInfo table to contain
      // the same certificate, eg. if the service status changes. Using an
      // std::map removes duplicates.
      service_keys[key_id] = jwk;
    }

  private:
    mutable std::mutex lock;
    std::map<std::string, did::Jwk> service_keys;
  };

  did::DidDocument get_did_document(
    const std::shared_ptr<ServiceIdentityIndexingStrategy>&
      service_identity_index,
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

    return service_identity_index->get_did_document(*cfg.service_identifier);
  }

  void register_service_endpoints(
    ccfapp::AbstractNodeContext& context, ccf::BaseEndpointRegistry& registry)
  {
    using namespace std::placeholders;

    auto service_identity_index =
      std::make_shared<ServiceIdentityIndexingStrategy>();

    context.get_indexing_strategies().install_strategy(service_identity_index);

    // A top-level DID (eg. did:web:example.com) would require serving the DID
    // document at `/.well-known/did.json`, which CCF does not yet support:
    // https://github.com/microsoft/CCF/issues/4810
    //
    // As a workaround, we currently use `did:web:example.com:scitt` as the DID.
    registry
      .make_endpoint(
        "/scitt/did.json",
        HTTP_GET,
        ccf::json_adapter(
          std::bind(get_did_document, service_identity_index, _1, _2)),
        {ccf::empty_auth_policy})
      .install();
  }
}
