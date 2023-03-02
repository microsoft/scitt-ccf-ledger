// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "kv_types.h"

#include <ccf/common_auth_policies.h>
#include <ccf/rpc_context.h>

namespace scitt
{
  /**
   * Authentication policy that requires a JWT 'Authorization' header.
   *
   * The policy is only active if enabled by the service configuration.
   * In addition to being signed appropriately, tokens must contain the minimum
   * set of claims required by the configuration.
   */
  class ConfigurableJwtAuthnPolicy : public ccf::JwtAuthnPolicy
  {
  public:
    std::unique_ptr<ccf::AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override
    {
      auto identity = JwtAuthnPolicy::authenticate(tx, ctx, error_reason);
      if (!identity)
      {
        log_auth_error(ctx, error_reason);
        return nullptr;
      }

      const auto* jwt =
        dynamic_cast<const ccf::JwtAuthnIdentity*>(identity.get());
      if (!jwt)
      {
        throw std::logic_error("JwtAuthnPolicy returned a bad identity type.");
      }

      auto handle = tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE);
      auto cfg = handle->get().value_or(Configuration{});
      const auto& required_claims = cfg.authentication.jwt.required_claims;
      if (!required_claims.is_object())
      {
        error_reason = "JWT authentication is not enabled";
        log_auth_error(ctx, error_reason);
        return nullptr;
      }

      if (check_claims(jwt->payload, required_claims, error_reason))
      {
        return identity;
      }
      else
      {
        log_auth_error(ctx, error_reason);
        return nullptr;
      }
    }

    static bool check_claims(
      const nlohmann::json& claims,
      const nlohmann::json& required_claims,
      std::string& error_reason)
    {
      if (!claims.is_object())
      {
        // This is enforced by CCF's JWT parser already.
        throw std::logic_error("Ill-formed JWT claims");
      }

      for (auto& kv : required_claims.items())
      {
        auto it = claims.find(kv.key());
        if (it == claims.end() || *it != kv.value())
        {
          error_reason = fmt::format("Missing claim {}", kv.key());
          return false;
        }
      }
      return true;
    }

    static void log_auth_error(
      const std::shared_ptr<ccf::RpcContext>& ctx, std::string& error_reason)
    {
      // CCF returns any errors in the auth policy with a 401 status
      CCF_APP_INFO(
        "ClientRequestId={} Verb={} URL={} Status=401",
        ctx->get_request_header("x-ms-client-request-id").value_or(""),
        ctx->get_request_verb().c_str(),
        ctx->get_request_url());
      CCF_APP_INFO(
        "ClientRequestId={} Code=InvalidAuthenticationInfo {}",
        ctx->get_request_header("x-ms-client-request-id").value_or(""),
        error_reason);
    }
  };

  /**
   * An authentication policy that allows any request through, only if permitted
   * by the service configuration.
   *
   * This policy is always included in the compile time set of policies, but the
   * `authentication.allow_unauthenticated` boolean service configuration option
   * controls whether it is active. The option is false by default.
   */
  class ConfigurableEmptyAuthnPolicy : public ccf::EmptyAuthnPolicy
  {
    std::unique_ptr<ccf::AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override
    {
      auto handle = tx.template ro<ConfigurationTable>(CONFIGURATION_TABLE);
      auto cfg = handle->get().value_or(Configuration{});
      if (cfg.authentication.allow_unauthenticated)
      {
        return EmptyAuthnPolicy::authenticate(tx, ctx, error_reason);
      }
      else
      {
        return nullptr;
      }
    }
  };
}
