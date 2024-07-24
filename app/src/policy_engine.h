// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "http_error.h"
#include "profiles.h"
#include "tracing.h"

#include <ccf/js/common_context.h>
#include <string>

namespace scitt
{
  using PolicyScript = std::string;

  namespace js
  {
    static inline ccf::js::core::JSWrappedValue claim_profile_to_js_val(
      ccf::js::core::Context& ctx, ClaimProfile claim_profile)
    {
      switch (claim_profile)
      {
        case ClaimProfile::IETF:
        {
          return ctx.new_string("IETF");
          break;
        }
        case ClaimProfile::X509:
        {
          return ctx.new_string("X509");
          break;
        }
        case ClaimProfile::Notary:
        {
          return ctx.new_string("Notary");
          break;
        }
        default:
        {
          throw std::logic_error("Unhandled ClaimProfile value");
        }
      }
    }

    static inline ccf::js::core::JSWrappedValue protected_headers_to_js_val(
      ccf::js::core::Context& ctx, const scitt::cose::ProtectedHeader& phdr)
    {
      auto obj = ctx.new_obj();

      // Vanilla SCITT protected header parameters
      {
        if (phdr.alg.has_value())
        {
          obj.set_int64("alg", phdr.alg.value());
        }

        if (phdr.crit.has_value())
        {
          auto crit_array = ctx.new_array();
          size_t i = 0;

          for (const auto& e : phdr.crit.value())
          {
            if (std::holds_alternative<int64_t>(e))
            {
              crit_array.set_at_index(
                i++,
                ccf::js::core::JSWrappedValue(
                  ctx, JS_NewInt64(ctx, std::get<int64_t>(e))));
            }
            else if (std::holds_alternative<std::string>(e))
            {
              crit_array.set_at_index(
                i++, ctx.new_string(std::get<std::string>(e)));
            }
          }

          obj.set("crit", std::move(crit_array));
        }

        if (phdr.kid.has_value())
        {
          obj.set("kid", ctx.new_string(phdr.kid.value()));
        }

        if (phdr.issuer.has_value())
        {
          obj.set("issuer", ctx.new_string(phdr.issuer.value()));
        }

        if (phdr.feed.has_value())
        {
          obj.set("feed", ctx.new_string(phdr.feed.value()));
        }

        if (phdr.cty.has_value())
        {
          if (std::holds_alternative<int64_t>(phdr.cty.value()))
          {
            obj.set_int64("cty", std::get<int64_t>(phdr.cty.value()));
          }
          else if (std::holds_alternative<std::string>(phdr.cty.value()))
          {
            obj.set(
              "cty", ctx.new_string(std::get<std::string>(phdr.cty.value())));
          }
        }

        if (phdr.x5chain.has_value())
        {
          auto x5_array = ctx.new_array();
          size_t i = 0;

          for (const auto& der_cert : phdr.x5chain.value())
          {
            auto pem = ccf::crypto::cert_der_to_pem(der_cert);
            x5_array.set_at_index(i++, ctx.new_string(pem.str()));
          }

          obj.set("x5chain", std::move(x5_array));
        }
      }

      // Extra Notary protected header parameters.
      {
        if (phdr.notary_signing_scheme.has_value())
        {
          obj.set(
            "notary_signing_scheme",
            ctx.new_string(phdr.notary_signing_scheme.value()));
        }

        if (phdr.notary_signing_time.has_value())
        {
          obj.set_int64(
            "notary_signing_time", phdr.notary_signing_time.value());
        }

        if (phdr.notary_authentic_signing_time.has_value())
        {
          obj.set_int64(
            "notary_authentic_signing_time",
            phdr.notary_authentic_signing_time.value());
        }

        if (phdr.notary_expiry.has_value())
        {
          obj.set_int64("notary_expiry", phdr.notary_expiry.value());
        }
      }

      return obj;
    }

    static inline bool apply_js_policy(
      const PolicyScript& script,
      const std::string& policy_name,
      ClaimProfile claim_profile,
      const scitt::cose::ProtectedHeader& phdr)
    {
      // Allow the policy to access common globals (including shims for
      // builtins) like "console", "ccf.crypto"
      ccf::js::CommonContext interpreter(ccf::js::TxAccess::APP_RO);

      ccf::js::core::JSWrappedValue apply_func;
      try
      {
        apply_func =
          interpreter.get_exported_function(script, "apply", policy_name);
      }
      catch (const std::exception& e)
      {
        throw BadRequestError(
          scitt::errors::PolicyError,
          fmt::format("Invalid policy module: {}", e.what()));
      }

      auto profile_val = claim_profile_to_js_val(interpreter, claim_profile);
      auto phdr_val = protected_headers_to_js_val(interpreter, phdr);

      const auto result = interpreter.call_with_rt_options(
        apply_func,
        {profile_val, phdr_val},
        std::nullopt,
        ccf::js::core::RuntimeLimitsPolicy::NONE);

      if (result.is_exception())
      {
        auto [reason, trace] = interpreter.error_message();

        throw BadRequestError(
          scitt::errors::PolicyError,
          fmt::format(
            "Error while applying policy: {}\n{}",
            reason,
            trace.value_or("<no trace>")));
      }

      // JS-style semantics - anything truthy becomes true
      return result.is_true();
    }
  }

  static inline bool run_policy_engine(
    const PolicyScript& script,
    const std::string& policy_name,
    ClaimProfile claim_profile,
    const cose::ProtectedHeader& phdr)
  {
    return js::apply_js_policy(script, policy_name, claim_profile, phdr);
  }
}