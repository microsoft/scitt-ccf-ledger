// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "cose.h"
#include "http_error.h"
#include "regorus.hpp"
#include "tracing.h"
#include "verified_details.h"

#include <ccf/ds/hex.h>
#include <ccf/js/common_context.h>
#include <chrono>
#include <string>

namespace scitt
{
  using PolicyScript = std::string;

  namespace js
  {
    static inline ccf::js::core::JSWrappedValue protected_header_to_js_val(
      ccf::js::core::Context& ctx, const scitt::cose::ProtectedHeader& phdr)
    {
      auto obj = ctx.new_obj();

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

        if (phdr.iat.has_value())
        {
          obj.set_int64("iat", phdr.iat.value());
        }

        if (phdr.svn.has_value())
        {
          obj.set_int64("svn", phdr.svn.value());
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

        auto cwt = ctx.new_obj();
        if (phdr.cwt_claims.iss.has_value())
        {
          cwt.set("iss", ctx.new_string(phdr.cwt_claims.iss.value()));
        }
        if (phdr.cwt_claims.sub.has_value())
        {
          cwt.set("sub", ctx.new_string(phdr.cwt_claims.sub.value()));
        }
        if (phdr.cwt_claims.iat.has_value())
        {
          cwt.set_int64("iat", phdr.cwt_claims.iat.value());
        }
        if (phdr.cwt_claims.svn.has_value())
        {
          cwt.set_int64("svn", phdr.cwt_claims.svn.value());
        }
        obj.set("cwt", std::move(cwt));

        auto tss_map = ctx.new_obj();
        if (phdr.tss_map.svc_id.has_value())
        {
          tss_map.set("svc_id", ctx.new_string(phdr.tss_map.svc_id.value()));
        }
        if (phdr.tss_map.attestation.has_value())
        {
          tss_map.set(
            "attestation",
            ctx.new_array_buffer_copy(phdr.tss_map.attestation.value()));
        }
        if (phdr.tss_map.attestation_type.has_value())
        {
          tss_map.set(
            "attestation_type",
            ctx.new_string(phdr.tss_map.attestation_type.value()));
        }
        if (phdr.tss_map.cose_key.has_value())
        {
          auto cose_key = phdr.tss_map.cose_key.value();
          auto cose_key_obj = ctx.new_obj();

          if (cose_key.kty().has_value())
          {
            cose_key_obj.set_int64("kty", cose_key.kty().value());
          }
          if (cose_key.crv_n_k_pub().has_value())
          {
            if (std::holds_alternative<int64_t>(cose_key.crv_n_k_pub().value()))
            {
              cose_key_obj.set_int64(
                "crv", std::get<int64_t>(cose_key.crv_n_k_pub().value()));
            }
            else if (std::holds_alternative<std::vector<uint8_t>>(
                       cose_key.crv_n_k_pub().value()))
            {
              cose_key_obj.set(
                "n",
                ctx.new_array_buffer_copy(std::get<std::vector<uint8_t>>(
                  cose_key.crv_n_k_pub().value())));
            }
          }
          if (cose_key.x_e().has_value())
          {
            cose_key_obj.set(
              "x_e", ctx.new_array_buffer_copy(cose_key.x_e().value()));
          }
          if (cose_key.y().has_value())
          {
            cose_key_obj.set(
              "y", ctx.new_array_buffer_copy(cose_key.y().value()));
          }

          tss_map.set("cose_key", std::move(cose_key_obj));

          auto cose_key_sha256 = cose_key.to_sha256_thumb();
          tss_map.set(
            "cose_key_sha256",
            ctx.new_string(ccf::ds::to_hex(cose_key_sha256)));
        }
        if (phdr.tss_map.snp_endorsements.has_value())
        {
          tss_map.set(
            "snp_endorsements",
            ctx.new_array_buffer_copy(phdr.tss_map.snp_endorsements.value()));
        }
        if (phdr.tss_map.uvm_endorsements.has_value())
        {
          tss_map.set(
            "uvm_endorsements",
            ctx.new_array_buffer_copy(phdr.tss_map.uvm_endorsements.value()));
        }
        if (phdr.tss_map.ver.has_value())
        {
          tss_map.set_int64("ver", phdr.tss_map.ver.value());
        }
        obj.set("attestedsvc", std::move(tss_map));
      }

      return obj;
    }

    static inline ccf::js::core::JSWrappedValue unprotected_header_to_js_val(
      ccf::js::core::Context& ctx, const scitt::cose::UnprotectedHeader uhdr)
    {
      auto obj = ctx.new_obj();

      if (uhdr.x5chain.has_value())
      {
        auto x5_array = ctx.new_array();
        size_t i = 0;

        for (const auto& der_cert : uhdr.x5chain.value())
        {
          auto pem = ccf::crypto::cert_der_to_pem(der_cert);
          x5_array.set_at_index(i++, ctx.new_string(pem.str()));
        }

        obj.set("x5chain", std::move(x5_array));
      }

      return obj;
    }

    static inline ccf::js::core::JSWrappedValue verified_details_to_js_val(
      ccf::js::core::Context& ctx,
      const std::optional<verifier::VerifiedSevSnpAttestationDetails>& details)
    {
      auto obj = ctx.new_obj();

      if (details.has_value())
      {
        const auto& measurement = details->get_measurement();
        obj.set("measurement", ctx.new_string(measurement.hex_str()));
        const auto& report_data = details->get_report_data();
        obj.set("report_data", ctx.new_string(report_data.hex_str()));
        auto host_data_str = ccf::ds::to_hex(details->get_host_data());
        obj.set("host_data", ctx.new_string(host_data_str));
        if (details->get_uvm_endorsements().has_value())
        {
          const auto& uvm_endorsements =
            details->get_uvm_endorsements().value();
          auto uvm_obj = ctx.new_obj();
          uvm_obj.set("did", ctx.new_string(uvm_endorsements.did));
          uvm_obj.set("feed", ctx.new_string(uvm_endorsements.feed));
          uvm_obj.set("svn", ctx.new_string(uvm_endorsements.svn));
          obj.set("uvm_endorsements", std::move(uvm_obj));
        }

        auto reported_tcb = ctx.new_obj();
        const auto& tcb = details->get_tcb_version_policy();
        if (tcb.microcode.has_value())
        {
          reported_tcb.set_uint32("microcode", tcb.microcode.value());
        }
        if (tcb.snp.has_value())
        {
          reported_tcb.set_uint32("snp", tcb.snp.value());
        }
        if (tcb.tee.has_value())
        {
          reported_tcb.set_uint32("tee", tcb.tee.value());
        }
        if (tcb.boot_loader.has_value())
        {
          reported_tcb.set_uint32("boot_loader", tcb.boot_loader.value());
        }
        if (tcb.fmc.has_value())
        {
          reported_tcb.set_uint32("fmc", tcb.fmc.value());
        }
        if (tcb.hexstring.has_value())
        {
          reported_tcb.set("hexstring", ctx.new_string(tcb.hexstring.value()));
        }
        obj.set("reported_tcb", std::move(reported_tcb));
        obj.set(
          "product_name",
          ctx.new_string(
            ccf::pal::snp::to_string(details->get_product_name())));
      }

      return obj;
    }

    static inline std::optional<std::string> apply_js_policy(
      const PolicyScript& script,
      const std::string& policy_name,
      const scitt::cose::ProtectedHeader& phdr,
      const scitt::cose::UnprotectedHeader& uhdr,
      std::span<uint8_t> payload,
      const std::optional<verifier::VerifiedSevSnpAttestationDetails>& details)
    {
      auto start = std::chrono::steady_clock::now();
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
        throw BadRequestCborError(
          scitt::errors::PolicyError,
          fmt::format("Invalid policy module: {}", e.what()));
      }

      auto phdr_val = protected_header_to_js_val(interpreter, phdr);
      auto uhdr_val = unprotected_header_to_js_val(interpreter, uhdr);
      auto payload_val = interpreter.new_array_buffer_copy(payload);
      auto details_val = verified_details_to_js_val(interpreter, details);

      const auto result = interpreter.call_with_rt_options(
        apply_func,
        {phdr_val, uhdr_val, payload_val, details_val},
        ccf::JSRuntimeOptions{
          10 * 1024 * 1024, // max_heap_bytes (10MB)
          1024 * 1024, // max_stack_bytes (1MB)
          1000, // max_execution_time_ms (1s)
          true, // log_exception_details
          false, // return_exception_details
          0, // max_cached_interpreters
        },
        // Limits defined explicitly above
        ccf::js::core::RuntimeLimitsPolicy::NONE);

      if (result.is_exception())
      {
        auto [reason, trace] = interpreter.error_message();

        throw BadRequestCborError(
          scitt::errors::PolicyError,
          fmt::format(
            "Error while applying policy: {}\n{}",
            reason,
            trace.value_or("<no trace>")));
      }

      if (result.is_str())
      {
        return interpreter.to_str(result);
      }

      // Note this does JS-style truthy conversion, so lots of truthy values may
      // become true here
      if (result.is_true())
      {
        return std::nullopt;
      }

      throw BadRequestCborError(
        scitt::errors::PolicyError,
        fmt::format(
          "Unexpected return value from policy: {}",
          interpreter.to_str(result)));
    }
  }

  // Returns nullopt for success, else a string describing why the policy was
  // refused. May also throw if given invalid policies, or policy execution
  // throws.
  static inline std::optional<std::string> check_for_policy_violations(
    const PolicyScript& script,
    const std::string& policy_name,
    const cose::ProtectedHeader& phdr,
    const cose::UnprotectedHeader& uhdr,
    std::span<uint8_t> payload,
    const std::optional<verifier::VerifiedSevSnpAttestationDetails>& details)
  {
    return js::apply_js_policy(
      script, policy_name, phdr, uhdr, payload, details);
  }

  using PolicyRego = std::string;

  static inline nlohmann::json rego_input_from_signed_statement(
    const cose::ProtectedHeader& phdr,
    std::span<uint8_t> payload,
    const std::optional<verifier::VerifiedSevSnpAttestationDetails>& details)
  {
    nlohmann::json rego_input;
    nlohmann::json cwt;
    // All integer labels registered with IANA are mapped to their name
    // https://www.iana.org/assignments/cwt/cwt.xhtml
    cwt["iss"] = phdr.cwt_claims.iss;
    cwt["sub"] = phdr.cwt_claims.sub;
    cwt["iat"] = phdr.cwt_claims.iat;
    // String labels such as "name" as prefixed with an underscore: "_name"
    cwt["_svn"] = phdr.cwt_claims.svn;
    nlohmann::json protected_header;
    // Same as above, but at the COSE level
    // https://www.iana.org/assignments/cose/cose.xhtml
    protected_header["CWT Claims"] = cwt;
    protected_header["alg"] = phdr.alg;
    if (phdr.cty.has_value())
    {
      if (std::holds_alternative<int64_t>(phdr.cty.value()))
      {
        protected_header["cty"] = std::get<int64_t>(phdr.cty.value());
      }
      else if (std::holds_alternative<std::string>(phdr.cty.value()))
      {
        protected_header["cty"] = std::get<std::string>(phdr.cty.value());
      }
    }
    // The COSE protected header is arbitrarily called phdr
    rego_input["phdr"] = protected_header;
    // Note: uhdr is deliberately not mapped, since the current agreement is to
    // manually expose only validated parts of the uhdr to policy, once there is
    // a use case.

    // Payload is exposed as a hex string, because rego has no byte array type.
    rego_input["payload"] = ccf::ds::to_hex(payload);

    // Attestation information where available is exposed as "attestation"
    if (details.has_value())
    {
      // Names match those defined in
      // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
      // Section 7.3 Attestation, Table 23, transformed to lower case
      nlohmann::json attestation;
      attestation["measurement"] = details->get_measurement().hex_str();
      attestation["report_data"] = details->get_report_data().hex_str();
      attestation["host_data"] = ccf::ds::to_hex(details->get_host_data());
      // Document in
      // https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64
      // Eventually expected to become a CWT Claims object
      if (details->get_uvm_endorsements().has_value())
      {
        const auto& uvm_endorsements = details->get_uvm_endorsements().value();
        nlohmann::json uvm;
        uvm["did"] = uvm_endorsements.did;
        uvm["feed"] = uvm_endorsements.feed;
        uvm["svn"] = uvm_endorsements.svn;
        attestation["uvm_endorsements"] = uvm;
      }
      nlohmann::json reported_tcb;
      const auto& tcb = details->get_tcb_version_policy();
      reported_tcb["microcode"] = tcb.microcode;
      reported_tcb["snp"] = tcb.snp;
      reported_tcb["tee"] = tcb.tee;
      reported_tcb["boot_loader"] = tcb.boot_loader;
      reported_tcb["fmc"] = tcb.fmc;
      reported_tcb["hexstring"] = tcb.hexstring;
      attestation["reported_tcb"] = reported_tcb;
      attestation["product_name"] =
        ccf::pal::snp::to_string(details->get_product_name());
      rego_input["attestation"] = attestation;
    }

    return rego_input;
  }

  static inline std::optional<std::string> check_for_policy_violations_rego(
    const PolicyRego& rego,
    const std::string& policy_name,
    const cose::ProtectedHeader& phdr,
    const cose::UnprotectedHeader& uhdr,
    std::span<uint8_t> payload,
    const std::optional<verifier::VerifiedSevSnpAttestationDetails>& details)
  {
    regorus::Engine engine;

    engine.add_policy("policy", rego.c_str());
    auto input = rego_input_from_signed_statement(phdr, payload, details);

    engine.set_input_json(input.dump().c_str());
    auto rego_rule_result = engine.eval_rule("data.policy.allow");

    if (!rego_rule_result)
    {
      throw BadRequestCborError(
        scitt::errors::PolicyError,
        fmt::format("Invalid policy module: {}", rego_rule_result.error()));
    }

    if (std::strcmp("true", rego_rule_result.output()) == 0)
    {
      return std::nullopt;
    }

    auto rego_errors = engine.eval_rule("data.policy.errors");
    if (!rego_errors)
    {
      return {"No error details exposed by policy"};
    }

    nlohmann::json errors = nlohmann::json::parse(rego_errors.output());
    if (errors.is_array() && !errors.empty())
    {
      std::string error_msg;
      for (const auto& element : errors)
      {
        if (!error_msg.empty())
        {
          error_msg += ", ";
        }
        if (element.is_string())
        {
          error_msg += element.get<std::string>();
        }
      }
      return error_msg;
    }

    return {"Could not obtain error details from policy"};
  }
}