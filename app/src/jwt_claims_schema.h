// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/ds/json.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

namespace scitt
{
  inline constexpr auto JWT_SCHEMA_DRAFT =
    "http://json-schema.org/draft-07/schema#";

  class JwtClaimsSchema
  {
    std::optional<nlohmann::json> loaded_schema;
    std::unique_ptr<valijson::Schema> parsed_schema;
    valijson::Validator validator;

  public:
    bool validate(
      const nlohmann::json& schema,
      const nlohmann::json& claims,
      std::string& error_reason)
    {
      if (
        !schema.is_object() || !schema.contains("$schema") ||
        !schema.at("$schema").is_string() ||
        schema.at("$schema") != JWT_SCHEMA_DRAFT)
      {
        error_reason = "Unsupported JWT claims schema";
        return false;
      }

      try
      {
        if (!loaded_schema.has_value() || *loaded_schema != schema)
        {
          auto next = std::make_unique<valijson::Schema>();
          valijson::SchemaParser parser;
          valijson::adapters::NlohmannJsonAdapter adapter(schema);
          parser.populateSchema(adapter, *next);
          parsed_schema = std::move(next);
          loaded_schema = schema;
        }

        valijson::adapters::NlohmannJsonAdapter adapter(claims);
        if (!validator.validate(*parsed_schema, adapter, nullptr))
        {
          error_reason = "JWT claims do not match the schema";
          return false;
        }
        return true;
      }
      catch (const std::runtime_error& e)
      {
        error_reason = std::string("Invalid JWT claims schema: ") + e.what();
        return false;
      }
      catch (const std::logic_error& e)
      {
        error_reason = std::string("Invalid JWT claims schema: ") + e.what();
        return false;
      }
    }
  };
}
