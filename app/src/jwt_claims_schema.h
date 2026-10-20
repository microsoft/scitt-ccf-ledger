// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ccf/ds/json.h>
#include <cmath>
#include <cstdint>
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

    static bool equal_integer_and_float(
      const nlohmann::json& integer, double number)
    {
      if (
        !std::isfinite(number) || std::trunc(number) != number ||
        std::abs(number) >= std::ldexp(1.0, 53))
      {
        return false;
      }

      if (integer.is_number_unsigned())
      {
        return number >= 0 && number < std::ldexp(1.0, 64) &&
          static_cast<uint64_t>(number) == integer.get<uint64_t>();
      }
      return number >= -std::ldexp(1.0, 63) && number < std::ldexp(1.0, 63) &&
        static_cast<int64_t>(number) == integer.get<int64_t>();
    }

    static bool equal_const(
      const nlohmann::json& actual, const nlohmann::json& expected)
    {
      if (actual.is_number() && expected.is_number())
      {
        if (
          (actual.is_number_float() &&
           std::abs(actual.get<double>()) >= std::ldexp(1.0, 53)) ||
          (expected.is_number_float() &&
           std::abs(expected.get<double>()) >= std::ldexp(1.0, 53)))
        {
          return false;
        }
        if (actual.is_number_float() && expected.is_number_integer())
        {
          return equal_integer_and_float(expected, actual.get<double>());
        }
        if (expected.is_number_float() && actual.is_number_integer())
        {
          return equal_integer_and_float(actual, expected.get<double>());
        }
        if (
          actual.is_number_integer() && expected.is_number_integer() &&
          actual.is_number_unsigned() != expected.is_number_unsigned())
        {
          const auto& signed_value =
            actual.is_number_unsigned() ? expected : actual;
          const auto& unsigned_value =
            actual.is_number_unsigned() ? actual : expected;
          return signed_value.get<int64_t>() >= 0 &&
            static_cast<uint64_t>(signed_value.get<int64_t>()) ==
            unsigned_value.get<uint64_t>();
        }
        return actual == expected;
      }

      if (actual.type() != expected.type())
      {
        return false;
      }
      if (actual.is_array())
      {
        if (actual.size() != expected.size())
        {
          return false;
        }
        for (size_t i = 0; i < actual.size(); ++i)
        {
          if (!equal_const(actual[i], expected[i]))
          {
            return false;
          }
        }
        return true;
      }
      if (actual.is_object())
      {
        if (actual.size() != expected.size())
        {
          return false;
        }
        for (const auto& [key, value] : expected.items())
        {
          auto it = actual.find(key);
          if (it == actual.end() || !equal_const(*it, value))
          {
            return false;
          }
        }
        return true;
      }
      return actual == expected;
    }

    static bool matches_consts(
      const nlohmann::json& branch, const nlohmann::json& claims)
    {
      auto properties = branch.find("properties");
      if (properties == branch.end())
      {
        return true;
      }
      if (!properties->is_object())
      {
        return false;
      }
      for (const auto& [key, property] : properties->items())
      {
        auto claim = claims.find(key);
        if (
          !property.is_object() || !property.contains("const") ||
          claim == claims.end() || !equal_const(*claim, property.at("const")))
        {
          return false;
        }
      }
      return true;
    }

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
        bool valid = validator.validate(*parsed_schema, adapter, nullptr) &&
          matches_consts(schema, claims);
        if (valid && schema.contains("anyOf"))
        {
          valid = false;
          for (const auto& branch : schema.at("anyOf"))
          {
            if (matches_consts(branch, claims))
            {
              valid = true;
              break;
            }
          }
        }
        if (!valid)
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
