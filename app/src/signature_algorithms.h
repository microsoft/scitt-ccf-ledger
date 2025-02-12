// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <fmt/format.h>
#include <stdexcept>
#include <string_view>

namespace scitt
{
  static constexpr int64_t COSE_ALGORITHM_ES256 = -7;
  static constexpr int64_t COSE_ALGORITHM_EDDSA = -8;
  static constexpr int64_t COSE_ALGORITHM_ES384 = -35;
  static constexpr int64_t COSE_ALGORITHM_ES512 = -36;
  static constexpr int64_t COSE_ALGORITHM_PS256 = -37;
  static constexpr int64_t COSE_ALGORITHM_PS384 = -38;
  static constexpr int64_t COSE_ALGORITHM_PS512 = -39;

  static constexpr std::string_view JOSE_ALGORITHM_ES256 = "ES256";
  static constexpr std::string_view JOSE_ALGORITHM_EDDSA = "EdDSA";
  static constexpr std::string_view JOSE_ALGORITHM_ES384 = "ES384";
  static constexpr std::string_view JOSE_ALGORITHM_ES512 = "ES512";
  static constexpr std::string_view JOSE_ALGORITHM_PS256 = "PS256";
  static constexpr std::string_view JOSE_ALGORITHM_PS384 = "PS384";
  static constexpr std::string_view JOSE_ALGORITHM_PS512 = "PS512";

  struct InvalidSignatureAlgorithm : public std::runtime_error
  {
    InvalidSignatureAlgorithm(const std::string& msg) : std::runtime_error(msg)
    {}
  };

  [[maybe_unused]] static std::string_view get_jose_alg_from_cose_alg(
    int64_t cose_alg)
  {
    switch (cose_alg)
    {
      case COSE_ALGORITHM_ES256:
        return JOSE_ALGORITHM_ES256;
      case COSE_ALGORITHM_ES384:
        return JOSE_ALGORITHM_ES384;
      case COSE_ALGORITHM_ES512:
        return JOSE_ALGORITHM_ES512;
      case COSE_ALGORITHM_PS256:
        return JOSE_ALGORITHM_PS256;
      case COSE_ALGORITHM_PS384:
        return JOSE_ALGORITHM_PS384;
      case COSE_ALGORITHM_PS512:
        return JOSE_ALGORITHM_PS512;
      case COSE_ALGORITHM_EDDSA:
        return JOSE_ALGORITHM_EDDSA;
      default:
        throw InvalidSignatureAlgorithm(
          fmt::format("COSE algorithm {} is not supported", cose_alg));
    }
  }
}
