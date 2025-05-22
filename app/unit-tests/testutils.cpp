// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdint>
#include <cstdlib>
#include <iomanip> // setw
#include <string>
#include <vector>

namespace testutils
{
  // Utility function to convert a vector of bytes to a hex string
  static std::string to_hex_string(const std::vector<uint8_t>& data)
  {
    std::ostringstream oss;
    for (auto byte : data)
    {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(byte);
    }
    return oss.str();
  }

  // Utility function to convert hex string to a vector of bytes
  static const int HEX_BASE = 16;
  static std::vector<uint8_t> from_hex_string(const std::string& hex)
  {
    // Check if string length is even
    if (hex.length() % 2 != 0)
    {
      throw std::invalid_argument(
        "Hex string must have an even number of characters");
    }

    // Validate all characters are valid hex digits
    for (char c : hex)
    {
      if (!std::isxdigit(c))
      {
        throw std::invalid_argument("Invalid hex character in string");
      }
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
      const std::string byteString = hex.substr(i, 2);
      char* end_ptr = nullptr;
      const long value = std::strtol(byteString.c_str(), &end_ptr, HEX_BASE);
      if (*end_ptr != '\0' || value < 0 || value > 255)
      {
        throw std::invalid_argument("Invalid hex value: " + byteString);
      }
      bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes;
  }
}