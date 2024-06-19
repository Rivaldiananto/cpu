#include "binToHex.h"
#include <stdexcept>

std::string binToHex(const std::string& bin) {
    static const char* const lut = "0123456789ABCDEF";
    size_t len = bin.length();

    if (len % 4 != 0) throw std::invalid_argument("Binary string length must be a multiple of 4");

    std::string hex;
    hex.reserve(len / 4);

    for (size_t i = 0; i < len; i += 4) {
        int nibble = (bin[i] - '0') << 3 | (bin[i + 1] - '0') << 2 | (bin[i + 2] - '0') << 1 | (bin[i + 3] - '0');
        hex.push_back(lut[nibble]);
    }

    return hex;
}
