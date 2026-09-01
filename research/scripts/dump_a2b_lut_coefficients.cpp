// Reproduce the runtime-generated p=16, order-1 A2B LUT coefficients from
// fhe-simd-alu without linking OpenFHE. The floating-point operation order,
// threshold, M_PI use, and BigFixedPoint::fromDouble conversion intentionally
// mirror the pinned upstream sources.

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using boost::multiprecision::cpp_int;

constexpr std::uint32_t kP = 16;
constexpr int kFixedPointBits = 128;

struct FixedPoint {
    cpp_int magnitude;
    bool negative;
};

bool IsNotEqualZero(std::complex<double> value) {
    constexpr double delta = 0x1p-32;
    return std::fabs(value.real()) >= delta || std::fabs(value.imag()) >= delta;
}

std::vector<std::complex<double>> GetHermiteTrigCoefficients(
    const std::function<std::int64_t(std::int64_t)>& function,
    std::uint32_t p,
    double scale) {
    using namespace std::complex_literals;

    std::uint32_t degree = 0;
    std::vector<std::complex<double>> coefficients(p);
    for (std::uint32_t i = 0; i < p; ++i) {
        for (std::uint32_t j = 0; j < p; ++j) {
            coefficients[i] += static_cast<double>(function(j)) *
                               std::exp((-2. * M_PI * i * j / p) * 1i);
        }
        coefficients[i] *= static_cast<double>(p - i) /
                           static_cast<double>(p * p) / scale;
        if (IsNotEqualZero(coefficients[i])) {
            degree = i;
        }
    }
    coefficients[0] /= 2.0;
    coefficients.resize(degree + 1);
    return coefficients;
}

FixedPoint FromDouble(double value) {
    bool negative = false;
    if (value < 0) {
        negative = true;
        value = -value;
    }

    int log2_scale = 0;
    double integer_part = 0;
    double fractional_part = std::modf(value, &integer_part);
    while (fractional_part != 0.0 && log2_scale < kFixedPointBits) {
        value *= 2.0;
        fractional_part = std::modf(value, &integer_part);
        ++log2_scale;
    }

    const double rounded = std::round(value);
    if (rounded > static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
        throw std::overflow_error("BigFixedPoint::fromDouble int64 conversion overflow");
    }
    cpp_int magnitude(static_cast<std::int64_t>(rounded));
    if (log2_scale < kFixedPointBits) {
        magnitude <<= (kFixedPointBits - log2_scale);
    } else if (log2_scale > kFixedPointBits) {
        magnitude >>= (log2_scale - kFixedPointBits);
    }
    return {magnitude, negative};
}

std::string SignedNumerator(const FixedPoint& value) {
    if (value.negative && value.magnitude != 0) {
        return "-" + value.magnitude.convert_to<std::string>();
    }
    return value.magnitude.convert_to<std::string>();
}

double EvaluateRealPart(const std::vector<std::complex<double>>& coefficients,
                        std::uint32_t point) {
    using namespace std::complex_literals;
    const std::complex<double> root =
        std::exp((2. * M_PI * point / kP) * 1i);
    std::complex<double> power = 1.0;
    std::complex<double> value = 0.0;
    for (const auto& coefficient : coefficients) {
        value += coefficient * power;
        power *= root;
    }
    return 2.0 * value.real();
}

void EmitCanonical(const std::string& name,
                   const std::vector<std::complex<double>>& coefficients) {
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        const FixedPoint real = FromDouble(coefficients[i].real());
        const FixedPoint imaginary = FromDouble(coefficients[i].imag());
        std::cout << name << '\t' << i << '\t'
                  << SignedNumerator(real) << '\t'
                  << SignedNumerator(imaginary) << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    const auto msb = GetHermiteTrigCoefficients(
        [](std::int64_t x) -> std::int64_t {
            return x <= kP / 2 && x != 0 ? 1 : 0;
        },
        kP,
        1.0);
    const auto identity = GetHermiteTrigCoefficients(
        [](std::int64_t x) -> std::int64_t {
            return x == 0 ? 0 : x - kP;
        },
        kP,
        static_cast<double>(kP));

    if (argc == 2 && std::string(argv[1]) == "--canonical") {
        EmitCanonical("msb", msb);
        EmitCanonical("id", identity);
        return 0;
    }
    if (argc != 1) {
        std::cerr << "usage: dump_a2b_lut_coefficients [--canonical]\n";
        return 2;
    }

    double max_msb_error = 0.0;
    double max_id_error = 0.0;
    for (std::uint32_t point = 0; point < kP; ++point) {
        const double want_msb = point <= kP / 2 && point != 0 ? 1.0 : 0.0;
        const double want_id = point == 0 ? 0.0 :
            static_cast<double>(static_cast<std::int64_t>(point) - kP) / kP;
        max_msb_error = std::max(
            max_msb_error,
            std::fabs(EvaluateRealPart(msb, point) - want_msb));
        max_id_error = std::max(
            max_id_error,
            std::fabs(EvaluateRealPart(identity, point) - want_id));
    }

    std::cout << "generator=fhe-simd-alu-p16-order1-a2b-lut\n"
              << "fixed_point_bits=" << kFixedPointBits << '\n'
              << "pi_hex=" << std::hexfloat << M_PI << std::defaultfloat << '\n'
              << "msb_degree=" << (msb.size() - 1) << '\n'
              << "id_degree=" << (identity.size() - 1) << '\n'
              << std::setprecision(17)
              << "max_msb_grid_error=" << max_msb_error << '\n'
              << "max_id_grid_error=" << max_id_error << '\n';
    EmitCanonical("msb", msb);
    EmitCanonical("id", identity);
    return 0;
}
