#include "openfhe.h"
#include "encoding/z-encoding.h"
#include "scheme/ckksrns/z-fhe.h"
#include "scheme/ckksrns/z-pke.h"
#include "scheme/ckksrns/z-user.h"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

constexpr uint32_t kWordBits = 8;
constexpr uint32_t kUsefulWords = 8192;
constexpr uint32_t kPackingSlots = kWordBits * kUsefulWords / 2;
constexpr uint32_t kRingDimension = 1U << 16;
constexpr uint32_t kWarmupCount = 1;
constexpr uint32_t kRepeatCount = 5;
constexpr uint32_t kQModuliCount = 21;
constexpr uint32_t kQLog2Aggregate = 904;
constexpr uint32_t kPModuliCount = 7;
constexpr uint32_t kPLog2Aggregate = 350;
constexpr uint32_t kScalingModulusBits = 43;
constexpr uint32_t kFirstModulusBits = 43;
constexpr uint32_t kMultiplicativeDepth = 20;
constexpr uint32_t kLargeDigits = 3;
constexpr uint32_t kMainSecretHammingWeight = 192;
constexpr uint32_t kEphemeralSecretHammingWeight = 32;
constexpr uint32_t kRNSDecompositionComponents = 3;
constexpr uint32_t kBaseTwoDecomposition = 0;
constexpr double kErrorSigma = 3.19;
constexpr uint32_t kErrorEffectiveIntegerBound = 39;
constexpr uint32_t kChunkWidth = 4;
constexpr int32_t kCutoffBits = -24;
constexpr char kSourceRevision[] = "08f1eb87434e7be072cba889270a8400bbffc08e";
constexpr char kRuntime[] = "OpenFHE-1.4.0;HEXL-1.2.6";
constexpr char kBuildProfile[] = "CMAKE_BUILD_TYPE=Release;CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=6;OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_NTL=ON;WITH_TCM=ON;WITH_OPENMP=ON;OMP_NUM_THREADS=1";

struct Options {
    std::string hostId;
    std::string outputPath;
    bool checkParametersOnly = false;
};

struct RuntimeModulusProfile {
    uint32_t qCount;
    uint32_t qBits;
    uint32_t pCount;
    uint32_t pBits;
    uint32_t actualFirstQModulusBits;
    double errorSigma;
    uint32_t rnsDecompositionComponents;
    std::vector<std::string> qModuli;
    std::vector<uint32_t> qModuliBitLengths;
    std::vector<std::string> pModuli;
    std::vector<uint32_t> pModuliBitLengths;
};

struct ExecutionMetadata {
    std::string sourceRevision;
    bool sourceModified;
    std::string compiler;
    std::string buildProfile;
    std::string os;
    std::string arch;
};

struct Verification {
    uint64_t checkedBits = 0;
    uint64_t mismatchCount = 0;
};

uint64_t ElapsedNanoseconds(std::chrono::steady_clock::time_point start,
                            std::chrono::steady_clock::time_point finish) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count());
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream output;
    for (unsigned char character : value) {
        switch (character) {
            case '\"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (character < 0x20) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<unsigned int>(character) << std::dec << std::setfill(' ');
                }
                else {
                    output << static_cast<char>(character);
                }
        }
    }
    return output.str();
}

std::string JsonStringArray(const std::vector<std::string>& values) {
    std::ostringstream output;
    output << '[';
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << '"' << JsonEscape(values[index]) << '"';
    }
    output << ']';
    return output.str();
}

std::string JsonUIntArray(const std::vector<uint32_t>& values) {
    std::ostringstream output;
    output << '[';
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << values[index];
    }
    output << ']';
    return output.str();
}

std::string RequireEnvironment(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        throw std::runtime_error(std::string(name) + " must be supplied by run_wsl.sh");
    }
    return value;
}

ExecutionMetadata RequireExecutionMetadata() {
    ExecutionMetadata metadata{
        RequireEnvironment("LCPDTE_GAO_SOURCE_REVISION"),
        false,
        RequireEnvironment("LCPDTE_GAO_COMPILER"),
        RequireEnvironment("LCPDTE_GAO_BUILD_PROFILE"),
        RequireEnvironment("LCPDTE_GAO_OS"),
        RequireEnvironment("LCPDTE_GAO_ARCH"),
    };
    const auto sourceModified = RequireEnvironment("LCPDTE_GAO_SOURCE_MODIFIED");
    if (metadata.sourceRevision != kSourceRevision) {
        throw std::runtime_error("execution metadata source revision differs from the pinned checkout");
    }
    if (sourceModified != "false") {
        throw std::runtime_error("execution metadata requires an unmodified pinned source");
    }
    if (metadata.buildProfile != kBuildProfile) {
        throw std::runtime_error("execution metadata build profile differs from the acceptance configuration");
    }
    if (RequireEnvironment("OMP_NUM_THREADS") != "1") {
        throw std::runtime_error("OMP_NUM_THREADS must be exactly 1");
    }
    if (metadata.compiler.find("/usr/bin/clang++ :: ") != 0 ||
        metadata.compiler.find("clang version 14.") == std::string::npos) {
        throw std::runtime_error("execution metadata requires cached /usr/bin/clang++ Clang 14");
    }
    if (metadata.os != "linux" || metadata.arch != "amd64") {
        throw std::runtime_error("execution metadata requires the admitted linux/amd64 build target");
    }
    return metadata;
}

Options ParseOptions(int argc, char* argv[]) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if ((argument == "-host-id" || argument == "--host-id" || argument == "-out" ||
             argument == "--output") &&
            index + 1 >= argc) {
            throw std::invalid_argument(argument + " requires a value");
        }
        if (argument == "-host-id" || argument == "--host-id") {
            options.hostId = argv[++index];
        }
        else if (argument == "-out" || argument == "--output") {
            options.outputPath = argv[++index];
        }
        else if (argument == "--check-parameters-only") {
            options.checkParametersOnly = true;
        }
        else if (argument == "--help" || argument == "-h") {
            std::cout << "Usage: " << argv[0]
                      << " -host-id ID [-out RESULT.json] [--check-parameters-only]\n";
            std::exit(0);
        }
        else {
            throw std::invalid_argument("unknown argument: " + argument);
        }
    }
    if (options.hostId.empty()) {
        throw std::invalid_argument("-host-id must be a non-empty string");
    }
    return options;
}

Verification VerifyAllBits(CiphertextGroup ciphertexts, const PKEZ& pke,
                           const std::vector<uint8_t>& expectedWords) {
    if (ciphertexts.size() != 2) {
        throw std::runtime_error("full Boolean output must contain low4 and high4 ciphertexts");
    }
    const auto decoded = pke->Decrypt(ciphertexts);
    if (decoded.size() != expectedWords.size()) {
        throw std::runtime_error("full Boolean output word count differs from the canonical workload");
    }

    Verification verification;
    uint32_t printedMismatches = 0;
    for (size_t word = 0; word < expectedWords.size(); ++word) {
        const auto observedWord = decoded[word].ConvertToInt();
        for (size_t bit = 0; bit < kWordBits; ++bit) {
            const auto observed = static_cast<uint64_t>((observedWord >> bit) & 1U);
            const auto expected = static_cast<uint64_t>((expectedWords[word] >> bit) & 1U);
            ++verification.checkedBits;
            if (observed != expected) {
                ++verification.mismatchCount;
                if (printedMismatches < 8) {
                    std::cerr << "mismatch word=" << word << " bit=" << bit
                              << " expected=" << expected << " observed=" << observed << '\n';
                    ++printedMismatches;
                }
            }
        }
    }
    return verification;
}

RuntimeModulusProfile RequireCanonicalRuntimeParameters(
    const std::shared_ptr<CryptoParametersCKKSRNS>& cryptoParameters) {
    if (!cryptoParameters) {
        throw std::runtime_error("CKKS crypto parameters are unavailable");
    }
    const auto paramsQ = cryptoParameters->GetElementParams();
    const auto paramsP = cryptoParameters->GetParamsP();
    if (!paramsQ || !paramsP) {
        throw std::runtime_error("CKKS Q/P parameters are unavailable");
    }
    const auto qCount = static_cast<uint32_t>(paramsQ->GetParams().size());
    const auto pCount = static_cast<uint32_t>(paramsP->GetParams().size());
    const auto qBits = static_cast<uint32_t>(paramsQ->GetModulus().GetMSB());
    const auto pBits = static_cast<uint32_t>(paramsP->GetModulus().GetMSB());
    if (qCount != kQModuliCount || qBits != kQLog2Aggregate ||
        pCount != kPModuliCount || pBits != kPLog2Aggregate) {
        std::ostringstream message;
        message << "generated modulus profile Q=" << qCount << "/" << qBits
                << " P=" << pCount << "/" << pBits << "; want Q="
                << kQModuliCount << "/" << kQLog2Aggregate << " P="
                << kPModuliCount << "/" << kPLog2Aggregate;
        throw std::runtime_error(message.str());
    }
    if (cryptoParameters->GetSecretKeyDist() != SPARSE_ENCAPSULATED) {
        throw std::runtime_error(
            "SPARSE_ENCAPSULATED is required for the weight-32 bootstrap key");
    }
    const auto errorSigma = static_cast<double>(cryptoParameters->GetDistributionParameter());
    if (std::abs(errorSigma - kErrorSigma) > 1e-6) {
        throw std::runtime_error("OpenFHE runtime error sigma differs from 3.19");
    }
    if (cryptoParameters->GetKeySwitchTechnique() != HYBRID) {
        throw std::runtime_error("OpenFHE runtime key switching is not HYBRID");
    }
    if (cryptoParameters->GetDigitSize() != kBaseTwoDecomposition) {
        throw std::runtime_error("OpenFHE runtime base-two decomposition is not zero");
    }
    const auto rnsDecompositionComponents = cryptoParameters->GetNumPartQ();
    if (rnsDecompositionComponents != kRNSDecompositionComponents) {
        throw std::runtime_error("OpenFHE runtime HYBRID decomposition does not have three components");
    }
    if (cryptoParameters->GetStdLevel() != HEStd_128_classic) {
        throw std::runtime_error("OpenFHE runtime security selector is not HEStd_128_classic");
    }

    RuntimeModulusProfile profile{qCount, qBits, pCount, pBits};
    profile.actualFirstQModulusBits =
        static_cast<uint32_t>(paramsQ->GetParams().front()->GetModulus().GetMSB());
    profile.errorSigma = errorSigma;
    profile.rnsDecompositionComponents = rnsDecompositionComponents;
    profile.qModuli.reserve(qCount);
    profile.qModuliBitLengths.reserve(qCount);
    for (const auto& parameter : paramsQ->GetParams()) {
        const auto& modulus = parameter->GetModulus();
        profile.qModuli.push_back(modulus.ToString());
        profile.qModuliBitLengths.push_back(static_cast<uint32_t>(modulus.GetMSB()));
    }
    profile.pModuli.reserve(pCount);
    profile.pModuliBitLengths.reserve(pCount);
    for (const auto& parameter : paramsP->GetParams()) {
        const auto& modulus = parameter->GetModulus();
        profile.pModuli.push_back(modulus.ToString());
        profile.pModuliBitLengths.push_back(static_cast<uint32_t>(modulus.GetMSB()));
    }
    return profile;
}

std::string BuildArtifact(const Options& options, const ExecutionMetadata& metadata,
                          const RuntimeModulusProfile& runtimeProfile,
                          uint64_t setupNanoseconds,
                          const std::vector<uint64_t>& samples, bool warmupVerified,
                          uint32_t verifiedEvaluations, uint64_t mismatchCount) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\": \"lcpdte-ckksint-a2b-benchmark-v3\",\n"
           << "  \"implementation\": \"gao-openfhe-a2b-full\",\n"
           << "  \"host_id\": \"" << JsonEscape(options.hostId) << "\",\n"
           << "  \"encryption_mode\": \"public-key\",\n"
           << "  \"factor_storage_mode\": \"resident-precomputed\",\n"
           << "  \"scale_schedule\": \"openfhe-flexiblemanual-native\",\n"
           << "  \"backend_bsgs_plan\": \"openfhe-auto-dim1-0\",\n"
           << "  \"source_revision\": \"" << JsonEscape(metadata.sourceRevision) << "\",\n"
           << "  \"source_modified\": " << (metadata.sourceModified ? "true" : "false") << ",\n"
           << "  \"runtime\": \"" << kRuntime << "\",\n"
           << "  \"compiler\": \"" << JsonEscape(metadata.compiler) << "\",\n"
           << "  \"build_profile\": \"" << JsonEscape(metadata.buildProfile) << "\",\n"
           << "  \"os\": \"" << JsonEscape(metadata.os) << "\",\n"
           << "  \"arch\": \"" << JsonEscape(metadata.arch) << "\",\n"
           << "  \"protocol\": \"gao-a2b-full-z8-w4-v1\",\n"
           << "  \"workload_id\": \"uint8-0to255-x32\",\n"
           << "  \"packing_id\": \"n65536-cslots32768-zslots8192-w4\",\n"
           << "  \"output_container\": \"two-ciphertexts-low4-high4\",\n"
           << "  \"word_bits\": " << kWordBits << ",\n"
           << "  \"ring_dimension\": " << kRingDimension << ",\n"
           << "  \"packing_slots\": " << kPackingSlots << ",\n"
           << "  \"useful_words\": " << kUsefulWords << ",\n"
           << "  \"parameters\": {\n"
           << "    \"comparison_scope\": \"gao-algorithm-exact-q-p-and-numerical-parameters\",\n"
           << "    \"q_moduli_count\": " << kQModuliCount << ",\n"
           << "    \"q_log2_aggregate\": " << kQLog2Aggregate << ",\n"
           << "    \"p_moduli_count\": " << kPModuliCount << ",\n"
           << "    \"p_log2_aggregate\": " << kPLog2Aggregate << ",\n"
           << "    \"scaling_modulus_bits\": " << kScalingModulusBits << ",\n"
           << "    \"first_modulus_bits\": " << kFirstModulusBits << ",\n"
           << "    \"multiplicative_depth\": " << kMultiplicativeDepth << ",\n"
           << "    \"large_digits\": " << kLargeDigits << ",\n"
           << "    \"main_secret_hamming_weight\": " << kMainSecretHammingWeight << ",\n"
           << "    \"ephemeral_secret_hamming_weight\": "
           << kEphemeralSecretHammingWeight << ",\n"
           << "    \"rns_decomposition_components\": "
           << kRNSDecompositionComponents << ",\n"
           << "    \"base_two_decomposition\": " << kBaseTwoDecomposition << ",\n"
           << "    \"level_budget\": [3, 2],\n"
           << "    \"openfhe_requested_bsgs_dimensions\": [0, 0],\n"
           << "    \"chunk_width\": " << kChunkWidth << ",\n"
           << "    \"cutoff_bits\": " << kCutoffBits << "\n"
           << "  },\n"
           << "  \"native_parameters\": {\n"
           << "    \"actual_first_q_modulus_bits\": "
           << runtimeProfile.actualFirstQModulusBits << ",\n"
           << "    \"main_secret_distribution\": \"balanced-sparse-ternary\",\n"
           << "    \"main_secret_hamming_weight\": " << kMainSecretHammingWeight << ",\n"
           << "    \"ephemeral_secret_distribution\": \"balanced-sparse-ternary\",\n"
           << "    \"ephemeral_secret_hamming_weight\": "
           << kEphemeralSecretHammingWeight << ",\n"
           << "    \"error_sampler\": \"openfhe-dgg\",\n"
           << "    \"error_sigma\": " << runtimeProfile.errorSigma << ",\n"
           << "    \"error_configured_bound\": null,\n"
           << "    \"error_effective_integer_bound\": "
           << kErrorEffectiveIntegerBound << ",\n"
           << "    \"key_switch_technique\": \"openfhe-hybrid\",\n"
           << "    \"key_switch_rns_decomposition_components\": "
           << runtimeProfile.rnsDecompositionComponents << ",\n"
           << "    \"key_switch_base_two_decomposition\": "
           << kBaseTwoDecomposition << ",\n"
           << "    \"security_selector\": \"HEStd_128_classic\",\n"
           << "    \"security_evidence\": \"openfhe-he-standard-ternary-table\",\n"
           << "    \"q_moduli\": " << JsonStringArray(runtimeProfile.qModuli) << ",\n"
           << "    \"q_moduli_bit_lengths\": "
           << JsonUIntArray(runtimeProfile.qModuliBitLengths) << ",\n"
           << "    \"p_moduli\": " << JsonStringArray(runtimeProfile.pModuli) << ",\n"
           << "    \"p_moduli_bit_lengths\": "
           << JsonUIntArray(runtimeProfile.pModuliBitLengths) << "\n"
           << "  },\n"
           << "  \"threads\": 1,\n"
           << "  \"timing_scope\": \"prepared-online\",\n"
           << "  \"setup_nanoseconds\": " << setupNanoseconds << ",\n"
           << "  \"warmup_count\": " << kWarmupCount << ",\n"
           << "  \"repeat_count\": " << kRepeatCount << ",\n"
           << "  \"timed_samples_nanoseconds\": [";
    for (size_t index = 0; index < samples.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << samples[index];
    }
    output << "],\n"
           << "  \"warmup_verified\": " << (warmupVerified ? "true" : "false") << ",\n"
           << "  \"verified_evaluations\": " << verifiedEvaluations << ",\n"
           << "  \"mismatch_count\": " << mismatchCount << "\n"
           << "}\n";
    return output.str();
}

void WriteArtifact(const std::string& document, const std::string& outputPath) {
    if (outputPath.empty()) {
        std::cout << document;
        return;
    }
    std::ofstream output(outputPath, std::ios::out | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("cannot open output file: " + outputPath);
    }
    output << document;
    if (!output) {
        throw std::runtime_error("cannot write output file: " + outputPath);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const Options options = ParseOptions(argc, argv);
        const auto executionMetadata = RequireExecutionMetadata();
        if (OpenFHEParallelControls.GetMachineThreads() != 1) {
            throw std::runtime_error("OMP_NUM_THREADS must be set to 1 before process startup");
        }
        OpenFHEParallelControls.Disable();

        std::vector<uint8_t> expectedWords(kUsefulWords);
        std::vector<BigInteger> inputWords(kUsefulWords, 0);
        for (size_t index = 0; index < kUsefulWords; ++index) {
            expectedWords[index] = static_cast<uint8_t>(index % 256);
            inputWords[index] = expectedWords[index];
        }

        const auto setupStart = std::chrono::steady_clock::now();

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(lbcrypto::SPARSE_ENCAPSULATED);
        parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetRingDim(kRingDimension);
        parameters.SetScalingModSize(kScalingModulusBits);
        parameters.SetFirstModSize(kFirstModulusBits);
        parameters.SetScalingTechnique(FLEXIBLEMANUAL);
        parameters.SetNumLargeDigits(kLargeDigits);
        parameters.SetMultiplicativeDepth(kMultiplicativeDepth);
        AUXMODSIZE_FLEXIBLEMANUAL = 50;

        CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
        const auto cryptoParameters =
            std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
        const auto runtimeProfile = RequireCanonicalRuntimeParameters(cryptoParameters);
        if (options.checkParametersOnly) {
            std::cout << "validated canonical OpenFHE parameters: Q=" << runtimeProfile.qCount
                      << "/" << runtimeProfile.qBits << " P=" << runtimeProfile.pCount << "/"
                      << runtimeProfile.pBits << " scale=" << kScalingModulusBits
                      << " first=" << kFirstModulusBits
                      << " depth=" << kMultiplicativeDepth
                      << " large_digits=" << kLargeDigits
                      << " main_weight=" << kMainSecretHammingWeight
                      << " ephemeral_weight=" << kEphemeralSecretHammingWeight
                      << " actual_first_q=" << runtimeProfile.actualFirstQModulusBits
                      << " error_sigma=" << kErrorSigma
                      << " key_switch=openfhe-hybrid"
                      << " base_two_decomposition=" << kBaseTwoDecomposition
                      << " security=HEStd_128_classic"
                      << " level_budget=[3,2] openfhe_requested_bsgs=[0,0]"
                      << " backend_bsgs_plan=openfhe-auto-dim1-0 w=" << kChunkWidth
                      << " cutoff=" << kCutoffBits << '\n';
            return 0;
        }
        context->Enable(PKE);
        context->Enable(KEYSWITCH);
        context->Enable(LEVELEDSHE);

        auto keyPair = context->KeyGen();
        context->EvalMultKeyGen(keyPair.secretKey);

        LeveledZ leveled = std::make_shared<LeveledZImpl>();
        AdvancedZ advanced = std::make_shared<AdvancedZImpl>(leveled);
        FHEZ fhe = std::make_shared<FHEZImpl>(leveled, advanced);
        PKEZ pke = std::make_shared<PKEZImpl>(keyPair.publicKey, keyPair.secretKey);
        pkeZ_global = pke;

        fhe->EvalBootstrapSetup(*context, kWordBits, kUsefulWords, {3, 2}, {0, 0},
                                kChunkWidth, kCutoffBits, 1);
        fhe->EvalBootstrapKeyGen(keyPair.secretKey, kWordBits, kUsefulWords);

        const auto elementParameters = context->GetCryptoParameters()->GetElementParams();
        const auto scalingFactor = cryptoParameters->GetScalingFactorBFP(0);
        auto encodedInput =
            ZEncodingImpl::encodeArith(inputWords, kWordBits, kUsefulWords, elementParameters, scalingFactor);
        auto encryptedInput = pke->Encrypt(encodedInput);

        const auto setupFinish = std::chrono::steady_clock::now();
        const uint64_t setupNanoseconds = ElapsedNanoseconds(setupStart, setupFinish);
        std::cerr << "setup complete in " << setupNanoseconds << " ns\n";

        uint64_t mismatchCount = 0;
        uint32_t verifiedEvaluations = 0;

        bool warmupVerified = false;
        {
            auto warmupOutput = fhe->EvalArithToBooleanFull(encryptedInput);
            const auto verification = VerifyAllBits(warmupOutput, pke, expectedWords);
            mismatchCount += verification.mismatchCount;
            warmupVerified = verification.checkedBits == kWordBits * kUsefulWords &&
                             verification.mismatchCount == 0;
            std::cerr << "warmup verified: " << verification.checkedBits << " bits, "
                      << verification.mismatchCount << " mismatches\n";
        }
        if (!warmupVerified) {
            throw std::runtime_error("full A2B warmup correctness failed");
        }

        std::vector<uint64_t> samples;
        samples.reserve(kRepeatCount);
        for (uint32_t repeat = 0; repeat < kRepeatCount; ++repeat) {
            const auto onlineStart = std::chrono::steady_clock::now();
            auto output = fhe->EvalArithToBooleanFull(encryptedInput);
            const auto onlineFinish = std::chrono::steady_clock::now();
            samples.push_back(ElapsedNanoseconds(onlineStart, onlineFinish));

            const auto verification = VerifyAllBits(output, pke, expectedWords);
            mismatchCount += verification.mismatchCount;
            ++verifiedEvaluations;
            std::cerr << "sample " << (repeat + 1) << ": " << samples.back()
                      << " ns; verified " << verification.checkedBits << " bits, "
                      << verification.mismatchCount << " mismatches\n";
            if (verification.checkedBits != kWordBits * kUsefulWords ||
                verification.mismatchCount != 0) {
                throw std::runtime_error("full A2B timed correctness failed");
            }
        }

        const auto artifact = BuildArtifact(options, executionMetadata, runtimeProfile,
                                            setupNanoseconds, samples, warmupVerified,
                                            verifiedEvaluations, mismatchCount);
        WriteArtifact(artifact, options.outputPath);
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "gao-openfhe-a2b-full: " << error.what() << '\n';
        return 1;
    }
}
