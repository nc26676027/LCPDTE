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
constexpr uint32_t kUsefulWords = 512;
constexpr uint32_t kPackingSlots = kWordBits * kUsefulWords / 2;
constexpr uint32_t kRingDimension = 1U << 16;
constexpr uint32_t kWarmupCount = 1;
constexpr uint32_t kRepeatCount = 5;

struct Options {
    std::string hostId;
    std::string outputPath;
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
        else if (argument == "--help" || argument == "-h") {
            std::cout << "Usage: " << argv[0] << " -host-id ID [-out RESULT.json]\n";
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

// Gao's PKEZImpl keeps its raw decryption helper translation-unit-local and its
// public ZDecryptResult decoder does not implement BModeSparse. This is the same
// RLWE decryption core used in z-pke.cpp, followed below by an independent
// bit-by-bit sparse-layout verifier.
DCRTPoly DecryptCore(const std::vector<DCRTPoly>& ciphertextElements,
                     const PrivateKey<DCRTPoly>& privateKey) {
    const DCRTPoly& secret = privateKey->GetPrivateElement();
    const size_t secretSizeQ = secret.GetParams()->GetParams().size();
    const size_t ciphertextSizeQ = ciphertextElements[0].GetParams()->GetParams().size();

    auto secretAtLevel(secret);
    secretAtLevel.DropLastElements(secretSizeQ - ciphertextSizeQ);
    DCRTPoly secretPower(secretAtLevel);

    DCRTPoly decrypted(ciphertextElements[0]);
    decrypted.SetFormat(Format::EVALUATION);
    for (size_t index = 1; index < ciphertextElements.size(); ++index) {
        DCRTPoly term(ciphertextElements[index]);
        term.SetFormat(Format::EVALUATION);
        decrypted += secretPower * term;
        secretPower *= secretAtLevel;
    }
    return decrypted;
}

Verification VerifyAllBits(ConstCiphertext<DCRTPoly>& ciphertext,
                           const PrivateKey<DCRTPoly>& privateKey,
                           const std::vector<uint8_t>& expectedWords) {
    const auto encodingParameters = ciphertext->GetZEncodingParams();
    if (!encodingParameters.isBModeSparse()) {
        throw std::runtime_error("A2B output is not BModeSparse");
    }
    if (encodingParameters.getZN() != kWordBits ||
        encodingParameters.getZSlots() != expectedWords.size()) {
        throw std::runtime_error("A2B output shape differs from the matched workload");
    }

    auto decrypted = DecryptCore(ciphertext->GetElements(), privateKey);
    auto encoded = std::make_shared<ZEncodingImpl>(
        decrypted.GetParams(), decrypted, ciphertext->GetScalingFactorBFP(), encodingParameters);
    const auto complexSlots = ZEncodingImpl::decodeR(encoded).toCSlots();
    const size_t requiredSlots = static_cast<size_t>(kWordBits) * expectedWords.size();
    if (complexSlots.size() < requiredSlots) {
        throw std::runtime_error("sparse Boolean output does not contain all logical bits");
    }

    Verification verification;
    uint32_t printedMismatches = 0;
    const size_t halfBits = kWordBits / 2;
    const size_t highHalfOffset = (expectedWords.size() - 1) * halfBits;
    for (size_t word = 0; word < expectedWords.size(); ++word) {
        for (size_t bit = 0; bit < kWordBits; ++bit) {
            size_t slot = word * halfBits + bit;
            if (bit >= halfBits) {
                slot += highHalfOffset;
            }
            const auto observed = static_cast<int64_t>(
                std::llround(complexSlots[slot].getReal().convertToDouble()));
            const auto expected = static_cast<int64_t>((expectedWords[word] >> bit) & 1U);
            ++verification.checkedBits;
            if (observed != expected) {
                ++verification.mismatchCount;
                if (printedMismatches < 8) {
                    std::cerr << "mismatch word=" << word << " bit=" << bit << " slot=" << slot
                              << " expected=" << expected << " observed=" << observed
                              << " real=" << complexSlots[slot].getReal().convertToDouble()
                              << " imag=" << complexSlots[slot].getImag().convertToDouble() << '\n';
                    ++printedMismatches;
                }
            }
        }
    }
    return verification;
}

std::string BuildArtifact(const Options& options, uint64_t setupNanoseconds,
                          const std::vector<uint64_t>& samples, bool warmupVerified,
                          uint32_t verifiedEvaluations, uint64_t mismatchCount) {
    std::ostringstream output;
    output << "{\n"
           << "  \"schema\": \"lcpdte-ckksint-a2b-benchmark-v2\",\n"
           << "  \"implementation\": \"gao-openfhe-a2b-sparse\",\n"
           << "  \"host_id\": \"" << JsonEscape(options.hostId) << "\",\n"
           << "  \"protocol\": \"gao-a2b-sparse-z8-w4-v1\",\n"
           << "  \"workload_id\": \"uint8-0to255-twice\",\n"
           << "  \"packing_id\": \"n65536-cslots2048-zslots512-w4\",\n"
           << "  \"output_container\": \"one-bmodesparse-ciphertext-4096-bits\",\n"
           << "  \"word_bits\": " << kWordBits << ",\n"
           << "  \"ring_dimension\": " << kRingDimension << ",\n"
           << "  \"packing_slots\": " << kPackingSlots << ",\n"
           << "  \"useful_words\": " << kUsefulWords << ",\n"
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
        parameters.SetRingDim(kRingDimension);
        parameters.SetScalingModSize(43);
        parameters.SetFirstModSize(43);
        parameters.SetScalingTechnique(FLEXIBLEMANUAL);
        parameters.SetNumLargeDigits(3);
        parameters.SetMultiplicativeDepth(20);
        AUXMODSIZE_FLEXIBLEMANUAL = 50;

        CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
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

        fhe->EvalBootstrapSetup(*context, kWordBits, kUsefulWords, {3, 2}, {0, 0}, 4, -24, 1);
        fhe->EvalBootstrapKeyGen(keyPair.secretKey, kWordBits, kUsefulWords);

        const auto cryptoParameters =
            std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
        const auto elementParameters = context->GetCryptoParameters()->GetElementParams();
        const auto scalingFactor = cryptoParameters->GetScalingFactorBFP(0);
        auto encodedInput =
            ZEncodingImpl::encodeArith(inputWords, kWordBits, kUsefulWords, elementParameters, scalingFactor);
        auto encryptedInput = pke->Encrypt(encodedInput);

        auto encodedBoolean = ZEncodingImpl::encodeBooleanSparse(
            inputWords, kWordBits, kUsefulWords, elementParameters, scalingFactor);
        auto encryptedBoolean = pke->Encrypt(encodedBoolean);
        const auto decoderVerification = VerifyAllBits(encryptedBoolean, keyPair.secretKey, expectedWords);
        if (decoderVerification.checkedBits != kWordBits * kUsefulWords ||
            decoderVerification.mismatchCount != 0) {
            throw std::runtime_error("sparse Boolean verifier self-check failed");
        }
        std::cerr << "sparse Boolean verifier self-check: 4096 bits, 0 mismatches\n";

        const auto setupFinish = std::chrono::steady_clock::now();
        const uint64_t setupNanoseconds = ElapsedNanoseconds(setupStart, setupFinish);
        std::cerr << "setup complete in " << setupNanoseconds << " ns\n";

        uint64_t mismatchCount = 0;
        uint32_t verifiedEvaluations = 0;

        bool warmupVerified = false;
        {
            auto warmupOutput = fhe->EvalArithToBooleanSparse(encryptedInput);
            const auto warmupVerification =
                VerifyAllBits(warmupOutput, keyPair.secretKey, expectedWords);
            mismatchCount += warmupVerification.mismatchCount;
            warmupVerified = warmupVerification.checkedBits == kWordBits * kUsefulWords &&
                             warmupVerification.mismatchCount == 0;
            std::cerr << "warmup verified: " << warmupVerification.checkedBits << " bits, "
                      << warmupVerification.mismatchCount << " mismatches\n";
        }
        if (!warmupVerified) {
            throw std::runtime_error("sparse A2B warmup correctness failed");
        }

        std::vector<uint64_t> samples;
        samples.reserve(kRepeatCount);
        for (uint32_t repeat = 0; repeat < kRepeatCount; ++repeat) {
            const auto onlineStart = std::chrono::steady_clock::now();
            auto output = fhe->EvalArithToBooleanSparse(encryptedInput);
            const auto onlineFinish = std::chrono::steady_clock::now();
            samples.push_back(ElapsedNanoseconds(onlineStart, onlineFinish));

            const auto verification = VerifyAllBits(output, keyPair.secretKey, expectedWords);
            mismatchCount += verification.mismatchCount;
            ++verifiedEvaluations;
            std::cerr << "sample " << (repeat + 1) << ": " << samples.back() << " ns; verified "
                      << verification.checkedBits << " bits, " << verification.mismatchCount
                      << " mismatches\n";
            if (verification.checkedBits != kWordBits * kUsefulWords ||
                verification.mismatchCount != 0) {
                throw std::runtime_error("sparse A2B timed correctness failed");
            }
        }

        const auto artifact = BuildArtifact(options, setupNanoseconds, samples, warmupVerified,
                                            verifiedEvaluations, mismatchCount);
        WriteArtifact(artifact, options.outputPath);
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "gao-openfhe-a2b-matched: " << error.what() << '\n';
        return 1;
    }
}
