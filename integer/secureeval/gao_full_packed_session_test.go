package secureeval

import (
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"strconv"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

func TestGaoFullPackedTraceDigestBindsOptimizedLiveGraph(t *testing.T) {
	digest := sha256.Sum256([]byte(gaoFullPackedA2BTraceSchema))
	if got, want := gaoFullPackedA2BTraceDigest, hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("trace digest=%q, want %q", got, want)
	}
}

func TestPadGaoFullPackedA2BWordsUsesZeroFill(t *testing.T) {
	got, err := padGaoFullPackedA2BWords([]uint8{7, 9})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != GaoFullPackedA2BMaxWords {
		t.Fatalf("padded words=%d, want %d", len(got), GaoFullPackedA2BMaxWords)
	}
	if got[0] != 7 || got[1] != 9 {
		t.Fatalf("input prefix changed: %v", got[:2])
	}
	for index, word := range got[2:] {
		if word != 0 {
			t.Fatalf("padding word %d=%d, want zero", index+2, word)
		}
	}
}

func TestPadGaoFullPackedA2BWordsValidatesCapacity(t *testing.T) {
	for _, size := range []int{0, GaoFullPackedA2BMaxWords + 1} {
		if _, err := padGaoFullPackedA2BWords(make([]uint8, size)); err == nil {
			t.Fatalf("word count %d unexpectedly accepted", size)
		}
	}
	full := make([]uint8, GaoFullPackedA2BMaxWords)
	for index := range full {
		full[index] = uint8(index)
	}
	got, err := padGaoFullPackedA2BWords(full)
	if err != nil {
		t.Fatal(err)
	}
	for index := range full {
		if got[index] != full[index] {
			t.Fatalf("full packing repeated or changed word %d: got %d want %d", index, got[index], full[index])
		}
	}
}

func TestGaoFullPackedA2BSessionAPISurface(t *testing.T) {
	var _ func() (*GaoFullPackedA2BClient, *GaoFullPackedA2BServer, GaoFullPackedA2BSetupReport, error) = NewGaoFullPackedA2BSession
	var _ func(*GaoFullPackedA2BClient, []uint8) (*GaoFullPackedA2BEncryptedInput, GaoFullPackedA2BPhaseReport, error) = (*GaoFullPackedA2BClient).EncryptA2B
	var _ func(*GaoFullPackedA2BServer, *GaoFullPackedA2BEncryptedInput) (*GaoFullPackedA2BEncryptedOutput, GaoFullPackedA2BPhaseReport, error) = (*GaoFullPackedA2BServer).EvaluateA2B
	var _ func(*GaoFullPackedA2BClient, *GaoFullPackedA2BEncryptedOutput) ([][8]uint8, GaoFullPackedA2BPhaseReport, error) = (*GaoFullPackedA2BClient).DecryptA2B
	var _ func(*GaoFullPackedA2BServer) = (*GaoFullPackedA2BServer).Close
	var _ time.Duration = GaoFullPackedA2BSetupReport{}.ClientConstructionWallTime
}

func TestNewGaoFullPackedClientCryptographyUsesPublicKey(t *testing.T) {
	params := gaoFactorStoreTestParameters(t)
	secretKey, publicKey, encryptor, decryptor, err := newGaoFullPackedClientCryptography(params)
	if err != nil {
		t.Fatal(err)
	}
	if secretKey == nil || publicKey == nil || encryptor == nil || decryptor == nil {
		t.Fatal("public-key client cryptography returned a nil component")
	}

	plaintext := rlwe.NewPlaintext(params, params.MaxLevel())
	ciphertext, err := encryptor.EncryptNew(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == nil || decryptor.DecryptNew(ciphertext) == nil {
		t.Fatal("public-key encryption did not produce a decryptable ciphertext")
	}
}

func TestGaoFullPackedParameterReportDerivesRuntimeModuli(t *testing.T) {
	parameters, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		t.Fatal(err)
	}
	got, err := newGaoFullPackedA2BParameterReport(parameters)
	if err != nil {
		t.Fatal(err)
	}
	if got.RingDimension != 65_536 || got.PackingSlots != 32_768 || got.UsefulWords != 8_192 ||
		got.QModuliCount != 21 || got.QLog2Aggregate != 904 ||
		got.PModuliCount != 7 || got.PLog2Aggregate != 350 ||
		got.ScalingModulusBits != 43 || got.FirstModulusBits != 43 || got.MultiplicativeDepth != 20 ||
		got.LargeDigits != 3 || got.EphemeralSecretHammingWeight != 32 ||
		got.LevelBudget != [2]int{3, 2} || got.OpenFHERequestedBSGSDimensions != [2]int{0, 0} ||
		got.ChunkWidth != 4 || got.CutoffBits != -24 ||
		got.STCLogBSGSRatio != 2 || got.CTSLogBSGSRatio != 2 || got.SpecialB0LogBSGSRatio != 2 ||
		got.EncryptionMode != "public-key" || got.FactorStorageMode != "resident-prevalidated" ||
		got.ScaleSchedule != "lattigo-explicit-level-scale-native" {
		t.Fatalf("runtime parameter report=%+v", got)
	}
	if got.MainSecretDistribution != "balanced-sparse-ternary" || got.MainSecretHammingWeight != 192 ||
		got.EphemeralSecretDistribution != "balanced-sparse-ternary" || got.EphemeralSecretHammingWeight != 32 ||
		got.ErrorSampler != "lattigo-bounded-discrete-gaussian" || got.ErrorSigma != 3.2 ||
		got.ErrorConfiguredBound != 19.2 || got.ErrorEffectiveIntegerBound != 19 ||
		got.KeySwitchTechnique != "lattigo-rns-qp-gadget" || got.RNSDecompositionComponents != 3 ||
		got.BaseTwoDecomposition != 0 || got.SecuritySelector != "external-estimator" ||
		got.SecurityEvidence != "full-packed-profile-not-assessed" {
		t.Fatalf("runtime native parameter profile=%+v", got)
	}

	params := parameters.BootstrappingParameters
	q, p := params.Q(), params.P()
	if got.ActualFirstQModulusBits != bits.Len64(q[0]) ||
		len(got.QModuli) != len(q) || len(got.QModuliBitLengths) != len(q) ||
		len(got.PModuli) != len(p) || len(got.PModuliBitLengths) != len(p) {
		t.Fatalf("runtime modulus identity shape=%+v", got)
	}
	for index, modulus := range q {
		if got.QModuli[index] != strconv.FormatUint(modulus, 10) ||
			got.QModuliBitLengths[index] != bits.Len64(modulus) {
			t.Fatalf("Q[%d]=%q/%d, want %d/%d", index, got.QModuli[index], got.QModuliBitLengths[index], modulus, bits.Len64(modulus))
		}
	}
	for index, modulus := range p {
		if got.PModuli[index] != strconv.FormatUint(modulus, 10) ||
			got.PModuliBitLengths[index] != bits.Len64(modulus) {
			t.Fatalf("P[%d]=%q/%d, want %d/%d", index, got.PModuli[index], got.PModuliBitLengths[index], modulus, bits.Len64(modulus))
		}
	}

	second, err := newGaoFullPackedA2BParameterReport(parameters)
	if err != nil {
		t.Fatal(err)
	}
	got.QModuli[0] = "mutated"
	got.QModuliBitLengths[0] = 0
	got.PModuli[0] = "mutated"
	got.PModuliBitLengths[0] = 0
	if second.QModuli[0] != strconv.FormatUint(q[0], 10) || second.QModuliBitLengths[0] != bits.Len64(q[0]) ||
		second.PModuli[0] != strconv.FormatUint(p[0], 10) || second.PModuliBitLengths[0] != bits.Len64(p[0]) {
		t.Fatal("runtime modulus identity slices alias across reports")
	}
}
