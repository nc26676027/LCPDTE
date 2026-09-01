package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const acceptedRouteBSigned8Radix4SHA256 = "5b9bd7ffebf551cd67cea4fc1d0f4ff214b4a2fdcfc1a4dd538743c61d2f7eda"

func TestAcceptedRouteBSigned8Radix4ArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_radix4_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 279_304 {
		t.Fatalf("canonical Route-B signed8 radix-4 bytes=%d, want 279304", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBSigned8Radix4SHA256 {
		t.Fatalf("canonical Route-B signed8 radix-4 digest=%s, want %s", got, acceptedRouteBSigned8Radix4SHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-signed8-radix4-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B signed8 radix-4 envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B signed8 radix-4 evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_212_533_760 ||
		result.BuildReceipt.BuildWallNanoseconds != 6_553_618_700 ||
		result.PostInstallPeakRSSBytes != 6_569_582_592 ||
		result.PostRadixPeakRSSBytes != 13_048_193_024 ||
		result.TotalWallNanoseconds != 69_422_489_500 ||
		result.Radix4.WallNanoseconds != 36_731_910_400 ||
		result.Radix4.CommonPrefixWallNanoseconds != 36_704_370_200 ||
		result.Radix4.TerminalWallNanoseconds != 15_486_800 ||
		result.Radix4.FullA2B.WallNanoseconds != 34_456_204_600 ||
		result.FirstOperation.WallNanoseconds != 5_989_092_100 ||
		result.MaxActiveAbsError != 1.7920877759536324e-7 ||
		result.MaxInactiveAbs != 5.263737763879564e-10 ||
		result.MaxImaginaryAbs != 6.095686089563721e-10 ||
		result.PathCounts != [4]uint32{55, 29, 30, 56} || result.EqualityCounts != [3]uint32{2, 2, 2} ||
		result.ActiveMismatchCount != 0 || result.InactiveMismatchCount != 0 || result.BinaryEquivalenceMismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} {
		t.Fatalf("canonical Route-B signed8 radix-4 measured row changed: %+v", result)
	}
	if result.Radix4.Digest != "4656b83b840b7cbf80025ec3bebd75041ab39272012f353643751b698b914f4f" ||
		result.Radix4.FullA2B.Digest != "b6cda315a88d24c41a5cb7dacd00660b3e46c44df8df7a82b4d6fe855c69198a" ||
		result.Radix4.FullA2B.SecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		result.Radix4.CapacityPlanDigest != "dfed5e77a1ec40748c9a614c565773286caf1b95b91b57f6435913835b5c59f0" ||
		result.InputPatternDigest != "d7d9335e7d4f74921b835191dddf3fc7c62b4af59721d5c6287456ff9c1775f7" ||
		result.ApplicationSecurityProfileDigest != "49db539532bd31000918b8417bcd36a80412c9062e9435e6e3e0d0a125fadefb" ||
		result.Radix4.Ablation.ExhaustiveEquivalenceProofDigest != "8b0f5a894f5dee94afd061395a4b70282f628e751b7ddaaea7b0e7259dbd937e" ||
		result.Radix4.Ablation.EquivalentBinaryModelDigest != "b8ce543b51642aa50cbdcfa95c15edca0771b05ddc9ce742c8d95ca839d90fb7" ||
		result.Radix4.ParameterDigest != "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816" ||
		result.Radix4.BroadcastSourceDigest != "078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2" ||
		result.Radix4.BroadcastCompiledDigest != "f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063" ||
		result.Radix4.BroadcastEncodedBytes != 25_166_272 ||
		!reflect.DeepEqual(result.Radix4.BroadcastRotationIndexes, []int{1, 2}) ||
		!reflect.DeepEqual(result.Radix4.AlignmentRotationIndexes, []int{4, 8}) ||
		!reflect.DeepEqual(result.Radix4.BroadcastGaloisElements, []uint64{5, 25}) ||
		!reflect.DeepEqual(result.Radix4.AlignmentGaloisElements, []uint64{625, 128481}) {
		t.Fatalf("canonical Route-B signed8 radix-4 identity changed: %+v", result.Radix4)
	}
	if result.Radix4.ThresholdDigest != "f35bdf3477649b0c2bcaf195bc99b0912b73664136c74393683ee5638dc12bdb" ||
		result.Radix4.GlobalOneDigest != "e48f9750462799c4b84d92db12551c71ab4fb336d17a1465eab096fa418a2a7e" ||
		result.Radix4.RoleMaskDigests != [3]string{
			"5cf4e9e6e566dcd917e6627c250f798a515375c1c94341cbaa5f97d97c1fb5bf",
			"4bb0dc77ff9357e863b1bed63218f2465635b8a70a1fa75a8a129a9337f2a9d0",
			"9d203ee4ffeaec2a5b5c69877be6542d53f4f5c1526fde3e3f20a659e51e5402",
		} ||
		result.Radix4.LeafDeltaDigests != [3]string{
			"ea248b58aa3be1ef9b48422481d735a7804d19c4686afd7864468f71ee5822cd",
			"ae6df6c5d11e7a4602a4d0a3d5b96e01dfd7cc620f0ef8c66548c031c75382b8",
			"7557fe8c9ed645f8855a1ebb787b62b14ddcad8241afb35298f760db2deb5b01",
		} || result.Radix4.BaseLeafDigest != "d7d3a46e9e353034b867d91d2b80efc41baa90e52880082ab95c7889256a1ab0" {
		t.Fatal("canonical Route-B signed8 radix-4 plaintext identity changed")
	}
	peak := result.FirstOperation.RuntimeCapacity.Peak
	capacity := result.FirstOperation.RuntimeCapacity.Capacity
	if peak.PreGuardIncrementalPeakBytes != 2_517_438_208 || peak.GuardedRequirementBytes != 3_054_309_120 ||
		peak.RemainingBelowLimitBytes != 4_260_232_652 || capacity.TotalPhysicalBytes != 33_618_251_776 ||
		capacity.AvailablePhysicalBytes != 14_038_192_128 {
		t.Fatalf("canonical Route-B signed8 radix-4 runtime capacity changed: peak=%+v capacity=%+v", peak, capacity)
	}
}
