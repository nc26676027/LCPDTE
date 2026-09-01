package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const acceptedRouteBSigned8SameFeatureBinarySHA256 = "622e43f99eada89a5bfce505389803d26eb9be1daf4853b1376531ad75f71f0b"

func TestAcceptedRouteBSigned8SameFeatureBinaryArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_same_feature_binary_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 283_809 {
		t.Fatalf("canonical Route-B same-feature binary bytes=%d, want 283809", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBSigned8SameFeatureBinarySHA256 {
		t.Fatalf("canonical Route-B same-feature binary digest=%s, want %s", got, acceptedRouteBSigned8SameFeatureBinarySHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-signed8-same-feature-binary-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B same-feature binary envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B same-feature binary evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_814_016 ||
		result.BuildReceipt.BuildWallNanoseconds != 6_535_207_600 ||
		result.PostInstallPeakRSSBytes != 6_569_451_520 ||
		result.PostBinaryPeakRSSBytes != 13_209_845_760 ||
		result.TotalWallNanoseconds != 70_515_213_800 ||
		result.SameFeatureBinary.WallNanoseconds != 37_012_714_900 ||
		result.SameFeatureBinary.CommonPrefixWallNanoseconds != 36_869_851_300 ||
		result.SameFeatureBinary.TerminalWallNanoseconds != 134_857_200 ||
		result.FirstOperation.WallNanoseconds != 5_867_961_700 ||
		result.MaxActiveAbsError != 2.1251607851269227e-7 ||
		result.MaxInactiveAbs != 8.223015298309167e-10 ||
		result.MaxImaginaryAbs != 9.737147197390928e-10 ||
		result.PathCounts != [4]uint32{55, 29, 30, 56} || result.EqualityCounts != [3]uint32{2, 2, 2} ||
		result.ActiveMismatchCount != 0 || result.InactiveMismatchCount != 0 || result.BinaryEquivalenceMismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} {
		t.Fatalf("canonical Route-B same-feature binary measured row changed: %+v", result)
	}
	base := result.SameFeatureBinary.Base
	if result.SameFeatureBinary.Digest != "38a314babbfe8a8512d9c603a512bec28db0d2bb5911488bb2c8d726531b426f" ||
		base.Digest != "7e00c4a249e90c931919a23cdd9eb56ec5df252f65654c0ef8f5662924f0b5ad" ||
		base.FullA2B.Digest != "2a054fde17b927fe5e92072886a10929efd362bd8fe6bd1f088d3e5ecc336cbc" ||
		base.FullA2B.SecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		base.CapacityPlanDigest != "888b4650d8148ec438e4da82ef95598c984cc29651c1b6d47846f977cf2a6298" ||
		result.InputPatternDigest != "d7d9335e7d4f74921b835191dddf3fc7c62b4af59721d5c6287456ff9c1775f7" ||
		result.ApplicationSecurityProfileDigest != "49db539532bd31000918b8417bcd36a80412c9062e9435e6e3e0d0a125fadefb" ||
		base.ParameterDigest != "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816" ||
		base.BroadcastSourceDigest != "078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2" ||
		base.BroadcastCompiledDigest != "f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063" ||
		base.BroadcastEncodedBytes != 25_166_272 || len(base.States) != 30 {
		t.Fatalf("canonical Route-B same-feature binary identity changed: %+v", result.SameFeatureBinary)
	}
	counts := base.OperationCounts
	if counts.PathCiphertextProducts != 3 || counts.PathRelinearizations != 3 || counts.PathRescales != 3 ||
		counts.LeafPlaintextProducts != 3 || counts.LeafRescales != 3 {
		t.Fatalf("canonical Route-B same-feature binary operation count changed: %+v", counts)
	}
	peak := result.FirstOperation.RuntimeCapacity.Peak
	capacity := result.FirstOperation.RuntimeCapacity.Capacity
	if peak.PreGuardIncrementalPeakBytes != 2_517_438_208 || peak.GuardedRequirementBytes != 3_054_309_120 ||
		peak.RemainingBelowLimitBytes != 4_188_851_660 || capacity.TotalPhysicalBytes != 33_618_251_776 ||
		capacity.AvailablePhysicalBytes != 13_966_811_136 {
		t.Fatalf("canonical Route-B same-feature binary runtime capacity changed: peak=%+v capacity=%+v", peak, capacity)
	}
}
