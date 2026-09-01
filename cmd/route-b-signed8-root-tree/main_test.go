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

const acceptedRouteBSigned8RootTreeSHA256 = "2410dc161bf37f404fcf88a1b0cfd8973f136833d6dfe902d098757b5c5fb67c"

func TestAcceptedRouteBSigned8RootTreeArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_root_tree_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 267_104 {
		t.Fatalf("canonical Route-B signed8 root-tree bytes=%d, want 267104", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBSigned8RootTreeSHA256 {
		t.Fatalf("canonical Route-B signed8 root-tree digest=%s, want %s", got, acceptedRouteBSigned8RootTreeSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-signed8-root-tree-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B signed8 root-tree envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B signed8 root-tree evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_736_192 ||
		result.BuildReceipt.BuildWallNanoseconds != 5_501_454_200 ||
		result.PostInstallPeakRSSBytes != 6_568_878_080 ||
		result.PostRootTreePeakRSSBytes != 13_130_219_520 ||
		result.TotalWallNanoseconds != 56_871_248_700 ||
		result.RootTree.WallNanoseconds != 27_696_407_400 ||
		result.RootTree.FullA2B.WallNanoseconds != 25_824_872_700 ||
		result.FirstOperation.WallNanoseconds != 4_332_579_000 ||
		result.MaxAbsError != 4.1590670063484936e-07 ||
		result.MaxImaginaryAbs != 6.313179629879332e-10 ||
		result.LeftWordCount != 256 || result.RightWordCount != 256 || result.MismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} {
		t.Fatalf("canonical Route-B signed8 root-tree measured row changed: %+v", result)
	}
	if result.RootTree.Digest != "fa0c3563714d95077833e1b085e55a679e02a220305ace9588d916754d323feb" ||
		result.RootTree.FullA2B.Digest != "d26dd046f85c507055ffadffa1a03c596ab4155df34e950f3f200ac5c36fd2f9" ||
		result.RootTree.FullA2B.SecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		result.RootTree.CapacityPlanDigest != "61e5f8bce34231dbdd33621ec247939a27b5bad806530cf79163e5d22a9c19f9" ||
		result.InputPatternDigest != "2db53e1464ae019964bdf79f18177058f0a48b2a9226aae0f4373dacd5e765f3" ||
		result.RootTree.ParameterDigest != "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816" ||
		result.RootTree.BroadcastSourceDigest != "078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2" ||
		result.RootTree.BroadcastCompiledDigest != "f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063" ||
		result.RootTree.BroadcastEncodedBytes != 25_166_272 ||
		!reflect.DeepEqual(result.RootTree.BroadcastRotationIndexes, []int{1, 2}) ||
		!reflect.DeepEqual(result.RootTree.BroadcastGaloisElements, []uint64{5, 25}) {
		t.Fatalf("canonical Route-B signed8 root-tree identity changed: %+v", result.RootTree)
	}
	if result.RootTree.ThresholdPayloadDigest != "59a64e760a792f019eb7c8f7469f4aaad22b865374f7127f9a07d8ec6d66dc85" ||
		result.RootTree.ScalarOnePayloadDigest != "e48f9750462799c4b84d92db12551c71ab4fb336d17a1465eab096fa418a2a7e" ||
		result.RootTree.LeafDeltaPayloadDigest != "aed1ea0ecebb663dded7044f63fe536631c12a91cae47641e28346270069a50a" ||
		result.RootTree.LeftLeafPayloadDigest != "9a1af619b712c8d617515b0d8bf06d314457f8c0e18b1bba43f5ac44aad00c39" {
		t.Fatalf("canonical Route-B signed8 root-tree plaintext identity changed")
	}
	peak := result.FirstOperation.RuntimeCapacity.Peak
	capacity := result.FirstOperation.RuntimeCapacity.Capacity
	if peak.PreGuardIncrementalPeakBytes != 2_451_902_208 || peak.GuardedRequirementBytes != 2_988_773_120 ||
		peak.RemainingBelowLimitBytes != 3_592_342_988 || capacity.TotalPhysicalBytes != 33_618_251_776 ||
		capacity.AvailablePhysicalBytes != 13_304_766_464 {
		t.Fatalf("canonical Route-B signed8 root-tree runtime capacity changed: peak=%+v capacity=%+v", peak, capacity)
	}
}
