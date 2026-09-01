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

const acceptedRouteBSigned8Depth2NodeBatchSHA256 = "8b99e96e439e13703b0eadc26c27b86ad17f9e5c562401e0c6f05d84a6dd85d8"

func TestAcceptedRouteBSigned8Depth2NodeBatchArtifactReplaysEverySlot(t *testing.T) {
	path := filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_depth2_node_batch_2026-09-01.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 281_296 {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch bytes=%d, want 281296", len(payload))
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != acceptedRouteBSigned8Depth2NodeBatchSHA256 {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch digest=%s, want %s", got, acceptedRouteBSigned8Depth2NodeBatchSHA256)
	}
	var envelope resultEnvelope
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != "lcpdte-route-b-signed8-depth2-node-batch-result-v1" || envelope.CompletedAt.IsZero() {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch envelope changed: %+v", envelope)
	}
	if err = envelope.Result.Validate(); err != nil {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch evidence failed replay: %v", err)
	}
	result := envelope.Result
	if result.BuildReceipt.BuildPeakRSSBytes != 3_273_629_696 ||
		result.BuildReceipt.BuildWallNanoseconds != 5_777_010_100 ||
		result.PostInstallPeakRSSBytes != 6_569_250_816 ||
		result.PostDepth2PeakRSSBytes != 13_206_462_464 ||
		result.TotalWallNanoseconds != 58_761_121_600 ||
		result.Depth2.WallNanoseconds != 28_893_712_600 ||
		result.Depth2.FullA2B.WallNanoseconds != 26_800_675_200 ||
		result.FirstOperation.WallNanoseconds != 4_507_543_300 ||
		result.MaxActiveAbsError != 4.0057496697443185e-07 ||
		result.MaxInactiveAbs != 9.3551663520329e-10 ||
		result.MaxImaginaryAbs != 1.0905832896081732e-09 ||
		result.QueryCount != 170 || result.InputWords != 512 || result.PaddingWords != 2 ||
		result.OutputSlots != 2048 || result.ActiveOutputSlots != 680 || result.InactiveOutputSlots != 1368 ||
		result.PathCounts != [4]uint32{44, 42, 42, 42} ||
		result.BranchTripleCounts != [8]uint32{22, 22, 21, 21, 21, 21, 21, 21} ||
		result.ActiveMismatchCount != 0 || result.InactiveMismatchCount != 0 ||
		result.OverallConstructionDelta != [4]uint64{0, 0, 0, 3} {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch measured row changed: %+v", result)
	}
	if result.Depth2.Digest != "54fb7d525d0ddca6a2ccbcc9579a286b6152ec6699b47085d3577678d0fddb1a" ||
		result.Depth2.FullA2B.Digest != "bc066aacca6054c745fb2eabaafab007229925250fef16efc13c4a0d5d68e5f6" ||
		result.Depth2.FullA2B.SecondSTC.Digest != "bf47f946a1378636f1568a594d8414fc0fe196b2b724b3a66333f598dd252d4a" ||
		result.Depth2.CapacityPlanDigest != "888b4650d8148ec438e4da82ef95598c984cc29651c1b6d47846f977cf2a6298" ||
		result.InputPatternDigest != "6036bfdd76c0e486a45ad8dc08527421da3d5233e2fe1d02d9e97c515e39c7c2" ||
		result.Depth2.ParameterDigest != "c37129e34fb3d726b37412887edf8df1cd6801ba9ab11d02531dddc4f08ea816" ||
		result.Depth2.BroadcastSourceDigest != "078fa95a6f35955ff4a8f8bbe9a10ba065e0f07ed318eb04185d09631b1bd5a2" ||
		result.Depth2.BroadcastCompiledDigest != "f5ce60cc821470595ee12a6c99155bcbed29c698da29b030638f973a452e0063" ||
		result.Depth2.BroadcastEncodedBytes != 25_166_272 ||
		!reflect.DeepEqual(result.Depth2.BroadcastRotationIndexes, []int{1, 2}) ||
		!reflect.DeepEqual(result.Depth2.AlignmentRotationIndexes, []int{4, 8}) ||
		!reflect.DeepEqual(result.Depth2.BroadcastGaloisElements, []uint64{5, 25}) ||
		!reflect.DeepEqual(result.Depth2.AlignmentGaloisElements, []uint64{625, 128481}) {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch identity changed: %+v", result.Depth2)
	}
	if result.Depth2.ThresholdDigest != "59a64e760a792f019eb7c8f7469f4aaad22b865374f7127f9a07d8ec6d66dc85" ||
		result.Depth2.GlobalOneDigest != "e48f9750462799c4b84d92db12551c71ab4fb336d17a1465eab096fa418a2a7e" ||
		result.Depth2.RootOneDigest != "207fdf10d81f4a1a923610d9b8934e22b4a26b96b5c53f309f20f33358a5f6d7" ||
		result.Depth2.RoleMaskDigests != [3]string{
			"5cf4e9e6e566dcd917e6627c250f798a515375c1c94341cbaa5f97d97c1fb5bf",
			"4bb0dc77ff9357e863b1bed63218f2465635b8a70a1fa75a8a129a9337f2a9d0",
			"9d203ee4ffeaec2a5b5c69877be6542d53f4f5c1526fde3e3f20a659e51e5402",
		} ||
		result.Depth2.LeafDeltaDigests != [3]string{
			"1d90b7adae780b9f1be92ea07489d8a04c4d8510cab3bfeccb9f26ad66219040",
			"1f2990720b17696531bf7e56773b4740b3c6210c6446e1db59ebc2048a40fef6",
			"2470bf54267e7529351c2862186427429cc0d842e138cff5fda2b39767d40b10",
		} ||
		result.Depth2.BaseLeafDigest != "e31d69316e79e6d6a45a6991f55f8aeaa84e11df5a8f029bf84085babacaaeb3" {
		t.Fatal("canonical Route-B signed8 depth-2 node-batch plaintext identity changed")
	}
	peak := result.FirstOperation.RuntimeCapacity.Peak
	capacity := result.FirstOperation.RuntimeCapacity.Capacity
	if peak.PreGuardIncrementalPeakBytes != 2_517_438_208 || peak.GuardedRequirementBytes != 3_054_309_120 ||
		peak.RemainingBelowLimitBytes != 3_293_466_060 || capacity.TotalPhysicalBytes != 33_618_251_776 ||
		capacity.AvailablePhysicalBytes != 13_071_425_536 {
		t.Fatalf("canonical Route-B signed8 depth-2 node-batch runtime capacity changed: peak=%+v capacity=%+v", peak, capacity)
	}
}
