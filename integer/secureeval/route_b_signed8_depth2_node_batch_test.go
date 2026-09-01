package secureeval

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func TestRouteBSigned8Depth2NodeBatchModelAndOracle(t *testing.T) {
	model, err := NewRouteBSigned8Depth2NodeBatchModel(
		[3]int64{0, 0, 0},
		[4]float64{-3.25, -0.75, 2.5, 5.125},
	)
	if err != nil {
		t.Fatal(err)
	}
	ranges := routeBSigned8Depth2CanonicalRanges(t)
	values := []int64{-128, -1, 0, 1, 127}
	seen := [8]bool{}
	for _, root := range values {
		for _, left := range values {
			for _, right := range values {
				got, path, branches, oracleErr := routeBSigned8Depth2NodeBatchOracle(
					[3]int64{root, left, right}, ranges, model,
				)
				if oracleErr != nil {
					t.Fatal(oracleErr)
				}
				wantBranches := [3]uint8{boolByte(root >= 0), boolByte(left >= 0), boolByte(right >= 0)}
				wantPath := uint8(2 * wantBranches[0])
				if wantBranches[0] == 0 {
					wantPath += wantBranches[1]
				} else {
					wantPath += wantBranches[2]
				}
				if branches != wantBranches || path != wantPath || math.Float64bits(got) != math.Float64bits(model.Leaves()[wantPath]) {
					t.Fatalf("oracle mismatch features=%v got=%g/%d/%v want=%g/%d/%v", [3]int64{root, left, right}, got, path, branches, model.Leaves()[wantPath], wantPath, wantBranches)
				}
				seen[4*branches[0]+2*branches[1]+branches[2]] = true
			}
		}
	}
	for index, value := range seen {
		if !value {
			t.Fatalf("branch triple %03b was not covered", index)
		}
	}
	if model.Digest() == "" || model.Thresholds() != [3]int64{} || model.Leaves() != [4]float64{-3.25, -0.75, 2.5, 5.125} {
		t.Fatalf("model projection changed: thresholds=%v leaves=%v digest=%q", model.Thresholds(), model.Leaves(), model.Digest())
	}
}

func TestRouteBSigned8Depth2NodeBatchRejectsInvalidModelRangesAndFeatures(t *testing.T) {
	validModel, err := NewRouteBSigned8Depth2NodeBatchModel([3]int64{}, [4]float64{-1, 0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	validRanges := routeBSigned8Depth2CanonicalRanges(t)
	tests := []struct {
		name   string
		model  RouteBSigned8Depth2NodeBatchModel
		ranges [3]homchain.Signed8NoOverflowRange
		input  [3]int64
	}{
		{name: "tampered model digest", model: func() RouteBSigned8Depth2NodeBatchModel { v := validModel; v.digest = "foreign"; return v }(), ranges: validRanges},
		{name: "foreign threshold range", model: validModel, ranges: func() [3]homchain.Signed8NoOverflowRange {
			v := validRanges
			v[1], _ = homchain.NewSigned8NoOverflowRange(-127, 127, 1, 1)
			return v
		}()},
		{name: "feature outside range", model: validModel, ranges: func() [3]homchain.Signed8NoOverflowRange {
			v := validRanges
			v[2], _ = homchain.NewSigned8NoOverflowRange(-4, 4, 0, 0)
			return v
		}(), input: [3]int64{0, 0, 5}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, oracleErr := routeBSigned8Depth2NodeBatchOracle(test.input, test.ranges, test.model); oracleErr == nil {
				t.Fatal("invalid depth-2 oracle input was admitted")
			}
		})
	}
	for _, test := range []struct {
		name       string
		thresholds [3]int64
		leaves     [4]float64
	}{
		{name: "low threshold", thresholds: [3]int64{-129}},
		{name: "high threshold", thresholds: [3]int64{0, 128}},
		{name: "nan leaf", leaves: [4]float64{math.NaN()}},
		{name: "infinite leaf", leaves: [4]float64{0, math.Inf(1)}},
		{name: "oversized leaf", leaves: [4]float64{0, 0, 0, 1 << 21}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, modelErr := NewRouteBSigned8Depth2NodeBatchModel(test.thresholds, test.leaves); modelErr == nil {
				t.Fatal("invalid depth-2 model was admitted")
			}
		})
	}
}

func TestRouteBSigned8Depth2NodeBatchAlignmentOracle(t *testing.T) {
	ge := make([]float64, routeBSigned8Depth2NodeBatchSlots)
	for word := 0; word < routeBSigned8Depth2NodeBatchWords; word++ {
		for slot := 0; slot < 4; slot++ {
			ge[4*word+slot] = float64(word + 1)
		}
	}
	root, left, right, err := routeBSigned8Depth2NodeBatchAlignOracle(ge)
	if err != nil {
		t.Fatal(err)
	}
	for query := 0; query < routeBSigned8Depth2NodeBatchQueries; query++ {
		rootWord := 3 * query
		for slot := 0; slot < 4; slot++ {
			index := 4*rootWord + slot
			if root[index] != float64(rootWord+1) || left[index] != float64(rootWord+2) || right[index] != float64(rootWord+3) {
				t.Fatalf("query %d slot %d alignment=%g/%g/%g", query, slot, root[index], left[index], right[index])
			}
		}
	}
	for word := 0; word < routeBSigned8Depth2NodeBatchWords; word++ {
		if word%3 == 0 && word < 3*routeBSigned8Depth2NodeBatchQueries {
			continue
		}
		for slot := 0; slot < 4; slot++ {
			index := 4*word + slot
			if root[index] != 0 || left[index] != 0 || right[index] != 0 {
				t.Fatalf("inactive word %d slot %d is nonzero: %g/%g/%g", word, slot, root[index], left[index], right[index])
			}
		}
	}
	if _, _, _, err = routeBSigned8Depth2NodeBatchAlignOracle(ge[:len(ge)-1]); err == nil {
		t.Fatal("short alignment vector was admitted")
	}
}

func TestRouteBSigned8Depth2NodeBatchArtifactsBindScheduleAndInstalledKeySubset(t *testing.T) {
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewRouteBSigned8Depth2NodeBatchModel([3]int64{}, [4]float64{-3.25, -0.75, 2.5, 5.125})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := newRouteBSigned8Depth2NodeBatchArtifacts(params, model)
	if err != nil {
		t.Fatal(err)
	}
	wantPathScale := params.DefaultScale().Mul(params.DefaultScale()).Div(rlwe.NewScale(params.Q()[2]))
	wantLeafScale := rlwe.NewScale(params.Q()[1]).Mul(params.DefaultScale()).Div(wantPathScale)
	if !artifacts.pathScale.Equal(wantPathScale) || !artifacts.leafOperandScale.Equal(wantLeafScale) ||
		artifacts.broadcastSourceDigest != routeBSigned8RootTreeBroadcastSourceDigest ||
		artifacts.broadcastCompiledDigest != routeBSigned8RootTreeBroadcastCompiledDigest ||
		artifacts.broadcastEncodedBytes != routeBSigned8RootTreeBroadcastEncodedBytes ||
		!slices.Equal(artifacts.broadcastRotationIndexes, []int{1, 2}) ||
		!slices.Equal(artifacts.alignmentRotationIndexes, []int{4, 8}) ||
		!slices.Equal(artifacts.alignmentGaloisElements, []uint64{625, 128481}) {
		t.Fatalf("depth-2 artifacts changed: path=%g leaf=%g broadcast=%s/%s/%d/%v align=%v/%v",
			artifacts.pathScale.Float64(), artifacts.leafOperandScale.Float64(),
			artifacts.broadcastSourceDigest, artifacts.broadcastCompiledDigest,
			artifacts.broadcastEncodedBytes, artifacts.broadcastRotationIndexes,
			artifacts.alignmentRotationIndexes, artifacts.alignmentGaloisElements)
	}
	digests := []string{
		artifacts.parameterDigest, artifacts.thresholdDigest, artifacts.globalOneDigest,
		artifacts.rootOneDigest, artifacts.roleMaskDigests[0], artifacts.roleMaskDigests[1],
		artifacts.roleMaskDigests[2], artifacts.leafDeltaDigests[0], artifacts.leafDeltaDigests[1],
		artifacts.leafDeltaDigests[2], artifacts.baseLeafDigest,
	}
	seen := map[string]bool{}
	for index, digest := range digests {
		if !routeBA2BFullIsSHA256(digest) {
			t.Fatalf("artifact digest %d is malformed: %q", index, digest)
		}
		if index >= 4 && index <= 6 && seen[digest] {
			t.Fatalf("role-mask digest %d is not distinct", index)
		}
		seen[digest] = true
	}
}

func TestRouteBSigned8Depth2NodeBatchReportRejectsSelfConsistentMutation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_depth2_node_batch_2026-09-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result RouteBCanonicalSigned8Depth2NodeBatchResult `json:"result"`
	}
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	base := envelope.Result.Depth2
	if err = base.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*RouteBSigned8Depth2NodeBatchReport)
	}{
		{"foreign role mask", func(value *RouteBSigned8Depth2NodeBatchReport) { value.RoleMaskDigests[0] = value.RoleMaskDigests[1] }},
		{"threshold not fixed by range", func(value *RouteBSigned8Depth2NodeBatchReport) { value.Model.Thresholds[1]++ }},
		{"broadcast raw level", func(value *RouteBSigned8Depth2NodeBatchReport) { value.States[3].Level-- }},
		{"operation ledger", func(value *RouteBSigned8Depth2NodeBatchReport) { value.OperationCounts.AlignmentRotations++ }},
		{"nested A2B", func(value *RouteBSigned8Depth2NodeBatchReport) { value.FullA2B.OperationCounts.KernelInvocations++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, marshalErr := json.Marshal(base)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var mutated RouteBSigned8Depth2NodeBatchReport
			if unmarshalErr := json.Unmarshal(encoded, &mutated); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			test.mutate(&mutated)
			mutated.Digest, err = digestRouteBSigned8Depth2NodeBatchReport(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err = mutated.Validate(); err == nil {
				t.Fatal("self-consistent foreign report was accepted")
			}
		})
	}
}

func routeBSigned8Depth2CanonicalRanges(t *testing.T) [3]homchain.Signed8NoOverflowRange {
	t.Helper()
	var result [3]homchain.Signed8NoOverflowRange
	for index := range result {
		value, err := homchain.NewSigned8NoOverflowRange(-128, 127, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = value
	}
	return result
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}
