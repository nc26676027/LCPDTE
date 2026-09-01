package secureeval

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"dt_go/integer/homchain"
	"dt_go/integer/secureprofile"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func TestRouteBSigned8RootTreeModelAndOracle(t *testing.T) {
	model, err := NewRouteBSigned8RootTreeModel(0, -2.25, 3.5)
	if err != nil {
		t.Fatal(err)
	}
	if model.Threshold() != 0 || model.LeftLeaf() != -2.25 || model.RightLeaf() != 3.5 || model.Digest() == "" {
		t.Fatalf("model changed: %+v", model)
	}
	ranges, err := homchain.NewSigned8NoOverflowRange(-128, 127, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateRouteBSigned8RootTreeInputs(ranges, model); err != nil {
		t.Fatal(err)
	}
	for value := int64(-128); value <= 127; value++ {
		want := -2.25
		if value >= 0 {
			want = 3.5
		}
		got, branch, oracleErr := routeBSigned8RootTreeOracle(value, ranges, model)
		if oracleErr != nil || got != want || branch != btoi(value >= 0) {
			t.Fatalf("x=%d got leaf=%g branch=%d err=%v, want %g/%d", value, got, branch, oracleErr, want, btoi(value >= 0))
		}
	}
}

func TestRouteBSigned8RootTreeRejectsInvalidModelOrRange(t *testing.T) {
	invalidModels := []struct {
		name      string
		threshold int64
		left      float64
		right     float64
	}{
		{"threshold-low", -129, 0, 1},
		{"threshold-high", 128, 0, 1},
		{"left-nan", 0, math.NaN(), 1},
		{"right-inf", 0, 0, math.Inf(1)},
		{"left-bound", 0, -(1 << 20) - 1, 1},
		{"right-bound", 0, 0, (1 << 20) + 1},
	}
	for _, test := range invalidModels {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRouteBSigned8RootTreeModel(test.threshold, test.left, test.right); err == nil {
				t.Fatal("invalid model was accepted")
			}
		})
	}

	model, err := NewRouteBSigned8RootTreeModel(1, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	wrongThresholdRange, err := homchain.NewSigned8NoOverflowRange(-10, 10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateRouteBSigned8RootTreeInputs(wrongThresholdRange, model); err == nil {
		t.Fatal("model threshold not fixed by the range certificate was accepted")
	}
	overflowRange, err := homchain.NewSigned8NoOverflowRange(-128, 127, 1, 1)
	if err == nil || overflowRange.Digest() != "" {
		t.Fatal("overflow-admitting range was accepted")
	}
}

func TestRouteBSigned8BroadcastOracleCopiesOnlySignColumn(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		input := [4]float64{}
		for bit := range input {
			input[bit] = float64((mask >> bit) & 1)
		}
		got := routeBSigned8BroadcastOracle(input)
		want := input[3]
		for slot, value := range got {
			if value != want {
				t.Fatalf("mask=%04b slot=%d got=%g want=%g", mask, slot, value, want)
			}
		}
	}
}

func TestRouteBSigned8RootTreeArtifactsUseFrozenLevelsAndInstalledKeys(t *testing.T) {
	params, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewRouteBSigned8RootTreeModel(0, -2.25, 3.5)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := newRouteBSigned8RootTreeArtifacts(params, model)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.threshold.Level() != 20 || !artifacts.threshold.Scale.Equal(params.DefaultScale()) ||
		artifacts.scalarOne.Level() != 3 || !artifacts.scalarOne.Scale.Equal(params.DefaultScale()) ||
		artifacts.leafDelta.Level() != 3 || !artifacts.leafDelta.Scale.Equal(rlwe.NewScale(params.Q()[3])) ||
		artifacts.leftLeaf.Level() != 2 || !artifacts.leftLeaf.Scale.Equal(params.DefaultScale()) {
		t.Fatal("signed8 root plaintext level or scale schedule changed")
	}
	if artifacts.broadcast.LevelQ != 4 || artifacts.broadcast.LevelP != 6 || len(artifacts.broadcast.Vec) != 4 ||
		artifacts.broadcastEncodedBytes != routeBSigned8RootTreeBroadcastEncodedBytes ||
		artifacts.broadcastSourceDigest != routeBSigned8RootTreeBroadcastSourceDigest ||
		artifacts.broadcastCompiledDigest != routeBSigned8RootTreeBroadcastCompiledDigest ||
		!slices.Equal(artifacts.broadcastRotationIndexes, routeBSigned8RootTreeExpectedBroadcastRotations()) ||
		!slices.Equal(artifacts.broadcastGaloisElements, routeBSigned8RootTreeExpectedBroadcastGalois()) {
		t.Fatalf("signed8 root broadcast topology changed: rotations=%v galois=%v bytes=%d",
			artifacts.broadcastRotationIndexes, artifacts.broadcastGaloisElements, artifacts.broadcastEncodedBytes)
	}
	installed := secureprofile.DefaultGaoN16PackingL11CapacityShape().EvaluationGaloisElements()
	for _, element := range artifacts.broadcastGaloisElements {
		if _, ok := slices.BinarySearch(installed, element); !ok {
			t.Fatalf("broadcast requires uninstalled Galois element %d", element)
		}
	}
	states, err := routeBSigned8RootTreeExpectedStates(params)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 8 || states[0].Stage != RouteBSigned8RootTreeStageInput || states[7].Stage != RouteBSigned8RootTreeStageOutput ||
		states[0].Level != 20 || states[7].Level != 2 {
		t.Fatalf("signed8 root expected state ledger changed: %+v", states)
	}
	counts := routeBSigned8RootTreeExpectedCounts(artifacts)
	if counts.PublicThresholdSubtractions != 1 || counts.CompleteA2BInvocations != 1 ||
		counts.BroadcastLinearTransformations != 1 || counts.LeafCiphertextPlaintextProducts != 1 ||
		counts.AdditionalRelinearizations != 0 || counts.LogicalPeakLiveWrapperCiphertexts != 5 {
		t.Fatalf("signed8 root operation ledger changed: %+v", counts)
	}
}

func TestRouteBSigned8RootTreeReportRejectsSelfConsistentMutation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_root_tree_2026-09-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result RouteBCanonicalSigned8RootTreeResult `json:"result"`
	}
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	base := envelope.Result.RootTree
	if err = base.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*RouteBSigned8RootTreeReport)
	}{
		{"foreign broadcast", func(value *RouteBSigned8RootTreeReport) { value.BroadcastSourceDigest = value.FullA2B.Digest }},
		{"threshold not fixed by range", func(value *RouteBSigned8RootTreeReport) { value.Model.Threshold++ }},
		{"high-half level", func(value *RouteBSigned8RootTreeReport) { value.States[2].Level-- }},
		{"operation ledger", func(value *RouteBSigned8RootTreeReport) { value.OperationCounts.BroadcastRotations++ }},
		{"nested A2B", func(value *RouteBSigned8RootTreeReport) { value.FullA2B.OperationCounts.KernelInvocations++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, marshalErr := json.Marshal(base)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var mutated RouteBSigned8RootTreeReport
			if unmarshalErr := json.Unmarshal(encoded, &mutated); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			test.mutate(&mutated)
			mutated.Digest, err = digestRouteBSigned8RootTreeReport(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err = mutated.Validate(); err == nil {
				t.Fatal("self-consistent foreign report was accepted")
			}
		})
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}
