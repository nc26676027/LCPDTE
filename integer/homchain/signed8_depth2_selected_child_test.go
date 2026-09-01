package homchain

import (
	"strings"
	"testing"

	"dt_go/integer/treeplan"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func TestSigned8Depth2SelectedChildProfileAndAdmission(t *testing.T) {
	tree := treeplan.BinaryTree[int8, float64]{
		Depth: 2,
		Splits: []treeplan.BinarySplit[int8]{
			{Feature: 2, Threshold: 1},
			{Feature: 0, Threshold: -2},
			{Feature: 3, Threshold: 3},
		},
		Leaves: []float64{-1.25, 2.5, -3.75, 5},
	}
	prefix := newSigned8Depth2ChildPrefixForTest(t)
	producer := prefix.selector.producer
	circuit, err := NewSigned8Depth2SelectedChildCircuit(producer, tree)
	if err != nil {
		t.Fatal(err)
	}
	profile := circuit.Profile()
	if profile.Fidelity() != Signed8Depth2SelectedChildFunctionalNotSecure ||
		profile.OperandMode() != Signed8PublicThresholdCTPT ||
		profile.RootThreshold() != 1 ||
		profile.FeatureIDs() != ([3]int{2, 0, 3}) ||
		profile.TreeDigest() == "" || profile.ScheduleDigest() == "" ||
		profile.RootThresholdPayloadDigest() == "" || profile.Digest() == "" {
		t.Fatalf("unexpected selected-child profile: %+v", profile)
	}
	if circuit.comparator != producer || circuit.selector.producer != producer ||
		circuit.prefix.selector != circuit.selector || circuit.child.prefix != circuit.prefix ||
		circuit.terminal.child != circuit.child {
		t.Fatal("selected-child circuit did not own one exact nested circuit graph")
	}

	features := make([]Signed8FeatureInput, 4)
	for featureID := range features {
		ciphertext := ckks.NewCiphertext(producer.params, 1, signed8InputLevel)
		// Give every feature a distinct authenticated payload without changing
		// the canonical metadata required by BindFeature.
		ciphertext.Value[0].Coeffs[0][0] = uint64(featureID + 1)
		features[featureID], err = producer.BindFeature(ciphertext, producer.params)
		if err != nil {
			t.Fatalf("bind feature %d: %v", featureID, err)
		}
	}
	input, err := circuit.BindFeatures(features)
	if err != nil {
		t.Fatal(err)
	}
	if input.FeatureIDs() != profile.FeatureIDs() || input.ProvenanceDigest() == "" {
		t.Fatalf("unexpected selected-child input: ids=%v provenance=%q", input.FeatureIDs(), input.ProvenanceDigest())
	}
	wantPayloads := [3]string{features[2].payloadDigest, features[0].payloadDigest, features[3].payloadDigest}
	if input.FeaturePayloadDigests() != wantPayloads {
		t.Fatalf("selected payload mapping=%v, want %v", input.FeaturePayloadDigests(), wantPayloads)
	}
	rootCopy := input.RootFeatureCiphertext()
	rootCopy.Value[0].Coeffs[0][0]++
	if rootAgain := input.RootFeatureCiphertext(); rootAgain.Equal(rootCopy) {
		t.Fatal("selected-child input leaked its owned root ciphertext")
	}

	if _, err = circuit.BindFeatures(features[:3]); err == nil || !strings.Contains(err.Error(), "feature 3") {
		t.Fatalf("missing referenced feature was not rejected: %v", err)
	}
	foreign := append([]Signed8FeatureInput(nil), features...)
	foreign[0].profileDigest = "foreign"
	if _, err = circuit.BindFeatures(foreign); err == nil {
		t.Fatal("foreign feature token was admitted")
	}
	mutated := append([]Signed8FeatureInput(nil), features...)
	mutated[3] = features[3]
	mutated[3].ciphertext = mutated[3].ciphertext.CopyNew()
	mutated[3].ciphertext.Value[0].Coeffs[0][0]++
	if _, err = circuit.BindFeatures(mutated); err == nil {
		t.Fatal("mutated feature payload was admitted")
	}
	if !features[2].ciphertext.Equal(input.root.ciphertext) || !features[0].ciphertext.Equal(input.left.ciphertext) ||
		!features[3].ciphertext.Equal(input.right.ciphertext) {
		t.Fatal("selected-child input did not preserve admitted ciphertext values")
	}
	if features[2].ciphertext == input.root.ciphertext || features[0].ciphertext == input.left.ciphertext ||
		features[3].ciphertext == input.right.ciphertext {
		t.Fatal("selected-child input retained caller-owned ciphertext pointers")
	}
}
