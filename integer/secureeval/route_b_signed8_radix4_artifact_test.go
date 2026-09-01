package secureeval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRouteBSigned8Radix4ReportRejectsSelfConsistentMutation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "research", "reproduction", "route_b", "route_b_signed8_radix4_2026-09-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result RouteBCanonicalSigned8Radix4Result `json:"result"`
	}
	if err = json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	base := envelope.Result.Radix4
	if err = base.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*RouteBSigned8Radix4Report)
	}{
		{"foreign threshold", func(value *RouteBSigned8Radix4Report) { value.Model.Thresholds[0]++ }},
		{"hidden path product", func(value *RouteBSigned8Radix4Report) { value.OperationCounts.PathCiphertextProducts++ }},
		{"lost output level", func(value *RouteBSigned8Radix4Report) { value.States[len(value.States)-1].Level-- }},
		{"equivalence proof", func(value *RouteBSigned8Radix4Report) {
			value.Ablation.ExhaustiveEquivalenceProofDigest = value.Ablation.EquivalentBinaryModelDigest
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, marshalErr := json.Marshal(base)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var mutated RouteBSigned8Radix4Report
			if unmarshalErr := json.Unmarshal(encoded, &mutated); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			test.mutate(&mutated)
			mutated.Digest, err = digestRouteBSigned8Radix4Report(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err = mutated.Validate(); err == nil {
				t.Fatal("self-consistent foreign radix-4 report was accepted")
			}
		})
	}
}
