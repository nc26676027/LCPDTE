package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAcceptedBenchmarkSummariesReplay(t *testing.T) {
	tests := []struct {
		name, directory, file, design, fileSHA, summaryDigest, manifestDigest, decision string
		repetitions, fileBytes                                                          int
		triggered, passed                                                               bool
		binaryCircuitMedian, radixCircuitMedian, aggregateCircuitDelta                  float64
	}{
		{
			name: "fixed-ab", directory: "same_feature_radix4_2026-09-01", file: "summary_fixed_ab_v2.json",
			design: "fixed-ab", repetitions: 7, fileBytes: 31_216,
			fileSHA:        "91b6dd7639c12977c76e9392a9f297c3f0ab0af074fd0017dfb1bd1670c0ae0a",
			summaryDigest:  "6e7562bd99e1680aa7514c8dfa8f6e367b946f3a059f5d98ddd81d70f1aacac2",
			manifestDigest: "fca804225adcb0eb086b4f354d806aef52f889a4ca65180219277a091995e767",
			decision:       "DESCRIPTIVE_ORDER_CONFOUNDED", triggered: false, passed: false,
			binaryCircuitMedian: 36_664_779_600, radixCircuitMedian: 36_318_429_300, aggregateCircuitDelta: 276_635_100,
		},
		{
			name: "counterbalanced", directory: "same_feature_radix4_counterbalanced_2026-09-01", file: "summary.json",
			design: "counterbalanced", repetitions: 16, fileBytes: 52_871,
			fileSHA:        "f221ff7ca64b562a0d90f1ef7a380cc76fe4e919a092771466b820045d80aeee",
			summaryDigest:  "9188e9ac0c231cb4c5ab907fd791a7982e29e0f449984478e563c00c309f90a6",
			manifestDigest: "9d22092774a12dc21ef3869f416e08735c4380ce55c25fdd9a005ec81390b8ad",
			decision:       "PASS", triggered: true, passed: true,
			binaryCircuitMedian: 34_794_350_000, radixCircuitMedian: 33_422_884_650, aggregateCircuitDelta: 568_437_450,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join("..", "..", "research", "reproduction", "route_b", "benchmarks", test.directory)
			path := filepath.Join(directory, test.file)
			payload, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != test.fileBytes {
				t.Fatalf("summary bytes=%d, want %d", len(payload), test.fileBytes)
			}
			digest := sha256.Sum256(payload)
			if got := hex.EncodeToString(digest[:]); got != test.fileSHA {
				t.Fatalf("summary SHA-256=%s, want %s", got, test.fileSHA)
			}
			var accepted benchmarkSummary
			if err = json.Unmarshal(payload, &accepted); err != nil {
				t.Fatal(err)
			}
			assertAcceptedSummary(t, accepted, test.design, test.repetitions, test.triggered, test.passed,
				test.decision, test.summaryDigest, test.manifestDigest,
				test.binaryCircuitMedian, test.radixCircuitMedian, test.aggregateCircuitDelta)

			replayed, err := summarize(directory, test.design, test.repetitions)
			if err != nil {
				t.Fatalf("replay rejected accepted artifacts: %v", err)
			}
			assertAcceptedSummary(t, replayed, test.design, test.repetitions, test.triggered, test.passed,
				test.decision, test.summaryDigest, test.manifestDigest,
				test.binaryCircuitMedian, test.radixCircuitMedian, test.aggregateCircuitDelta)
		})
	}
}

func assertAcceptedSummary(
	t *testing.T, summary benchmarkSummary, design string, repetitions int, triggered, passed bool,
	decision, digest, manifest string, binaryCircuit, radixCircuit, aggregateDelta float64,
) {
	t.Helper()
	if summary.Schema != summarySchema || summary.Design != design || summary.RepetitionsPerArm != repetitions ||
		summary.ExtensionTriggered != triggered || summary.TimingDecision.RegisteredCriteriaPassed != passed ||
		summary.TimingDecision.Decision != decision || summary.SummaryDigest != digest ||
		summary.ArtifactManifestDigest != manifest || len(summary.Observations) != 2*repetitions {
		t.Fatalf("accepted benchmark identity changed: %+v", summary)
	}
	arm := func(name string) armSummary {
		for _, item := range summary.Arms {
			if item.Arm == name {
				return item
			}
		}
		t.Fatalf("missing arm %s", name)
		return armSummary{}
	}
	if arm("binary").Metrics["circuit_wall_nanoseconds"].Median != binaryCircuit ||
		arm("radix4").Metrics["circuit_wall_nanoseconds"].Median != radixCircuit ||
		summary.TimingDecision.AggregateCircuitBinaryMinusRadix4.Median != aggregateDelta {
		t.Fatalf("accepted benchmark medians changed: %+v", summary.TimingDecision)
	}
	for _, observation := range summary.Observations {
		if observation.ActiveMismatchCount != 0 || observation.InactiveMismatchCount != 0 ||
			observation.EquivalenceMismatchCount != 0 || observation.FileSHA256 == "" || observation.FileBytes == 0 {
			t.Fatalf("accepted observation failed correctness/hash ledger: %+v", observation)
		}
	}
}

func TestType7Quantile(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	if got := type7Quantile(values, 0.25); got != 2.75 {
		t.Fatalf("Q1=%v, want 2.75", got)
	}
	if got := type7Quantile(values, 0.5); got != 4.5 {
		t.Fatalf("median=%v, want 4.5", got)
	}
	if got := type7Quantile(values, 0.75); got != 6.25 {
		t.Fatalf("Q3=%v, want 6.25", got)
	}
}
