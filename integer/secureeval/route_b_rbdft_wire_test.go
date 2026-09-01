package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	rbdftFixtureLabel = "wire_fixture_only"
	rbdftFixtureScope = "canonical_wire_grammar_and_cross_record_identity_only"
)

func TestRBDFTTransformAggregateCanonicalRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		recordType byte
		role       byte
		factors    []independentRBDFTFactorRef
		parse      func([]byte) (RBDFTTransformAggregateReport, error)
		wantTotal  uint64
		wantHash   string
	}{
		{
			name: "type03 STC numeric", recordType: 0x03, role: 0x01,
			factors: []independentRBDFTFactorRef{
				{index: 0, digest: repeatedRBDFTDigest(0x21), recordBytes: 1001},
				{index: 1, digest: repeatedRBDFTDigest(0x22), recordBytes: 1002},
			},
			parse: ParseRBDFTNumericTransformAggregate, wantTotal: 2121,
			wantHash: "145580806501756f3e56b0f960fd641ada5b904a95b3723cefdb04cf83dd73c5",
		},
		{
			name: "type03 CTS numeric", recordType: 0x03, role: 0x02,
			factors: []independentRBDFTFactorRef{
				{index: 0, digest: repeatedRBDFTDigest(0x31), recordBytes: 2001},
				{index: 1, digest: repeatedRBDFTDigest(0x32), recordBytes: 2002},
				{index: 2, digest: repeatedRBDFTDigest(0x33), recordBytes: 2003},
			},
			parse: ParseRBDFTNumericTransformAggregate, wantTotal: 6168,
			wantHash: "89b364a21d82c9d7277cab7cbd7953f1a9026e43bcbfe5665199b74c53571816",
		},
		{
			name: "type04 STC encoded", recordType: 0x04, role: 0x01,
			factors: []independentRBDFTFactorRef{
				{index: 0, digest: repeatedRBDFTDigest(0x41), recordBytes: 3001},
				{index: 1, digest: repeatedRBDFTDigest(0x42), recordBytes: 3002},
			},
			parse: ParseRBDFTEncodedTransformAggregate, wantTotal: 6121,
			wantHash: "876994d8d663a7144b1b7ffd6f4142670f33773aeddc4e9afd1c2e6ffb8c116c",
		},
		{
			name: "type04 CTS encoded", recordType: 0x04, role: 0x02,
			factors: []independentRBDFTFactorRef{
				{index: 0, digest: repeatedRBDFTDigest(0x51), recordBytes: 4001},
				{index: 1, digest: repeatedRBDFTDigest(0x52), recordBytes: 4002},
				{index: 2, digest: repeatedRBDFTDigest(0x53), recordBytes: 4003},
			},
			parse: ParseRBDFTEncodedTransformAggregate, wantTotal: 12168,
			wantHash: "6124e32898edfd41d2908470ad796ae80925c279dd105bea710b859dfb855bd2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := independentRBDFTTransformAggregateFixture(test.recordType, test.role, test.factors)
			parsed, err := test.parse(fixture)
			if err != nil {
				t.Fatal(err)
			}
			got, err := marshalRBDFTTransformAggregate(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, fixture) {
				t.Fatalf("canonical aggregate round trip changed bytes\n got=%x\nwant=%x", got, fixture)
			}
			if parsed.Role != test.role || parsed.FactorCount != uint32(len(test.factors)) || parsed.AggregateRecordBytes != test.wantTotal {
				t.Fatalf("unexpected parsed aggregate: %+v", parsed)
			}
			independentRole, independentFactors, independentTotal, err := independentParseRBDFTTransformAggregateFixture(fixture)
			if err != nil {
				t.Fatalf("independent aggregate parser rejected fixture: %v", err)
			}
			if independentRole != parsed.Role || independentTotal != parsed.AggregateRecordBytes || len(independentFactors) != int(parsed.FactorCount) {
				t.Fatal("production and independent aggregate parsers disagree on framing")
			}
			for index, factor := range independentFactors {
				if parsed.Factors[index] != (RBDFTFactorRecordRef{Index: factor.index, Digest: factor.digest, RecordBytes: factor.recordBytes}) {
					t.Fatalf("production and independent aggregate parsers disagree at factor %d", index)
				}
			}
			fullHash := sha256.Sum256(fixture)
			if gotHash := rbdftHex(fullHash[:]); gotHash != test.wantHash {
				t.Fatalf("freeze %s SHA-256 as %s", test.name, gotHash)
			}
		})
	}
}

func TestRBDFTArtifactPairMatchesFrozenRBAUTHFixture(t *testing.T) {
	if rbdftFixtureLabel != "wire_fixture_only" ||
		rbdftFixtureScope != "canonical_wire_grammar_and_cross_record_identity_only" {
		t.Fatalf("fixture scope changed: label=%q scope=%q", rbdftFixtureLabel, rbdftFixtureScope)
	}
	_, _, _, _, _, pairRecord := goldenRBAUTHRecords(t)
	parsed, err := ParseRBDFTArtifactPairAggregate(pairRecord)
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalRBDFTArtifactPairAggregate(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pairRecord) {
		t.Fatal("production type05 parser/marshaler changed the frozen RBAUTH fixture")
	}
	if len(got) != 210 {
		t.Fatalf("type05 bytes=%d, want 210", len(got))
	}
	fullHash := sha256.Sum256(got)
	if gotHash := rbdftHex(fullHash[:]); gotHash != "f33c626d313523fbd61e0b8553502320dbe0815c36a79a579a31f8fb46c282fe" {
		t.Fatalf("frozen type05 SHA-256 changed: %s", gotHash)
	}
	independent, err := independentParseRBDFTPair(got)
	if err != nil {
		t.Fatalf("independent type05 parser rejected production bytes: %v", err)
	}
	if parsed.BuildPermitDigest != independent.buildPermitDigest ||
		parsed.Payload.STCNumeric != (RBAUTHPayloadTuple{AggregateDigest: independent.stcNumeric.digest, RecordBytes: independent.stcNumeric.recordBytes}) ||
		parsed.Payload.STCEncoded != (RBAUTHPayloadTuple{AggregateDigest: independent.stcEncoded.digest, RecordBytes: independent.stcEncoded.recordBytes}) ||
		parsed.Payload.CTSNumeric != (RBAUTHPayloadTuple{AggregateDigest: independent.ctsNumeric.digest, RecordBytes: independent.ctsNumeric.recordBytes}) ||
		parsed.Payload.CTSEncoded != (RBAUTHPayloadTuple{AggregateDigest: independent.ctsEncoded.digest, RecordBytes: independent.ctsEncoded.recordBytes}) {
		t.Fatal("production and independent type05 parsers disagree")
	}
}

func TestRBDFTLifecycleSuccessCanonicalRoundTrip(t *testing.T) {
	events := independentRBDFTSuccessLifecycleEvents()
	fixture := independentRBDFTLifecycleFixture(1, uint32(len(events)), uint32(len(events)), 0, events)
	parsed, err := ParseRBDFTLifecycle(fixture)
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalRBDFTLifecycle(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatalf("canonical lifecycle round trip changed bytes\n got=%x\nwant=%x", got, fixture)
	}
	if len(got) != 1848 || parsed.TerminalStatus != 1 || parsed.CompletedEventCount != 35 ||
		parsed.AttemptedEventLowerBound != 35 || parsed.FailureStage != 0 {
		t.Fatalf("unexpected success lifecycle report: bytes=%d report=%+v", len(got), parsed)
	}
	independentStatus, independentCompleted, independentAttempted, independentFailure, independentEvents, err := independentParseRBDFTLifecycleFixture(fixture)
	if err != nil {
		t.Fatalf("independent lifecycle parser rejected fixture: %v", err)
	}
	if independentStatus != parsed.TerminalStatus || independentCompleted != parsed.CompletedEventCount ||
		independentAttempted != parsed.AttemptedEventLowerBound || independentFailure != parsed.FailureStage ||
		len(independentEvents) != len(parsed.Events()) {
		t.Fatal("production and independent lifecycle parsers disagree on framing")
	}
	for index, event := range independentEvents {
		production := parsed.Events()[index]
		if production != (RBDFTLifecycleEvent{
			Sequence: event.sequence, Source: event.source, Code: event.code, Role: event.role,
			FactorIndex: event.factorIndex, PayloadKind: event.payloadKind,
			PayloadDigest: event.digest, Value: event.value,
		}) {
			t.Fatalf("production and independent lifecycle parsers disagree at event %d", index)
		}
	}
	fullHash := sha256.Sum256(got)
	if gotHash := rbdftHex(fullHash[:]); gotHash != "4db54a4ad120b8863525e3ec3e1c7206efed5c4ca6bbde7550912bcc83539fb8" {
		t.Fatalf("freeze type06 success lifecycle SHA-256 as %s", gotHash)
	}
	first := parsed.Events()
	second := parsed.Events()
	if len(first) != 35 || len(second) != 35 {
		t.Fatalf("event accessor lengths=%d/%d, want 35/35", len(first), len(second))
	}
	first[0].Code = 0xff
	if parsed.Events()[0].Code != 0x01 {
		t.Fatal("lifecycle event accessor exposed mutable report backing storage")
	}
}

func TestRBDFTBuildReceiptMatchesFrozenRBAUTHFixture(t *testing.T) {
	_, _, _, _, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	parsed, err := ParseRBDFTBuildReceipt(receiptRecord)
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalRBDFTBuildReceipt(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, receiptRecord) {
		t.Fatal("production type07 parser/marshaler changed the frozen RBAUTH fixture")
	}
	if len(got) != 585 {
		t.Fatalf("type07 bytes=%d, want 585", len(got))
	}
	fullHash := sha256.Sum256(got)
	if gotHash := rbdftHex(fullHash[:]); gotHash != "aae3c2b57e19b3ebd04194e438ae1c826bd82b55e5e9f895419771e27948913a" {
		t.Fatalf("frozen type07 SHA-256 changed: %s", gotHash)
	}
	independent, err := independentParseRBDFTReceipt(got)
	if err != nil {
		t.Fatalf("independent type07 parser rejected production bytes: %v", err)
	}
	if parsed.BuildPermitDigest != independent.buildPermitDigest ||
		parsed.PreparedParameterDigest != independent.preparedParameterDigest ||
		parsed.LifecycleDigest != independent.lifecycleDigest ||
		parsed.ArtifactManifestDigest != independent.artifactManifestDigest ||
		parsed.ArtifactManifestDigest != RBAUTHDigest(sha256.Sum256(pairRecord)) {
		t.Fatal("production and independent type07 parsers disagree on digest links")
	}
	if parsed.BuilderID != independent.builderID || parsed.DigestID != independent.digestID ||
		parsed.AllocationID != independent.allocationID || parsed.ReleaseID != independent.releaseID ||
		parsed.OwnershipID != independent.ownershipID ||
		parsed.GeneratorPrecisionBits != independent.generatorPrecision ||
		parsed.EncoderPrecisionBits != independent.encoderPrecision ||
		parsed.DefaultCounterDelta != independent.defaultCounterDelta ||
		parsed.ExplicitWholeCounterDelta != independent.explicitCounterDelta ||
		parsed.RawNumericCounterDelta != independent.rawNumericCounterDelta ||
		parsed.ObservedStreamingCounterDelta != independent.observedCounterDelta ||
		parsed.MaxLiveNumeric != independent.maxLiveNumeric ||
		parsed.STCFactorCount != independent.stcFactorCount || parsed.CTSFactorCount != independent.ctsFactorCount ||
		parsed.Payload.STCNumeric != (RBAUTHPayloadTuple{AggregateDigest: independent.stcNumeric.digest, RecordBytes: independent.stcNumeric.recordBytes}) ||
		parsed.Payload.STCEncoded != (RBAUTHPayloadTuple{AggregateDigest: independent.stcEncoded.digest, RecordBytes: independent.stcEncoded.recordBytes}) ||
		parsed.Payload.CTSNumeric != (RBAUTHPayloadTuple{AggregateDigest: independent.ctsNumeric.digest, RecordBytes: independent.ctsNumeric.recordBytes}) ||
		parsed.Payload.CTSEncoded != (RBAUTHPayloadTuple{AggregateDigest: independent.ctsEncoded.digest, RecordBytes: independent.ctsEncoded.recordBytes}) ||
		parsed.BuildWallNanoseconds != independent.buildWallNanoseconds ||
		parsed.BuildPeakRSSBytes != independent.buildPeakRSSBytes || parsed.ArtifactState != independent.artifactState {
		t.Fatal("production and independent type07 parsers disagree on receipt semantics")
	}
	if _, exists := reflect.TypeOf(parsed).MethodByName("MarshalBinary"); exists {
		t.Fatal("public inert receipt report unexpectedly exposes a minting marshaler")
	}
}

func TestRBDFTBuildRecordLinksCanonicalAndTamperEvident(t *testing.T) {
	records, buildPermitDigest, preparedParameterDigest := independentRBDFTLinkedFixture(t)
	if err := ValidateRBDFTBuildRecordLinks(records, buildPermitDigest, preparedParameterDigest); err != nil {
		t.Fatal(err)
	}

	t.Run("aggregate identity", func(t *testing.T) {
		mutated := records
		mutated.STCNumericAggregate = append([]byte(nil), records.STCNumericAggregate...)
		mutated.STCNumericAggregate[30] ^= 1
		if err := ValidateRBDFTBuildRecordLinks(mutated, buildPermitDigest, preparedParameterDigest); !errors.Is(err, ErrRBDFTBlocked) {
			t.Fatalf("aggregate digest mutation error=%v, want blocked", err)
		}
	})
	t.Run("lifecycle payload identity", func(t *testing.T) {
		mutated := records
		mutated.Lifecycle = append([]byte(nil), records.Lifecycle...)
		// First numeric-digested payload starts at event 4. Its digest begins
		// after the 18-byte header, 10-byte prefix, four 52-byte events and
		// the 12-byte event metadata.
		mutated.Lifecycle[18+10+4*52+12] ^= 1
		mutated.BuildReceipt = independentRBDFTRebindReceiptLifecycleDigest(t, records.BuildReceipt, mutated.Lifecycle)
		if err := ValidateRBDFTBuildRecordLinks(mutated, buildPermitDigest, preparedParameterDigest); !errors.Is(err, ErrRBDFTBlocked) || !strings.Contains(err.Error(), "lifecycle factor digest") {
			t.Fatalf("lifecycle payload mutation error=%v, want blocked", err)
		}
	})
	t.Run("artifact sealed lifecycle identity", func(t *testing.T) {
		mutated := records
		mutated.Lifecycle = append([]byte(nil), records.Lifecycle...)
		mutated.Lifecycle[18+10+33*52+12] ^= 1
		mutated.BuildReceipt = independentRBDFTRebindReceiptLifecycleDigest(t, records.BuildReceipt, mutated.Lifecycle)
		if err := ValidateRBDFTBuildRecordLinks(mutated, buildPermitDigest, preparedParameterDigest); !errors.Is(err, ErrRBDFTBlocked) || !strings.Contains(err.Error(), "artifact-sealed") {
			t.Fatalf("artifact-sealed mutation error=%v, want deep blocked link", err)
		}
	})
	t.Run("pair manifest identity", func(t *testing.T) {
		mutated := records
		mutated.ArtifactPair = append([]byte(nil), records.ArtifactPair...)
		mutated.ArtifactPair[60] ^= 1
		if err := ValidateRBDFTBuildRecordLinks(mutated, buildPermitDigest, preparedParameterDigest); !errors.Is(err, ErrRBDFTBlocked) {
			t.Fatalf("pair mutation error=%v, want blocked", err)
		}
	})
	t.Run("expected build permit", func(t *testing.T) {
		foreign := buildPermitDigest
		foreign[0] ^= 1
		if err := ValidateRBDFTBuildRecordLinks(records, foreign, preparedParameterDigest); !errors.Is(err, ErrRBDFTBlocked) {
			t.Fatalf("foreign build permit error=%v, want blocked", err)
		}
	})
	t.Run("expected prepared parameters", func(t *testing.T) {
		foreign := preparedParameterDigest
		foreign[0] ^= 1
		if err := ValidateRBDFTBuildRecordLinks(records, buildPermitDigest, foreign); !errors.Is(err, ErrRBDFTBlocked) {
			t.Fatalf("foreign prepared parameters error=%v, want blocked", err)
		}
	})
}

func TestRBDFTFailureLifecycleCanonicalPrefixes(t *testing.T) {
	allEvents := independentRBDFTSuccessLifecycleEvents()
	for completed := uint32(0); completed < 35; completed++ {
		t.Run(fmt.Sprintf("completed-%02d", completed), func(t *testing.T) {
			fixture := independentRBDFTLifecycleFixture(
				2,
				completed,
				completed+1,
				independentRBDFTFailureStage(completed),
				allEvents[:completed],
			)
			parsed, err := ParseRBDFTLifecycle(fixture)
			if err != nil {
				t.Fatal(err)
			}
			got, err := marshalRBDFTLifecycle(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, fixture) {
				t.Fatal("failure lifecycle prefix did not round-trip canonically")
			}
		})
	}

	fixture := independentRBDFTLifecycleFixture(2, 15, 15, 5, allEvents[:15])
	if _, err := ParseRBDFTLifecycle(fixture); err != nil {
		t.Fatalf("failure prefix without an incomplete event dispatch was rejected: %v", err)
	}
}

func TestRBDFTFailureLifecycleRejectsInvalidBoundsAndStage(t *testing.T) {
	allEvents := independentRBDFTSuccessLifecycleEvents()
	tests := []struct {
		name      string
		completed uint32
		attempted uint32
		stage     byte
		events    []independentRBDFTLifecycleEventFixture
	}{
		{name: "attempted below completed", completed: 15, attempted: 14, stage: 5, events: allEvents[:15]},
		{name: "attempted beyond one in-flight dispatch", completed: 15, attempted: 17, stage: 5, events: allEvents[:15]},
		{name: "wrong failure stage", completed: 15, attempted: 16, stage: 3, events: allEvents[:15]},
		{name: "failure after complete success sequence", completed: 35, attempted: 35, stage: 0, events: allEvents},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := independentRBDFTLifecycleFixture(2, test.completed, test.attempted, test.stage, test.events)
			parsed, err := ParseRBDFTLifecycle(fixture)
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTLifecycleReport{}) {
				t.Fatalf("report=%+v error=%v, want zero/malformed", parsed, err)
			}
		})
	}
}

func TestRBDFTParsersAreBoundedExactAndZeroOnError(t *testing.T) {
	records, _, _ := independentRBDFTLinkedFixture(t)

	t.Run("aggregate", func(t *testing.T) {
		base := records.STCNumericAggregate
		mutations := map[string]func([]byte) []byte{
			"truncated":           func(value []byte) []byte { return value[:len(value)-1] },
			"trailing":            func(value []byte) []byte { return append(value, 0) },
			"oversize":            func(value []byte) []byte { return append(value, make([]byte, 100)...) },
			"wrong type":          func(value []byte) []byte { value[16] = 0x04; return value },
			"zero role":           func(value []byte) []byte { value[17] = 0; return value },
			"max count":           func(value []byte) []byte { binary.LittleEndian.PutUint32(value[18:22], ^uint32(0)); return value },
			"noncontiguous index": func(value []byte) []byte { binary.LittleEndian.PutUint32(value[22:26], 1); return value },
			"zero digest":         func(value []byte) []byte { clear(value[26:58]); return value },
			"zero bytes":          func(value []byte) []byte { clear(value[58:66]); return value },
			"overflowed ledger":   func(value []byte) []byte { binary.LittleEndian.PutUint64(value[58:66], ^uint64(0)); return value },
			"wrong ledger":        func(value []byte) []byte { value[len(value)-1] ^= 1; return value },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				candidate := mutate(append([]byte(nil), base...))
				parsed, err := ParseRBDFTNumericTransformAggregate(candidate)
				if !errors.Is(err, ErrRBDFTMalformed) {
					t.Fatalf("error=%v, want malformed", err)
				}
				if parsed != (RBDFTTransformAggregateReport{}) {
					t.Fatalf("error returned nonzero report: %+v", parsed)
				}
			})
		}
		if parsed, err := ParseRBDFTEncodedTransformAggregate(base); !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTTransformAggregateReport{}) {
			t.Fatalf("type04 parser accepted type03 record: report=%+v error=%v", parsed, err)
		}
	})

	t.Run("pair", func(t *testing.T) {
		base := records.ArtifactPair
		mutations := map[string]func([]byte) []byte{
			"truncated":         func(value []byte) []byte { return value[:len(value)-1] },
			"trailing":          func(value []byte) []byte { return append(value, 0) },
			"wrong role":        func(value []byte) []byte { value[17] = 1; return value },
			"zero permit":       func(value []byte) []byte { clear(value[18:50]); return value },
			"zero tuple digest": func(value []byte) []byte { clear(value[50:82]); return value },
			"zero tuple bytes":  func(value []byte) []byte { clear(value[82:90]); return value },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				parsed, err := ParseRBDFTArtifactPairAggregate(mutate(append([]byte(nil), base...)))
				if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTArtifactPairReport{}) {
					t.Fatalf("report=%+v error=%v, want zero/malformed", parsed, err)
				}
			})
		}
	})

	t.Run("lifecycle", func(t *testing.T) {
		base := records.Lifecycle
		mutations := map[string]func([]byte) []byte{
			"truncated":                func(value []byte) []byte { return value[:len(value)-1] },
			"trailing":                 func(value []byte) []byte { return append(value, 0) },
			"wrong role":               func(value []byte) []byte { value[17] = 1; return value },
			"bad status":               func(value []byte) []byte { value[18] = 3; return value },
			"max count":                func(value []byte) []byte { binary.LittleEndian.PutUint32(value[19:23], ^uint32(0)); return value },
			"attempt mismatch":         func(value []byte) []byte { binary.LittleEndian.PutUint32(value[23:27], 34); return value },
			"failure stage on success": func(value []byte) []byte { value[27] = 1; return value },
			"sequence gap":             func(value []byte) []byte { binary.LittleEndian.PutUint32(value[28:32], 1); return value },
			"source drift":             func(value []byte) []byte { value[32] = 2; return value },
			"payload on empty event":   func(value []byte) []byte { value[39] = 1; return value },
			"precision drift":          func(value []byte) []byte { binary.LittleEndian.PutUint64(value[28+52+44:28+52+52], 255); return value },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				parsed, err := ParseRBDFTLifecycle(mutate(append([]byte(nil), base...)))
				if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTLifecycleReport{}) {
					t.Fatalf("report=%+v error=%v, want zero/malformed", parsed, err)
				}
			})
		}
		if events := (RBDFTLifecycleReport{CompletedEventCount: 36}).Events(); events != nil {
			t.Fatal("invalid caller-created lifecycle report caused a non-nil event view")
		}
	})

	t.Run("receipt", func(t *testing.T) {
		base := records.BuildReceipt
		generatorPrecisionOffset := independentRBDFTReceiptPrecisionOffset(t, base)
		mutations := map[string]func([]byte) []byte{
			"truncated":   func(value []byte) []byte { return value[:len(value)-1] },
			"trailing":    func(value []byte) []byte { return append(value, 0) },
			"oversize":    func(value []byte) []byte { return append(value, make([]byte, 2000)...) },
			"wrong role":  func(value []byte) []byte { value[17] = 1; return value },
			"zero permit": func(value []byte) []byte { clear(value[18:50]); return value },
			"max string":  func(value []byte) []byte { binary.LittleEndian.PutUint32(value[82:86], ^uint32(0)); return value },
			"precision drift": func(value []byte) []byte {
				binary.LittleEndian.PutUint32(value[generatorPrecisionOffset:generatorPrecisionOffset+4], 255)
				return value
			},
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				parsed, err := ParseRBDFTBuildReceipt(mutate(append([]byte(nil), base...)))
				if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTBuildReceiptReport{}) {
					t.Fatalf("report=%+v error=%v, want zero/malformed", parsed, err)
				}
			})
		}
	})
}

func TestRBDFTAndRBAUTHDomainsRejectEachOther(t *testing.T) {
	records, _, _ := independentRBDFTLinkedFixture(t)
	spec := goldenArtifactBuildSpec(t)
	rbauthRecord, err := spec.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseRBDFTBuildReceipt(rbauthRecord); !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTBuildReceiptReport{}) {
		t.Fatalf("RBDFT parser accepted RBAUTH: report=%+v error=%v", parsed, err)
	}
	if parsed, err := ParseArtifactBuildSpec(records.BuildReceipt); !errors.Is(err, ErrRBAUTHMalformed) || !reflect.DeepEqual(parsed, ArtifactBuildSpec{}) {
		t.Fatalf("RBAUTH parser accepted RBDFT: report=%+v error=%v", parsed, err)
	}
}

func FuzzRBDFTMetadataParsersBounded(f *testing.F) {
	records, _, _ := independentRBDFTLinkedFixture(f)
	for _, seed := range [][]byte{
		records.STCNumericAggregate, records.STCEncodedAggregate,
		records.CTSNumericAggregate, records.CTSEncodedAggregate,
		records.ArtifactPair, records.Lifecycle, records.BuildReceipt,
		{}, []byte("LCPDTE-RBDFT-v1\x00"), bytes.Repeat([]byte{0xff}, 4096),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if parsed, err := ParseRBDFTNumericTransformAggregate(encoded); err != nil {
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTTransformAggregateReport{}) {
				t.Fatalf("numeric aggregate error returned nonzero/wrong-domain result: %+v %v", parsed, err)
			}
		}
		if parsed, err := ParseRBDFTEncodedTransformAggregate(encoded); err != nil {
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTTransformAggregateReport{}) {
				t.Fatalf("encoded aggregate error returned nonzero/wrong-domain result: %+v %v", parsed, err)
			}
		}
		if parsed, err := ParseRBDFTArtifactPairAggregate(encoded); err != nil {
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTArtifactPairReport{}) {
				t.Fatalf("pair error returned nonzero/wrong-domain result: %+v %v", parsed, err)
			}
		}
		if parsed, err := ParseRBDFTLifecycle(encoded); err != nil {
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTLifecycleReport{}) {
				t.Fatalf("lifecycle error returned nonzero/wrong-domain result: %+v %v", parsed, err)
			}
		}
		if parsed, err := ParseRBDFTBuildReceipt(encoded); err != nil {
			if !errors.Is(err, ErrRBDFTMalformed) || parsed != (RBDFTBuildReceiptReport{}) {
				t.Fatalf("receipt error returned nonzero/wrong-domain result: %+v %v", parsed, err)
			}
		}
	})
}

func independentRBDFTFailureStage(nextSequence uint32) byte {
	switch {
	case nextSequence == 0:
		return 1
	case nextSequence == 1:
		return 2
	case nextSequence >= 2 && nextSequence <= 13:
		return 3
	case nextSequence == 14:
		return 4
	case nextSequence >= 15 && nextSequence <= 31:
		return 5
	case nextSequence == 32:
		return 6
	case nextSequence == 33:
		return 7
	case nextSequence == 34:
		return 8
	default:
		return 0
	}
}

func independentRBDFTReceiptPrecisionOffset(t *testing.T, record []byte) int {
	t.Helper()
	offset := len("LCPDTE-RBDFT-v1\x00") + 2 + 2*sha256.Size
	for index := 0; index < 5; index++ {
		if offset > len(record)-4 {
			t.Fatal("receipt fixture truncated before identifier length")
		}
		length := int(binary.LittleEndian.Uint32(record[offset : offset+4]))
		offset += 4
		if length <= 0 || offset > len(record)-length {
			t.Fatal("receipt fixture has invalid identifier length")
		}
		offset += length
	}
	return offset
}

func independentRBDFTRebindReceiptLifecycleDigest(t *testing.T, receipt, lifecycle []byte) []byte {
	t.Helper()
	result := append([]byte(nil), receipt...)
	offset := independentRBDFTReceiptPrecisionOffset(t, result) + 2*4 + 4*8
	if offset > len(result)-sha256.Size {
		t.Fatal("receipt fixture truncated before lifecycle digest")
	}
	digest := sha256.Sum256(lifecycle)
	copy(result[offset:offset+sha256.Size], digest[:])
	return result
}

type independentRBDFTFactorRef struct {
	index       uint32
	digest      RBAUTHDigest
	recordBytes uint64
}

type independentRBDFTLifecycleEventFixture struct {
	sequence    uint32
	source      byte
	code        byte
	role        byte
	factorIndex int32
	payloadKind byte
	digest      RBAUTHDigest
	value       uint64
}

func independentRBDFTSuccessLifecycleEvents() []independentRBDFTLifecycleEventFixture {
	events := make([]independentRBDFTLifecycleEventFixture, 0, 35)
	appendEvent := func(source, code, role byte, factorIndex int32, payloadKind byte, digest RBAUTHDigest, value uint64) {
		events = append(events, independentRBDFTLifecycleEventFixture{
			sequence: uint32(len(events)), source: source, code: code, role: role,
			factorIndex: factorIndex, payloadKind: payloadKind, digest: digest, value: value,
		})
	}
	appendEvent(1, 0x01, 0, -1, 0, RBAUTHDigest{}, 0)
	appendEvent(1, 0x02, 0, -1, 0x04, RBAUTHDigest{}, 256)
	for _, roleAndCount := range [][2]byte{{1, 2}, {2, 3}} {
		role, count := roleAndCount[0], roleAndCount[1]
		appendEvent(2, 0x03, role, -1, 0, RBAUTHDigest{}, 0)
		for index := byte(0); index < count; index++ {
			appendEvent(2, 0x04, role, int32(index), 0, RBAUTHDigest{}, 0)
			appendEvent(2, 0x05, role, int32(index), 0x01, repeatedRBDFTDigest(0x60+role*8+index), 1000+uint64(role)*100+uint64(index))
			appendEvent(2, 0x06, role, int32(index), 0, RBAUTHDigest{}, 0)
			appendEvent(2, 0x07, role, int32(index), 0x02, repeatedRBDFTDigest(0x70+role*8+index), 2000+uint64(role)*100+uint64(index))
			appendEvent(2, 0x08, role, int32(index), 0, RBAUTHDigest{}, 0)
		}
		appendEvent(2, 0x09, role, -1, 0, RBAUTHDigest{}, 0)
		appendEvent(2, 0x0a, role, -1, 0, RBAUTHDigest{}, 0)
	}
	appendEvent(1, 0x0b, 0, -1, 0x03, repeatedRBDFTDigest(0x7f), 210)
	appendEvent(1, 0x0c, 0, -1, 0, RBAUTHDigest{}, 0)
	return events
}

func independentRBDFTLifecycleFixture(status byte, completed, attempted uint32, failureStage byte, events []independentRBDFTLifecycleEventFixture) []byte {
	var body bytes.Buffer
	_ = body.WriteByte(status)
	_ = binary.Write(&body, binary.LittleEndian, completed)
	_ = binary.Write(&body, binary.LittleEndian, attempted)
	_ = body.WriteByte(failureStage)
	for _, event := range events {
		_ = binary.Write(&body, binary.LittleEndian, event.sequence)
		_ = body.WriteByte(event.source)
		_ = body.WriteByte(event.code)
		_ = body.WriteByte(event.role)
		_ = binary.Write(&body, binary.LittleEndian, event.factorIndex)
		_ = body.WriteByte(event.payloadKind)
		_, _ = body.Write(event.digest[:])
		_ = binary.Write(&body, binary.LittleEndian, event.value)
	}
	record := append([]byte("LCPDTE-RBDFT-v1\x00"), byte(0x06), byte(0))
	return append(record, body.Bytes()...)
}

func independentParseRBDFTLifecycleFixture(record []byte) (byte, uint32, uint32, byte, []independentRBDFTLifecycleEventFixture, error) {
	if len(record) < 18 || !bytes.Equal(record[:16], []byte("LCPDTE-RBDFT-v1\x00")) || record[16] != 0x06 || record[17] != 0 {
		return 0, 0, 0, 0, nil, errors.New("independent lifecycle header rejected")
	}
	cursor := independentRBDFTFixtureCursor{data: record[18:]}
	status, err := cursor.u8()
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	completed, err := cursor.u32()
	if err != nil || completed > 35 {
		return 0, 0, 0, 0, nil, errors.New("independent lifecycle count rejected")
	}
	attempted, err := cursor.u32()
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	failure, err := cursor.u8()
	if err != nil {
		return 0, 0, 0, 0, nil, err
	}
	events := make([]independentRBDFTLifecycleEventFixture, completed)
	for index := range events {
		event := &events[index]
		if event.sequence, err = cursor.u32(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		if event.source, err = cursor.u8(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		if event.code, err = cursor.u8(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		if event.role, err = cursor.u8(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		factorIndex, readErr := cursor.u32()
		if readErr != nil {
			return 0, 0, 0, 0, nil, readErr
		}
		event.factorIndex = int32(factorIndex)
		if event.payloadKind, err = cursor.u8(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		if event.digest, err = cursor.digest(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
		if event.value, err = cursor.u64(); err != nil {
			return 0, 0, 0, 0, nil, err
		}
	}
	if cursor.offset != len(cursor.data) {
		return 0, 0, 0, 0, nil, errors.New("independent lifecycle EOF rejected")
	}
	return status, completed, attempted, failure, events, nil
}

func independentRBDFTLinkedFixture(t testing.TB) (RBDFTBuildRecordSet, RBAUTHDigest, RBAUTHDigest) {
	t.Helper()
	stcNumeric := independentRBDFTTransformAggregateFixture(0x03, 0x01, []independentRBDFTFactorRef{
		{index: 0, digest: repeatedRBDFTDigest(0x68), recordBytes: 1100},
		{index: 1, digest: repeatedRBDFTDigest(0x69), recordBytes: 1101},
	})
	stcEncoded := independentRBDFTTransformAggregateFixture(0x04, 0x01, []independentRBDFTFactorRef{
		{index: 0, digest: repeatedRBDFTDigest(0x78), recordBytes: 2100},
		{index: 1, digest: repeatedRBDFTDigest(0x79), recordBytes: 2101},
	})
	ctsNumeric := independentRBDFTTransformAggregateFixture(0x03, 0x02, []independentRBDFTFactorRef{
		{index: 0, digest: repeatedRBDFTDigest(0x70), recordBytes: 1200},
		{index: 1, digest: repeatedRBDFTDigest(0x71), recordBytes: 1201},
		{index: 2, digest: repeatedRBDFTDigest(0x72), recordBytes: 1202},
	})
	ctsEncoded := independentRBDFTTransformAggregateFixture(0x04, 0x02, []independentRBDFTFactorRef{
		{index: 0, digest: repeatedRBDFTDigest(0x80), recordBytes: 2200},
		{index: 1, digest: repeatedRBDFTDigest(0x81), recordBytes: 2201},
		{index: 2, digest: repeatedRBDFTDigest(0x82), recordBytes: 2202},
	})
	payload := RBAUTHActualPayload{
		STCNumeric: RBAUTHPayloadTuple{AggregateDigest: RBAUTHDigest(sha256.Sum256(stcNumeric)), RecordBytes: 2319},
		STCEncoded: RBAUTHPayloadTuple{AggregateDigest: RBAUTHDigest(sha256.Sum256(stcEncoded)), RecordBytes: 4319},
		CTSNumeric: RBAUTHPayloadTuple{AggregateDigest: RBAUTHDigest(sha256.Sum256(ctsNumeric)), RecordBytes: 3765},
		CTSEncoded: RBAUTHPayloadTuple{AggregateDigest: RBAUTHDigest(sha256.Sum256(ctsEncoded)), RecordBytes: 6765},
	}
	buildPermitDigest := repeatedRBDFTDigest(0x91)
	preparedParameterDigest := repeatedRBDFTDigest(0x92)
	pair := independentRBDFTArtifactPairFixture(buildPermitDigest, payload)
	events := independentRBDFTSuccessLifecycleEvents()
	events[33].digest = RBAUTHDigest(sha256.Sum256(pair))
	lifecycle := independentRBDFTLifecycleFixture(1, 35, 35, 0, events)
	receipt := independentRBDFTBuildReceiptFixture(
		buildPermitDigest,
		preparedParameterDigest,
		RBAUTHDigest(sha256.Sum256(lifecycle)),
		payload,
		RBAUTHDigest(sha256.Sum256(pair)),
	)
	return RBDFTBuildRecordSet{
		STCNumericAggregate: stcNumeric,
		STCEncodedAggregate: stcEncoded,
		CTSNumericAggregate: ctsNumeric,
		CTSEncodedAggregate: ctsEncoded,
		ArtifactPair:        pair,
		Lifecycle:           lifecycle,
		BuildReceipt:        receipt,
	}, buildPermitDigest, preparedParameterDigest
}

func independentRBDFTArtifactPairFixture(buildPermitDigest RBAUTHDigest, payload RBAUTHActualPayload) []byte {
	var body bytes.Buffer
	_, _ = body.Write(buildPermitDigest[:])
	for _, tuple := range []RBAUTHPayloadTuple{
		payload.STCNumeric, payload.STCEncoded, payload.CTSNumeric, payload.CTSEncoded,
	} {
		_, _ = body.Write(tuple.AggregateDigest[:])
		_ = binary.Write(&body, binary.LittleEndian, tuple.RecordBytes)
	}
	record := append([]byte("LCPDTE-RBDFT-v1\x00"), byte(0x05), byte(0))
	return append(record, body.Bytes()...)
}

func independentRBDFTBuildReceiptFixture(
	buildPermitDigest, preparedParameterDigest, lifecycleDigest RBAUTHDigest,
	payload RBAUTHActualPayload,
	manifestDigest RBAUTHDigest,
) []byte {
	var body bytes.Buffer
	_, _ = body.Write(buildPermitDigest[:])
	_, _ = body.Write(preparedParameterDigest[:])
	for _, identifier := range []string{
		"lattigo-route-b-prebuilt-dft-streaming-builder-v1",
		"sha256-canonical-streaming-binary-v1",
		"stc-then-cts-single-factor-v1",
		"logical-reference-drop-v1",
		"private-exclusive-transfer-v1",
	} {
		_ = binary.Write(&body, binary.LittleEndian, uint32(len(identifier)))
		_, _ = body.WriteString(identifier)
	}
	_ = binary.Write(&body, binary.LittleEndian, uint32(256))
	_ = binary.Write(&body, binary.LittleEndian, uint32(256))
	for _, delta := range []uint64{0, 0, 0, 2} {
		_ = binary.Write(&body, binary.LittleEndian, delta)
	}
	_, _ = body.Write(lifecycleDigest[:])
	for _, count := range []uint32{1, 2, 3} {
		_ = binary.Write(&body, binary.LittleEndian, count)
	}
	tuples := []RBAUTHPayloadTuple{
		payload.STCNumeric, payload.STCEncoded, payload.CTSNumeric, payload.CTSEncoded,
	}
	for _, tuple := range tuples {
		_, _ = body.Write(tuple.AggregateDigest[:])
	}
	for _, tuple := range tuples {
		_ = binary.Write(&body, binary.LittleEndian, tuple.RecordBytes)
	}
	_ = binary.Write(&body, binary.LittleEndian, uint64(123456789))
	_ = binary.Write(&body, binary.LittleEndian, uint64(2968063744))
	state := "private-uninstalled"
	_ = binary.Write(&body, binary.LittleEndian, uint32(len(state)))
	_, _ = body.WriteString(state)
	_, _ = body.Write(manifestDigest[:])
	record := append([]byte("LCPDTE-RBDFT-v1\x00"), byte(0x07), byte(0))
	return append(record, body.Bytes()...)
}

func independentRBDFTTransformAggregateFixture(recordType, role byte, factors []independentRBDFTFactorRef) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, uint32(len(factors)))
	var total uint64 = uint64(len("LCPDTE-RBDFT-v1\x00") + 2 + 4 + len(factors)*(4+sha256.Size+8) + 8)
	for _, factor := range factors {
		_ = binary.Write(&body, binary.LittleEndian, factor.index)
		_, _ = body.Write(factor.digest[:])
		_ = binary.Write(&body, binary.LittleEndian, factor.recordBytes)
		total += factor.recordBytes
	}
	_ = binary.Write(&body, binary.LittleEndian, total)
	record := append([]byte("LCPDTE-RBDFT-v1\x00"), recordType, role)
	return append(record, body.Bytes()...)
}

func independentParseRBDFTTransformAggregateFixture(record []byte) (byte, []independentRBDFTFactorRef, uint64, error) {
	if len(record) < 18 || !bytes.Equal(record[:16], []byte("LCPDTE-RBDFT-v1\x00")) ||
		(record[16] != 0x03 && record[16] != 0x04) || (record[17] != 1 && record[17] != 2) {
		return 0, nil, 0, errors.New("independent aggregate header rejected")
	}
	cursor := independentRBDFTFixtureCursor{data: record[18:]}
	count, err := cursor.u32()
	if err != nil || count == 0 || count > 3 || (record[17] == 1 && count != 2) || (record[17] == 2 && count != 3) {
		return 0, nil, 0, errors.New("independent aggregate count rejected")
	}
	factors := make([]independentRBDFTFactorRef, count)
	total := uint64(18 + 4 + int(count)*(4+32+8) + 8)
	for index := uint32(0); index < count; index++ {
		factor := &factors[index]
		if factor.index, err = cursor.u32(); err != nil || factor.index != index {
			return 0, nil, 0, errors.New("independent aggregate index rejected")
		}
		if factor.digest, err = cursor.digest(); err != nil || factor.digest == (RBAUTHDigest{}) {
			return 0, nil, 0, errors.New("independent aggregate digest rejected")
		}
		if factor.recordBytes, err = cursor.u64(); err != nil || factor.recordBytes == 0 || total > ^uint64(0)-factor.recordBytes {
			return 0, nil, 0, errors.New("independent aggregate byte ledger rejected")
		}
		total += factor.recordBytes
	}
	declared, err := cursor.u64()
	if err != nil || declared != total || cursor.offset != len(cursor.data) {
		return 0, nil, 0, errors.New("independent aggregate total or EOF rejected")
	}
	return record[17], factors, declared, nil
}

type independentRBDFTFixtureCursor struct {
	data   []byte
	offset int
}

func (cursor *independentRBDFTFixtureCursor) take(length int) ([]byte, error) {
	if length < 0 || cursor.offset < 0 || cursor.offset > len(cursor.data)-length {
		return nil, errors.New("independent RBDFT fixture truncated")
	}
	result := cursor.data[cursor.offset : cursor.offset+length]
	cursor.offset += length
	return result, nil
}

func (cursor *independentRBDFTFixtureCursor) u8() (byte, error) {
	encoded, err := cursor.take(1)
	if err != nil {
		return 0, err
	}
	return encoded[0], nil
}

func (cursor *independentRBDFTFixtureCursor) u32() (uint32, error) {
	encoded, err := cursor.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(encoded), nil
}

func (cursor *independentRBDFTFixtureCursor) u64() (uint64, error) {
	encoded, err := cursor.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(encoded), nil
}

func (cursor *independentRBDFTFixtureCursor) digest() (RBAUTHDigest, error) {
	encoded, err := cursor.take(sha256.Size)
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var result RBAUTHDigest
	copy(result[:], encoded)
	return result, nil
}

func repeatedRBDFTDigest(value byte) (result RBAUTHDigest) {
	for index := range result {
		result[index] = value
	}
	return
}

func rbdftHex(value []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = digits[item>>4]
		encoded[index*2+1] = digits[item&0x0f]
	}
	return string(encoded)
}
