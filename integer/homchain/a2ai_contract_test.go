package homchain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
)

func TestExactScaleSnapshotPreservesMetadataWithoutAliasing(t *testing.T) {
	value := new(big.Float).SetPrec(211).SetMode(big.ToNegativeInf)
	if _, ok := value.SetString("0x1.23456789abcdef0123456789p+47"); !ok {
		t.Fatal("parse test scale")
	}
	original := rlwe.Scale{Value: *value, Mod: new(big.Int).SetUint64(65537)}

	snapshot, err := homchain.NewExactScaleSnapshot(original)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := snapshot.Scale()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Value.Cmp(&original.Value) != 0 {
		t.Fatal("snapshot changed the scale value")
	}
	if got, want := recovered.Value.Prec(), original.Value.Prec(); got != want {
		t.Fatalf("precision: got %d, want %d", got, want)
	}
	if got, want := recovered.Value.Mode(), original.Value.Mode(); got != want {
		t.Fatalf("rounding mode: got %v, want %v", got, want)
	}
	if recovered.Mod == nil || recovered.Mod.Cmp(original.Mod) != 0 {
		t.Fatalf("modulus: got %v, want %v", recovered.Mod, original.Mod)
	}

	// Mutating either the source or a recovered copy must not affect the
	// immutable audit snapshot or another recovered copy.
	original.Value.SetInt64(9)
	original.Mod.SetInt64(11)
	recovered.Value.SetInt64(13)
	recovered.Mod.SetInt64(17)

	recoveredAgain, err := snapshot.Scale()
	if err != nil {
		t.Fatal(err)
	}
	wantValue := new(big.Float).SetPrec(211).SetMode(big.ToNegativeInf)
	wantValue.SetString("0x1.23456789abcdef0123456789p+47")
	if recoveredAgain.Value.Cmp(wantValue) != 0 {
		t.Fatal("snapshot aliases a mutable scale value")
	}
	if got, want := recoveredAgain.Mod.String(), "65537"; got != want {
		t.Fatalf("snapshot aliases a mutable modulus: got %s, want %s", got, want)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(encoded); got == "{}" || got == "null" {
		t.Fatalf("exact scale has no public audit projection: %s", got)
	}
	var decoded homchain.ExactScaleSnapshot
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(snapshot) {
		t.Fatalf("exact scale JSON round-trip changed snapshot: %s", encoded)
	}
	stateJSON, err := json.Marshal(homchain.CiphertextState{Status: homchain.A2AIReached, Scale: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stateJSON, []byte(`"value_hex"`)) || bytes.Contains(stateJSON, []byte(`"Scale":{}`)) {
		t.Fatalf("embedded ciphertext-state scale is not auditable: %s", stateJSON)
	}
}

func TestExactScaleSnapshotRejectsZeroScale(t *testing.T) {
	zero := new(big.Float).SetPrec(128).SetInt64(0)
	if _, err := homchain.NewExactScaleSnapshot(rlwe.Scale{Value: *zero}); err == nil {
		t.Fatal("expected zero rlwe.Scale to be rejected")
	}
}

func TestAdmissionCertificateBindsExactDeltaAndExternalEvidence(t *testing.T) {
	deltaValue := new(big.Float).SetPrec(173).SetMode(big.ToPositiveInf)
	deltaValue.SetInt(new(big.Int).Lsh(big.NewInt(1), 71))
	delta := rlwe.Scale{Value: *deltaValue}
	bound := big.NewInt(4096)
	artifact := "review://a2ai-centered-bound/functional-profile-v1"
	artifactHash := sha256.Sum256([]byte(artifact))

	certificate, err := homchain.NewA2AIAdmissionCertificate(homchain.A2AIAdmissionRequest{
		Delta:                delta,
		DeltaSemantics:       homchain.A2AIDeltaGaoArithmeticInput,
		CenteredMessageBound: bound,
		CenteredBoundUnit:    homchain.A2AICenteredCoefficientInfinityNorm,
		CenteredBoundDomain:  homchain.A2AIBoundBeforeGuardedScaleDown,
		EvidenceArtifact:     artifact,
		EvidenceDigest:       hex.EncodeToString(artifactHash[:]),
		VerificationStatus:   homchain.A2AIEvidenceExternalUnverified,
		MaturityStatus:       homchain.A2AIEvidenceFunctionalNotSecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.Delta().EqualScale(delta) {
		t.Fatal("certificate did not retain the exact Delta")
	}
	if got, want := certificate.CenteredMessageBound().String(), "4096"; got != want {
		t.Fatalf("centered bound: got %s, want %s", got, want)
	}
	if got, want := certificate.EvidenceDigest(), hex.EncodeToString(artifactHash[:]); got != want {
		t.Fatalf("evidence digest: got %s, want %s", got, want)
	}
	if certificate.Digest() == "" {
		t.Fatal("certificate digest is empty")
	}
	if certificate.MessageBoundInternallyVerified() {
		t.Fatal("external evidence must not be reported as internally verified")
	}
	if got, want := certificate.VerificationStatus(), homchain.A2AIEvidenceExternalUnverified; got != want {
		t.Fatalf("verification status: got %q, want %q", got, want)
	}
	if got, want := certificate.MaturityStatus(), homchain.A2AIEvidenceFunctionalNotSecure; got != want {
		t.Fatalf("maturity status: got %q, want %q", got, want)
	}
	if got, want := certificate.CenteredBoundUnit(), homchain.A2AICenteredCoefficientInfinityNorm; got != want {
		t.Fatalf("centered-bound unit: got %q, want %q", got, want)
	}
	if got, want := certificate.CenteredBoundDomain(), homchain.A2AIBoundBeforeGuardedScaleDown; got != want {
		t.Fatalf("centered-bound domain: got %q, want %q", got, want)
	}

	bound.SetInt64(1)
	if got, want := certificate.CenteredMessageBound().String(), "4096"; got != want {
		t.Fatalf("certificate aliases caller bound: got %s, want %s", got, want)
	}
	mutated := certificate.CenteredMessageBound()
	mutated.SetInt64(2)
	if got, want := certificate.CenteredMessageBound().String(), "4096"; got != want {
		t.Fatalf("certificate accessor aliases stored bound: got %s, want %s", got, want)
	}

	_, err = homchain.NewA2AIAdmissionCertificate(homchain.A2AIAdmissionRequest{
		Delta:                delta,
		DeltaSemantics:       homchain.A2AIDeltaGaoArithmeticInput,
		CenteredMessageBound: big.NewInt(4096),
		CenteredBoundUnit:    homchain.A2AICenteredCoefficientInfinityNorm,
		CenteredBoundDomain:  homchain.A2AIBoundBeforeGuardedScaleDown,
		EvidenceArtifact:     artifact,
		EvidenceDigest:       "00" + hex.EncodeToString(artifactHash[1:]),
		VerificationStatus:   homchain.A2AIEvidenceExternalUnverified,
		MaturityStatus:       homchain.A2AIEvidenceFunctionalNotSecure,
	})
	if err == nil {
		t.Fatal("expected mismatched evidence digest to be rejected")
	}

	validRequest := func() homchain.A2AIAdmissionRequest {
		return homchain.A2AIAdmissionRequest{
			Delta:                delta,
			DeltaSemantics:       homchain.A2AIDeltaGaoArithmeticInput,
			CenteredMessageBound: big.NewInt(4096),
			CenteredBoundUnit:    homchain.A2AICenteredCoefficientInfinityNorm,
			CenteredBoundDomain:  homchain.A2AIBoundBeforeGuardedScaleDown,
			EvidenceArtifact:     artifact,
			EvidenceDigest:       hex.EncodeToString(artifactHash[:]),
			VerificationStatus:   homchain.A2AIEvidenceExternalUnverified,
			MaturityStatus:       homchain.A2AIEvidenceFunctionalNotSecure,
		}
	}
	invalidRequests := map[string]func(*homchain.A2AIAdmissionRequest){
		"caller-promoted-verification": func(request *homchain.A2AIAdmissionRequest) {
			request.VerificationStatus = homchain.A2AIEvidenceVerificationStatus("externally_attested")
		},
		"caller-promoted-maturity": func(request *homchain.A2AIAdmissionRequest) {
			request.MaturityStatus = homchain.A2AIEvidenceMaturityStatus("reviewed")
		},
		"ambiguous-bound-unit": func(request *homchain.A2AIAdmissionRequest) {
			request.CenteredBoundUnit = ""
		},
		"ambiguous-bound-domain": func(request *homchain.A2AIAdmissionRequest) {
			request.CenteredBoundDomain = ""
		},
	}
	for name, mutate := range invalidRequests {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(&request)
			if _, err := homchain.NewA2AIAdmissionCertificate(request); err == nil {
				t.Fatal("expected invalid admission request to be rejected")
			}
		})
	}
}
