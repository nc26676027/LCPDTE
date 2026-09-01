package secureprofile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

type routeBConstructionFixture struct {
	plan           GaoN16PackingL11CapacityPlan
	snapshot       PhysicalMemorySnapshot
	capacityPermit GaoN16PackingL11CapacityPermit
	artifacts      GaoN16RouteBArtifactDigests
	semantics      GaoN16RouteBConstructionSemantics
	spec           GaoN16RouteBConstructionSpec
	permit         GaoN16RouteBConstructionPermit
}

func newRouteBConstructionFixture(t *testing.T) routeBConstructionFixture {
	t.Helper()
	profile, err := NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGaoN16PackingL11CapacityPlan(profile, DefaultGaoN16PackingL11CapacityShape(), DefaultArtifactCapacityPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := PhysicalMemorySnapshot{
		SnapshotID:             "route-b-construction-audit-2026-08-30",
		TotalPhysicalBytes:     33617782768,
		AvailablePhysicalBytes: 17151951897,
	}
	_, capacityPermit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	c2s, err := NewGaoN16RouteBC2SDigests(
		routeBFixtureDigest("c2s-raw-literal"),
		routeBFixtureDigest("c2s-effective-literal"),
		routeBFixtureDigest("c2s-raw-scaling"),
		routeBFixtureDigest("c2s-effective-scaling"),
	)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := NewGaoN16RouteBS2CDigests(
		routeBFixtureDigest("s2c-raw-literal"),
		routeBFixtureDigest("s2c-effective-literal"),
		routeBFixtureDigest("s2c-raw-scaling"),
		routeBFixtureDigest("s2c-effective-scaling"),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := NewGaoN16RouteBArtifactDigests(
		c2s,
		s2c,
		routeBFixtureDigest("numeric-payload"),
		routeBFixtureDigest("encoded-payload"),
	)
	if err != nil {
		t.Fatal(err)
	}
	semantics := DefaultGaoN16RouteBConstructionSemantics()
	spec, err := NewGaoN16RouteBConstructionSpec(plan, artifacts, semantics)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := spec.Evaluate(snapshot, capacityPermit)
	if err != nil {
		t.Fatal(err)
	}
	return routeBConstructionFixture{
		plan: plan, snapshot: snapshot, capacityPermit: capacityPermit,
		artifacts: artifacts, semantics: semantics, spec: spec, permit: permit,
	}
}

func routeBFixtureDigest(label string) string {
	digest := sha256.Sum256([]byte("route-b-construction-test:" + label))
	return fmt.Sprintf("%x", digest[:])
}

func TestGaoN16RouteBConstructionBindsExactAcceptedContract(t *testing.T) {
	fixture := newRouteBConstructionFixture(t)
	spec := fixture.spec
	permit := fixture.permit
	peak := spec.PeakContract()

	if spec.SchemaVersion() != gaoN16RouteBConstructionSpecSchema ||
		spec.AdaptationLabel() != "lattigo_packing_adaptation_r1" ||
		spec.EvidenceScope() != "precision_construction_contract_only" ||
		spec.Maturity() != RouteBConstructionContractOnlyUnverified ||
		spec.IsSourceFaithful() || spec.IsFullPacked() {
		t.Fatalf("construction claim boundary changed: %+v", spec)
	}
	if spec.CapacityPlanDigest() != fixture.plan.Digest() ||
		spec.ParameterDigest() != fixture.plan.ParameterDigest() ||
		spec.ProfileDigest() != fixture.plan.ProfileDigest() ||
		spec.ShapeDigest() != fixture.plan.ShapeDigest() ||
		spec.PolicyDigest() != fixture.plan.PolicyDigest() {
		t.Fatalf("capacity-to-construction identity edge changed: %+v", spec)
	}
	if spec.GeneratorPrecisionBits() != 256 || spec.EncoderPrecisionBits() != 256 ||
		spec.BuilderID() != "lattigo-route-b-prebuilt-dft-streaming-builder-v1" ||
		spec.DigestAlgorithmID() != "sha256-canonical-streaming-binary-v1" ||
		spec.AllocationScheduleID() != "route-b-l11-factor-at-a-time-no-default-v1" ||
		spec.ReleaseScheduleID() != "route-b-l11-release-factor-scratch-before-next-v1" ||
		spec.OwnershipModelID() != "route-b-private-exclusive-transfer-no-alias-v1" ||
		spec.DefaultConstructorCalls() != 0 {
		t.Fatalf("precision or construction schedule changed: %+v", spec.Semantics())
	}
	if peak.FullArtifactPeakBytes() != 2968063744 ||
		peak.PreGuardIncrementalPeakBytes() != 7129861888 ||
		peak.GuardedRequirementBytes() != 7842848076 ||
		peak.RemainingBelowLimitBytes() != 2585547267 ||
		peak.ForbiddenDuplicateDefaultBytes() != 2641362944 ||
		peak.ForbiddenDuplicateExcessBytes() != 55815677 {
		t.Fatalf("Route-B peak contract changed: %+v", peak)
	}
	if spec.RawC2SLiteralDigest() != fixture.artifacts.C2S().RawLiteralDigest() ||
		spec.EffectiveC2SLiteralDigest() != fixture.artifacts.C2S().EffectiveLiteralDigest() ||
		spec.RawC2SScalingDigest() != fixture.artifacts.C2S().RawScalingDigest() ||
		spec.EffectiveC2SScalingDigest() != fixture.artifacts.C2S().EffectiveScalingDigest() ||
		spec.RawS2CLiteralDigest() != fixture.artifacts.S2C().RawLiteralDigest() ||
		spec.EffectiveS2CLiteralDigest() != fixture.artifacts.S2C().EffectiveLiteralDigest() ||
		spec.RawS2CScalingDigest() != fixture.artifacts.S2C().RawScalingDigest() ||
		spec.EffectiveS2CScalingDigest() != fixture.artifacts.S2C().EffectiveScalingDigest() ||
		spec.NumericPayloadDigest() != fixture.artifacts.NumericPayloadDigest() ||
		spec.EncodedPayloadDigest() != fixture.artifacts.EncodedPayloadDigest() ||
		spec.ArtifactManifestDigest() == "" || spec.Digest() == "" {
		t.Fatalf("artifact identity is incomplete: %+v", spec)
	}
	if permit.IsZero() || permit.SchemaVersion() != gaoN16RouteBConstructionPermitSchema ||
		permit.Decision() != Admitted || permit.SpecDigest() != spec.Digest() ||
		permit.CapacityPlanDigest() != fixture.plan.Digest() ||
		permit.CapacityPermitDigest() != fixture.capacityPermit.Digest() ||
		permit.CapacityReportDigest() != fixture.capacityPermit.ReportDigest() ||
		permit.CapacityProbeDigest() != fixture.capacityPermit.ProbeDigest() ||
		permit.Snapshot() != fixture.snapshot || permit.SnapshotDigest() == "" ||
		permit.ArtifactManifestDigest() != spec.ArtifactManifestDigest() || permit.Digest() == "" {
		t.Fatalf("construction permit identity is incomplete: %+v", permit)
	}
	if err := spec.ValidatePermit(fixture.snapshot, fixture.capacityPermit, permit); err != nil {
		t.Fatalf("unique permit did not revalidate: %v", err)
	}

	providerCalls, builderCalls, encoderCalls, defaultConstructorCalls := 0, 0, 0, 0
	stage := func(counter *int) GaoN16RouteBConstructionStage {
		return func(candidate GaoN16RouteBConstructionPermit) error {
			*counter++
			if candidate != permit {
				t.Fatal("authorized stage received a foreign permit")
			}
			return nil
		}
	}
	if err := spec.RunAfterValidation(
		fixture.snapshot,
		fixture.capacityPermit,
		permit,
		stage(&providerCalls),
		stage(&builderCalls),
		stage(&encoderCalls),
	); err != nil {
		t.Fatal(err)
	}
	if providerCalls != 1 || builderCalls != 1 || encoderCalls != 1 || defaultConstructorCalls != 0 {
		t.Fatalf("wrong authorized stage counts: provider=%d builder=%d encoder=%d default=%d",
			providerCalls, builderCalls, encoderCalls, defaultConstructorCalls)
	}
	t.Logf("Route-B construction digests artifacts=%s manifest=%s semantics=%s spec=%s snapshot=%s permit=%s",
		fixture.artifacts.Digest(), spec.ArtifactManifestDigest(), fixture.semantics.Digest(), spec.Digest(), permit.SnapshotDigest(), permit.Digest())
}

func TestGaoN16RouteBConstructionRejectsResealedPermitFieldDriftBeforeStages(t *testing.T) {
	fixture := newRouteBConstructionFixture(t)
	mutations := []struct {
		name   string
		mutate func(*GaoN16RouteBConstructionPermit)
	}{
		{name: "schema", mutate: func(p *GaoN16RouteBConstructionPermit) { p.schema = "foreign" }},
		{name: "adaptation", mutate: func(p *GaoN16RouteBConstructionPermit) { p.adaptationLabel = "source_faithful" }},
		{name: "scope", mutate: func(p *GaoN16RouteBConstructionPermit) { p.evidenceScope = "encrypted" }},
		{name: "maturity", mutate: func(p *GaoN16RouteBConstructionPermit) { p.maturity = ParameterCandidateUnverified }},
		{name: "decision", mutate: func(p *GaoN16RouteBConstructionPermit) { p.decision = ResourceBlocked }},
		{name: "source faithful promotion", mutate: func(p *GaoN16RouteBConstructionPermit) { p.sourceFaithful = true }},
		{name: "full packed promotion", mutate: func(p *GaoN16RouteBConstructionPermit) { p.fullPacked = true }},
		{name: "spec", mutate: func(p *GaoN16RouteBConstructionPermit) { p.specDigest = routeBFixtureDigest("foreign-spec") }},
		{name: "capacity plan", mutate: func(p *GaoN16RouteBConstructionPermit) { p.capacityPlanDigest = routeBFixtureDigest("foreign-plan") }},
		{name: "capacity probe", mutate: func(p *GaoN16RouteBConstructionPermit) { p.capacityProbeDigest = routeBFixtureDigest("foreign-probe") }},
		{name: "capacity report", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.capacityReportDigest = routeBFixtureDigest("foreign-report")
		}},
		{name: "capacity permit", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.capacityPermitDigest = routeBFixtureDigest("foreign-capacity-permit")
		}},
		{name: "parameter", mutate: func(p *GaoN16RouteBConstructionPermit) { p.parameterDigest = routeBFixtureDigest("foreign-parameter") }},
		{name: "profile", mutate: func(p *GaoN16RouteBConstructionPermit) { p.profileDigest = routeBFixtureDigest("foreign-profile") }},
		{name: "shape", mutate: func(p *GaoN16RouteBConstructionPermit) { p.shapeDigest = routeBFixtureDigest("foreign-shape") }},
		{name: "policy", mutate: func(p *GaoN16RouteBConstructionPermit) { p.policyDigest = routeBFixtureDigest("foreign-policy") }},
		{name: "snapshot ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.snapshot.SnapshotID = "stale" }},
		{name: "snapshot total", mutate: func(p *GaoN16RouteBConstructionPermit) { p.snapshot.TotalPhysicalBytes++ }},
		{name: "snapshot available", mutate: func(p *GaoN16RouteBConstructionPermit) { p.snapshot.AvailablePhysicalBytes++ }},
		{name: "snapshot digest", mutate: func(p *GaoN16RouteBConstructionPermit) { p.snapshotDigest = routeBFixtureDigest("foreign-snapshot") }},
		{name: "raw C2S literal", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.c2s.rawLiteralDigest = routeBFixtureDigest("raw-c2s-drift")
		}},
		{name: "effective C2S literal", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.c2s.effectiveLiteralDigest = routeBFixtureDigest("effective-c2s-drift")
		}},
		{name: "raw C2S scaling", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.c2s.rawScalingDigest = routeBFixtureDigest("raw-c2s-scaling-drift")
		}},
		{name: "effective C2S scaling", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.c2s.effectiveScalingDigest = routeBFixtureDigest("effective-c2s-scaling-drift")
		}},
		{name: "raw S2C literal", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.s2c.rawLiteralDigest = routeBFixtureDigest("raw-s2c-drift")
		}},
		{name: "effective S2C literal", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.s2c.effectiveLiteralDigest = routeBFixtureDigest("effective-s2c-drift")
		}},
		{name: "raw S2C scaling", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.s2c.rawScalingDigest = routeBFixtureDigest("raw-s2c-scaling-drift")
		}},
		{name: "effective S2C scaling", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.s2c.effectiveScalingDigest = routeBFixtureDigest("effective-s2c-scaling-drift")
		}},
		{name: "numeric payload", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.numericPayloadDigest = routeBFixtureDigest("numeric-drift")
		}},
		{name: "encoded payload", mutate: func(p *GaoN16RouteBConstructionPermit) {
			p.artifacts.encodedPayloadDigest = routeBFixtureDigest("encoded-drift")
		}},
		{name: "artifact identity", mutate: func(p *GaoN16RouteBConstructionPermit) { p.artifacts.digest = routeBFixtureDigest("artifact-drift") }},
		{name: "artifact manifest missing", mutate: func(p *GaoN16RouteBConstructionPermit) { p.manifest.digest = "" }},
		{name: "artifact manifest foreign", mutate: func(p *GaoN16RouteBConstructionPermit) { p.manifest.digest = routeBFixtureDigest("foreign-manifest") }},
		{name: "generator precision", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.generatorPrecisionBits = 255 }},
		{name: "encoder precision", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.encoderPrecisionBits = 255 }},
		{name: "builder ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.builderID = "unknown" }},
		{name: "digest algorithm ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.digestAlgorithmID = "unknown" }},
		{name: "allocation schedule ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.allocationScheduleID = "default-then-replace" }},
		{name: "release schedule ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.releaseScheduleID = "unknown" }},
		{name: "ownership model ID", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.ownershipModelID = "caller-alias" }},
		{name: "default constructor count", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.defaultConstructorCalls = 1 }},
		{name: "semantics digest", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.digest = routeBFixtureDigest("semantics-drift") }},
		{name: "full artifact peak", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.fullArtifactPeakBytes++ }},
		{name: "pre-guard peak", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.preGuardIncrementalPeakBytes++ }},
		{name: "guarded requirement", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.guardedRequirementBytes++ }},
		{name: "margin", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.remainingBelowLimitBytes++ }},
		{name: "duplicate default bytes", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.forbiddenDuplicateDefaultBytes++ }},
		{name: "duplicate excess bytes", mutate: func(p *GaoN16RouteBConstructionPermit) { p.semantics.peak.forbiddenDuplicateExcessBytes++ }},
		{name: "manifest seal", mutate: func(p *GaoN16RouteBConstructionPermit) { p.manifestDigest = routeBFixtureDigest("manifest-seal-drift") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := fixture.permit
			mutation.mutate(&candidate)
			var err error
			candidate.sealDigest, err = digestGaoN16RouteBConstructionPermit(candidate)
			if err != nil {
				t.Fatal(err)
			}
			assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, fixture.snapshot, fixture.capacityPermit, candidate)
		})
	}
}

func TestGaoN16RouteBConstructionRejectsStaleForeignAndSwappedEvidenceBeforeStages(t *testing.T) {
	fixture := newRouteBConstructionFixture(t)

	assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, fixture.snapshot, fixture.capacityPermit, GaoN16RouteBConstructionPermit{})

	staleSnapshot := fixture.snapshot
	staleSnapshot.AvailablePhysicalBytes++
	assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, staleSnapshot, fixture.capacityPermit, fixture.permit)

	foreignSnapshot := fixture.snapshot
	foreignSnapshot.SnapshotID = "foreign-capacity-permit"
	_, foreignCapacityPermit, err := fixture.plan.Evaluate(foreignSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, fixture.snapshot, foreignCapacityPermit, fixture.permit)

	for _, test := range []struct {
		name   string
		mutate func(*GaoN16RouteBArtifactDigests)
	}{
		{name: "swap C2S raw effective literal", mutate: func(a *GaoN16RouteBArtifactDigests) {
			a.c2s.rawLiteralDigest, a.c2s.effectiveLiteralDigest = a.c2s.effectiveLiteralDigest, a.c2s.rawLiteralDigest
		}},
		{name: "swap S2C raw effective literal", mutate: func(a *GaoN16RouteBArtifactDigests) {
			a.s2c.rawLiteralDigest, a.s2c.effectiveLiteralDigest = a.s2c.effectiveLiteralDigest, a.s2c.rawLiteralDigest
		}},
		{name: "swap C2S raw effective scaling", mutate: func(a *GaoN16RouteBArtifactDigests) {
			a.c2s.rawScalingDigest, a.c2s.effectiveScalingDigest = a.c2s.effectiveScalingDigest, a.c2s.rawScalingDigest
		}},
		{name: "swap S2C raw effective scaling", mutate: func(a *GaoN16RouteBArtifactDigests) {
			a.s2c.rawScalingDigest, a.s2c.effectiveScalingDigest = a.s2c.effectiveScalingDigest, a.s2c.rawScalingDigest
		}},
		{name: "swap transform roles", mutate: func(a *GaoN16RouteBArtifactDigests) { a.c2s, a.s2c = a.s2c, a.c2s }},
		{name: "numeric drift", mutate: func(a *GaoN16RouteBArtifactDigests) { a.numericPayloadDigest = routeBFixtureDigest("foreign-numeric") }},
		{name: "encoded drift", mutate: func(a *GaoN16RouteBArtifactDigests) { a.encodedPayloadDigest = routeBFixtureDigest("foreign-encoded") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifacts := fixture.artifacts
			test.mutate(&artifacts)
			artifacts.c2s.digest, _ = digestGaoN16RouteBTransformDigests(artifacts.c2s)
			artifacts.s2c.digest, _ = digestGaoN16RouteBTransformDigests(artifacts.s2c)
			artifacts.digest, _ = digestGaoN16RouteBArtifactDigests(artifacts)
			foreignSpec, createErr := NewGaoN16RouteBConstructionSpec(fixture.plan, artifacts, fixture.semantics)
			if test.name == "swap transform roles" {
				assertRouteBConstructionBlocked(t, createErr)
				return
			}
			if createErr != nil {
				t.Fatal(createErr)
			}
			assertRouteBConstructionRejectedBeforeStages(t, foreignSpec, fixture.snapshot, fixture.capacityPermit, fixture.permit)
		})
	}
}

func TestGaoN16RouteBConstructionRejectsPrecisionIDsScheduleAndEveryPeakDrift(t *testing.T) {
	fixture := newRouteBConstructionFixture(t)
	tests := []struct {
		name   string
		mutate func(*GaoN16RouteBConstructionSemantics)
	}{
		{name: "generator precision", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.generatorPrecisionBits = 53 }},
		{name: "encoder precision", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.encoderPrecisionBits = 53 }},
		{name: "unknown builder", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.builderID = "unknown" }},
		{name: "unknown digest", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.digestAlgorithmID = "unknown" }},
		{name: "duplicate default schedule", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.allocationScheduleID = "stock-default-then-replace" }},
		{name: "unknown release", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.releaseScheduleID = "unknown" }},
		{name: "mutable alias ownership", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.ownershipModelID = "provider-retains-alias" }},
		{name: "default constructor promoted", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.defaultConstructorCalls = 1 }},
		{name: "full artifact peak", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.fullArtifactPeakBytes++ }},
		{name: "pre-guard peak", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.preGuardIncrementalPeakBytes++ }},
		{name: "guarded requirement", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.guardedRequirementBytes++ }},
		{name: "margin", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.remainingBelowLimitBytes++ }},
		{name: "duplicate bytes", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.forbiddenDuplicateDefaultBytes++ }},
		{name: "duplicate excess", mutate: func(s *GaoN16RouteBConstructionSemantics) { s.peak.forbiddenDuplicateExcessBytes++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			semantics := fixture.semantics
			test.mutate(&semantics)
			semantics.digest, _ = digestGaoN16RouteBConstructionSemantics(semantics)
			_, err := NewGaoN16RouteBConstructionSpec(fixture.plan, fixture.artifacts, semantics)
			assertRouteBConstructionBlocked(t, err)
		})
	}
}

func TestGaoN16RouteBConstructionZeroValuesAreSafeAndFailClosed(t *testing.T) {
	var transform GaoN16RouteBTransformDigests
	if !transform.IsZero() || transform.Role() != "" || transform.RawLiteralDigest() != "" ||
		transform.EffectiveLiteralDigest() != "" || transform.RawScalingDigest() != "" ||
		transform.EffectiveScalingDigest() != "" || transform.Digest() != "" {
		t.Fatalf("transform zero value is not inert: %+v", transform)
	}
	var artifacts GaoN16RouteBArtifactDigests
	if !artifacts.IsZero() || !artifacts.C2S().IsZero() || !artifacts.S2C().IsZero() ||
		artifacts.NumericPayloadDigest() != "" || artifacts.EncodedPayloadDigest() != "" || artifacts.Digest() != "" {
		t.Fatalf("artifact zero value is not inert: %+v", artifacts)
	}
	var peak GaoN16RouteBPeakContract
	if !peak.IsZero() || peak.FullArtifactPeakBytes() != 0 || peak.ForbiddenDuplicateExcessBytes() != 0 {
		t.Fatalf("peak zero value is not inert: %+v", peak)
	}
	var semantics GaoN16RouteBConstructionSemantics
	if !semantics.IsZero() || !semantics.PeakContract().IsZero() || semantics.Digest() != "" {
		t.Fatalf("semantics zero value is not inert: %+v", semantics)
	}
	var manifest GaoN16RouteBArtifactManifest
	if !manifest.IsZero() || manifest.Digest() != "" {
		t.Fatalf("manifest zero value is not inert: %+v", manifest)
	}
	var spec GaoN16RouteBConstructionSpec
	if !spec.IsZero() || !spec.Artifacts().IsZero() || !spec.Semantics().IsZero() || !spec.PeakContract().IsZero() {
		t.Fatalf("spec zero value is not inert: %+v", spec)
	}
	var permit GaoN16RouteBConstructionPermit
	if !permit.IsZero() || !permit.Artifacts().IsZero() || !permit.Semantics().IsZero() || permit.Snapshot() != (PhysicalMemorySnapshot{}) {
		t.Fatalf("permit zero value is not inert: %+v", permit)
	}

	fixture := newRouteBConstructionFixture(t)
	if _, err := NewGaoN16RouteBC2SDigests("", routeBFixtureDigest("a"), routeBFixtureDigest("b"), routeBFixtureDigest("c")); err == nil {
		t.Fatal("missing transform digest was admitted")
	} else {
		assertRouteBConstructionBlocked(t, err)
	}
	if _, err := NewGaoN16RouteBArtifactDigests(GaoN16RouteBTransformDigests{}, fixture.artifacts.S2C(), routeBFixtureDigest("a"), routeBFixtureDigest("b")); err == nil {
		t.Fatal("zero transform identity was admitted")
	} else {
		assertRouteBConstructionBlocked(t, err)
	}
	if _, err := NewGaoN16RouteBConstructionSpec(GaoN16PackingL11CapacityPlan{}, fixture.artifacts, fixture.semantics); err == nil {
		t.Fatal("zero capacity plan was admitted")
	} else {
		assertRouteBConstructionBlocked(t, err)
	}
	if _, err := NewGaoN16RouteBConstructionSpec(fixture.plan, GaoN16RouteBArtifactDigests{}, fixture.semantics); err == nil {
		t.Fatal("zero artifact identity was admitted")
	} else {
		assertRouteBConstructionBlocked(t, err)
	}
	if _, err := NewGaoN16RouteBConstructionSpec(fixture.plan, fixture.artifacts, GaoN16RouteBConstructionSemantics{}); err == nil {
		t.Fatal("zero construction semantics were admitted")
	} else {
		assertRouteBConstructionBlocked(t, err)
	}
	assertRouteBConstructionRejectedBeforeStages(t, GaoN16RouteBConstructionSpec{}, fixture.snapshot, fixture.capacityPermit, fixture.permit)
	assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, fixture.snapshot, GaoN16PackingL11CapacityPermit{}, fixture.permit)
	assertRouteBConstructionRejectedBeforeStages(t, fixture.spec, fixture.snapshot, fixture.capacityPermit, GaoN16RouteBConstructionPermit{})

	providerCalls, builderCalls, encoderCalls := 0, 0, 0
	err := fixture.spec.RunAfterValidation(
		fixture.snapshot,
		fixture.capacityPermit,
		fixture.permit,
		nil,
		func(GaoN16RouteBConstructionPermit) error { builderCalls++; return nil },
		func(GaoN16RouteBConstructionPermit) error { encoderCalls++; return nil },
	)
	assertRouteBConstructionBlocked(t, err)
	if providerCalls != 0 || builderCalls != 0 || encoderCalls != 0 {
		t.Fatalf("nil stage validation occurred after calls: provider=%d builder=%d encoder=%d", providerCalls, builderCalls, encoderCalls)
	}
}

func TestGaoN16RouteBConstructionRejectsResealedSpecPromotion(t *testing.T) {
	fixture := newRouteBConstructionFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*GaoN16RouteBConstructionSpec)
	}{
		{name: "source faithful", mutate: func(s *GaoN16RouteBConstructionSpec) { s.sourceFaithful = true }},
		{name: "full packed", mutate: func(s *GaoN16RouteBConstructionSpec) { s.fullPacked = true }},
		{name: "maturity", mutate: func(s *GaoN16RouteBConstructionSpec) { s.maturity = ParameterCandidateUnverified }},
		{name: "scope", mutate: func(s *GaoN16RouteBConstructionSpec) { s.evidenceScope = "encrypted_secure" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := fixture.spec
			test.mutate(&candidate)
			candidate.digest, _ = digestGaoN16RouteBConstructionSpec(candidate)
			assertRouteBConstructionRejectedBeforeStages(t, candidate, fixture.snapshot, fixture.capacityPermit, fixture.permit)
		})
	}
}

func assertRouteBConstructionRejectedBeforeStages(
	t *testing.T,
	spec GaoN16RouteBConstructionSpec,
	snapshot PhysicalMemorySnapshot,
	capacityPermit GaoN16PackingL11CapacityPermit,
	constructionPermit GaoN16RouteBConstructionPermit,
) {
	t.Helper()
	providerCalls, builderCalls, encoderCalls := 0, 0, 0
	err := spec.RunAfterValidation(
		snapshot,
		capacityPermit,
		constructionPermit,
		func(GaoN16RouteBConstructionPermit) error { providerCalls++; return nil },
		func(GaoN16RouteBConstructionPermit) error { builderCalls++; return nil },
		func(GaoN16RouteBConstructionPermit) error { encoderCalls++; return nil },
	)
	assertRouteBConstructionBlocked(t, err)
	if providerCalls != 0 || builderCalls != 0 || encoderCalls != 0 {
		t.Fatalf("invalid construction reached a stage: provider=%d builder=%d encoder=%d", providerCalls, builderCalls, encoderCalls)
	}
}

func assertRouteBConstructionBlocked(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected Route-B construction rejection")
	}
	var blocked *ErrGaoN16RouteBConstructionBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("error=%T %v, want typed ErrGaoN16RouteBConstructionBlocked", err, err)
	}
}
