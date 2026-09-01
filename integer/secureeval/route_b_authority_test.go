package secureeval

import (
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureprofile"
)

type scriptedPhysicalMemoryResult struct {
	totals physicalMemoryTotals
	err    error
}

type scriptedPhysicalMemorySampler struct {
	mu      sync.Mutex
	results []scriptedPhysicalMemoryResult
	calls   int
}

type functionPhysicalMemorySampler func() (physicalMemoryTotals, error)

func (sampler functionPhysicalMemorySampler) samplePhysicalMemory() (physicalMemoryTotals, error) {
	return sampler()
}

func (sampler *scriptedPhysicalMemorySampler) samplePhysicalMemory() (physicalMemoryTotals, error) {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	sampler.calls++
	if len(sampler.results) == 0 {
		return physicalMemoryTotals{}, errors.New("scripted sampler exhausted")
	}
	result := sampler.results[0]
	sampler.results = sampler.results[1:]
	return result.totals, result.err
}

func TestRouteBAuthorityAuthorizeBuildUsesTrustedDynamicCapacity(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
		{totals: physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}},
	}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}

	spec1, permit1, err := authority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorizedBuildMatchesIndependentCapacity(t, spec1, permit1)
	if spec1.Peak.RemainingBelowLimitBytes != 2_585_547_267 ||
		spec1.Peak.DuplicateDefaultExcessBytes != 55_815_677 {
		t.Fatalf("first dynamic peak=%+v", spec1.Peak)
	}

	copyOfAuthority := *authority
	spec2, permit2, err := copyOfAuthority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorizedBuildMatchesIndependentCapacity(t, spec2, permit2)
	if spec2.Peak.RemainingBelowLimitBytes != 2_625_539_968 ||
		spec2.Peak.DuplicateDefaultExcessBytes != 15_822_976 {
		t.Fatalf("second dynamic peak=%+v", spec2.Peak)
	}
	if spec1 == spec2 || permit1.lineage == permit2.lineage ||
		permit1.lineage.owner != permit2.lineage.owner ||
		permit1.lineage.mintGeneration != 1 || permit2.lineage.mintGeneration != 2 ||
		authority.cell.generation != 2 || sampler.calls != 2 ||
		authority.cell.sampleCalls.Load() != 2 || authority.cell.prepareCalls.Load() != 2 {
		t.Fatalf("shared Authority generations/counters changed: generations=%d/%d cell=%d sampler=%d sample=%d prepare=%d",
			permit1.lineage.mintGeneration, permit2.lineage.mintGeneration, authority.cell.generation,
			sampler.calls, authority.cell.sampleCalls.Load(), authority.cell.prepareCalls.Load())
	}
	if permit1.lineage.state.Load() != uint32(routeBLineageAuthorized) ||
		permit2.lineage.state.Load() != uint32(routeBLineageAuthorized) {
		t.Fatal("new build lineage is not authorized")
	}
}

func TestRouteBAuthorityBlockedAndSamplerFailuresConsumeGenerationBeforePrepare(t *testing.T) {
	sentinel := errors.New("OS sampler sentinel")
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{
		{err: sentinel},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 1}},
		{totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}},
	}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}

	if spec, permit, gotErr := authority.AuthorizeBuild(); !errors.Is(gotErr, ErrRBAUTHBlocked) ||
		!errors.Is(gotErr, sentinel) || spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
		t.Fatalf("sampler failure returned spec/permit/error=%+v/%+v/%v", spec, permit, gotErr)
	}
	if authority.cell.generation != 1 || authority.cell.prepareCalls.Load() != 0 {
		t.Fatalf("sampler failure generation/prepare=%d/%d", authority.cell.generation, authority.cell.prepareCalls.Load())
	}

	var capacityErr *secureprofile.ErrArtifactCapacityBlocked
	if spec, permit, gotErr := authority.AuthorizeBuild(); !errors.Is(gotErr, ErrRBAUTHBlocked) ||
		!errors.As(gotErr, &capacityErr) || spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
		t.Fatalf("capacity failure returned spec/permit/error=%+v/%+v/%v", spec, permit, gotErr)
	}
	if authority.cell.generation != 2 || authority.cell.prepareCalls.Load() != 0 {
		t.Fatalf("capacity failure generation/prepare=%d/%d", authority.cell.generation, authority.cell.prepareCalls.Load())
	}

	spec, permit, err := authority.AuthorizeBuild()
	if err != nil {
		t.Fatal(err)
	}
	if permit.lineage.mintGeneration != 3 || authority.cell.prepareCalls.Load() != 1 {
		t.Fatalf("post-failure authorization generation/prepare=%d/%d", permit.lineage.mintGeneration, authority.cell.prepareCalls.Load())
	}
	assertAuthorizedBuildMatchesIndependentCapacity(t, spec, permit)
}

func TestRouteBAuthorityGenerationExhaustionBlocksBeforeSideEffects(t *testing.T) {
	sampler := &scriptedPhysicalMemorySampler{results: []scriptedPhysicalMemoryResult{{
		totals: physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897},
	}}}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	authority.cell.generation = math.MaxUint64

	spec, permit, err := authority.AuthorizeBuild()
	if !errors.Is(err, ErrRBAUTHBlocked) || spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
		t.Fatalf("exhausted generation returned spec/permit/error=%+v/%+v/%v", spec, permit, err)
	}
	if authority.cell.generation != math.MaxUint64 || sampler.calls != 0 ||
		authority.cell.sampleCalls.Load() != 0 || authority.cell.capacityEvaluationCalls.Load() != 0 ||
		authority.cell.prepareCalls.Load() != 0 {
		t.Fatalf("exhausted generation changed state generation/sampler/sample/capacity/prepare=%d/%d/%d/%d/%d",
			authority.cell.generation, sampler.calls, authority.cell.sampleCalls.Load(),
			authority.cell.capacityEvaluationCalls.Load(), authority.cell.prepareCalls.Load())
	}
}

func TestRouteBAuthorityPublicSurfaceHasNoCapacityInjection(t *testing.T) {
	constructor := reflect.ValueOf(NewRouteBAuthority)
	if constructor.Type().NumIn() != 0 {
		t.Fatalf("NewRouteBAuthority has %d inputs, want zero", constructor.Type().NumIn())
	}
	authorityType := reflect.TypeOf((*RouteBAuthority)(nil))
	method, ok := authorityType.MethodByName("AuthorizeBuild")
	if !ok || method.Type.NumIn() != 1 {
		t.Fatalf("AuthorizeBuild public inputs changed: present=%v type=%v", ok, method.Type)
	}
	if reflect.TypeOf(RouteBAuthority{}).NumField() != 1 || reflect.TypeOf(RouteBAuthority{}).Field(0).IsExported() ||
		reflect.TypeOf(ArtifactBuildPermit{}).NumField() != 2 {
		t.Fatal("Authority or live permit exposes an unexpected public field")
	}

	var zero *RouteBAuthority
	if spec, permit, err := zero.AuthorizeBuild(); !errors.Is(err, ErrRBAUTHLineage) ||
		spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
		t.Fatalf("nil Authority returned spec/permit/error=%+v/%+v/%v", spec, permit, err)
	}
	if spec, permit, err := (&RouteBAuthority{}).AuthorizeBuild(); !errors.Is(err, ErrRBAUTHLineage) ||
		spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
		t.Fatalf("zero Authority returned spec/permit/error=%+v/%+v/%v", spec, permit, err)
	}
}

func TestRouteBAuthorityAuthorizeBuildEnforcesGateOrder(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "route_b_authority.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var authorize *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv != nil && function.Name.Name == "AuthorizeBuild" {
			authorize = function
			break
		}
	}
	if authorize == nil {
		t.Fatal("RouteBAuthority.AuthorizeBuild declaration is missing")
	}

	var calls []string
	ast.Inspect(authorize.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			calls = append(calls, function.Name)
		case *ast.SelectorExpr:
			calls = append(calls, function.Sel.Name)
		}
		return true
	})
	callIndex := func(name string) int {
		for index, call := range calls {
			if call == name {
				return index
			}
		}
		return -1
	}
	sample := callIndex("sampleAndEvaluateCapacity")
	prepare := callIndex("prepareStoredParameters")
	mint := callIndex("mintArtifactBuildPermit")
	if sample < 0 || prepare <= sample || mint <= prepare {
		t.Fatalf("AuthorizeBuild gate order changed: calls=%v", calls)
	}
	for _, forbidden := range []string{
		"NewEncoder", "NewEvaluator", "NewKeyGenerator", "GenEvaluationKeys", "NewDFTMatrixFromLiteral",
	} {
		if callIndex(forbidden) >= 0 {
			t.Fatalf("AuthorizeBuild performs forbidden heavyweight construction %q: calls=%v", forbidden, calls)
		}
	}
}

func TestRouteBAuthorityConcurrentCopiesShareUniqueGenerations(t *testing.T) {
	const count = 12
	results := make([]scriptedPhysicalMemoryResult, count)
	for index := range results {
		results[index].totals = physicalMemoryTotals{total: 33_617_782_768, available: 17_151_951_897}
	}
	sampler := &scriptedPhysicalMemorySampler{results: results}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	copyOfAuthority := *authority

	type outcome struct {
		permit ArtifactBuildPermit
		err    error
	}
	outcomes := make(chan outcome, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(useCopy bool) {
			defer wait.Done()
			target := authority
			if useCopy {
				target = &copyOfAuthority
			}
			_, permit, authorizeErr := target.AuthorizeBuild()
			outcomes <- outcome{permit: permit, err: authorizeErr}
		}(index%2 == 0)
	}
	wait.Wait()
	close(outcomes)

	generations := make(map[uint64]struct{}, count)
	lineages := make(map[*routeBLineageCell]struct{}, count)
	for outcome := range outcomes {
		if outcome.err != nil || outcome.permit.IsZero() {
			t.Fatalf("concurrent authorization failed: %v", outcome.err)
		}
		if outcome.permit.lineage.owner != authority.cell.owner {
			t.Fatal("concurrent permit has a foreign owner")
		}
		generations[outcome.permit.lineage.mintGeneration] = struct{}{}
		lineages[outcome.permit.lineage] = struct{}{}
	}
	if len(generations) != count || len(lineages) != count || authority.cell.generation != count ||
		authority.cell.sampleCalls.Load() != count || authority.cell.prepareCalls.Load() != count {
		t.Fatalf("concurrent uniqueness counts generations/lineages/cell/sample/prepare=%d/%d/%d/%d/%d",
			len(generations), len(lineages), authority.cell.generation,
			authority.cell.sampleCalls.Load(), authority.cell.prepareCalls.Load())
	}
	for generation := uint64(1); generation <= count; generation++ {
		if _, exists := generations[generation]; !exists {
			t.Fatalf("concurrent generation %d is missing", generation)
		}
	}
}

func TestRouteBAuthorityRejectsTypedNilSamplerAndCapacityCapabilityReplay(t *testing.T) {
	var nilSampler *scriptedPhysicalMemorySampler
	if authority, err := newRouteBAuthorityWithSampler(nilSampler); !errors.Is(err, ErrRBAUTHLineage) || authority != nil {
		t.Fatalf("typed-nil sampler returned authority/error=%v/%v", authority, err)
	}
	var nilFunctionSampler functionPhysicalMemorySampler
	if authority, err := newRouteBAuthorityWithSampler(nilFunctionSampler); !errors.Is(err, ErrRBAUTHLineage) || authority != nil {
		t.Fatalf("typed-nil function sampler returned authority/error=%v/%v", authority, err)
	}

	sampler := &scriptedPhysicalMemorySampler{}
	authority, err := newRouteBAuthorityWithSampler(sampler)
	if err != nil {
		t.Fatal(err)
	}
	cell := authority.cell
	cell.generation = 7
	totals := physicalMemoryTotals{total: 33_618_251_776, available: 17_192_038_400}
	capability := routeBCapacityCapability{
		cell:       &routeBCapabilityCell{owner: cell.owner, generation: 7},
		generation: 7, sampledAt: time.Now().UTC(), totals: totals,
		snapshotID: routeBCapacitySnapshotID(cell.ownerSecret, 7, totals),
	}
	copyOfCapability := capability
	if _, _, err = cell.consumeCapacityCapability(capability); err != nil {
		t.Fatal(err)
	}
	if _, _, err = cell.consumeCapacityCapability(copyOfCapability); !errors.Is(err, ErrRBAUTHLineage) {
		t.Fatalf("copied capability replay error=%v, want lineage", err)
	}
	foreign := routeBCapacityCapability{
		cell:       &routeBCapabilityCell{owner: &routeBAuthorityOwner{marker: 1}, generation: 7},
		generation: 7, sampledAt: time.Now().UTC(), totals: totals,
		snapshotID: routeBCapacitySnapshotID(cell.ownerSecret, 7, totals),
	}
	if _, _, err = cell.consumeCapacityCapability(foreign); !errors.Is(err, ErrRBAUTHLineage) {
		t.Fatalf("foreign capability error=%v, want lineage", err)
	}
}

func TestRouteBCapacitySnapshotIDGolden(t *testing.T) {
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index)
	}
	got := routeBCapacitySnapshotID(secret, 7, physicalMemoryTotals{
		total: 33_618_251_776, available: 17_192_038_400,
	})
	if got != "969ac9468a2a92b82a09fd93fe72f6dee29b7bf171a6bc62374f98e70cedcf87" {
		t.Fatalf("capacity snapshot ID=%s", got)
	}
}

func TestProductionRouteBAuthorityAuthorizeBuildSmoke(t *testing.T) {
	authority, err := NewRouteBAuthority()
	if err != nil {
		t.Fatal(err)
	}
	spec, permit, err := authority.AuthorizeBuild()
	if err != nil {
		if errors.Is(err, ErrRBAUTHBlocked) {
			if spec != (ArtifactBuildSpec{}) || !permit.IsZero() {
				t.Fatal("blocked production authorization returned a partial capability")
			}
			t.Skipf("current host is not admitted by the live capacity gate: %v", err)
		}
		t.Fatal(err)
	}
	assertAuthorizedBuildMatchesIndependentCapacity(t, spec, permit)
	if authority.cell.generation != 1 || authority.cell.sampleCalls.Load() != 1 ||
		authority.cell.capacityEvaluationCalls.Load() != 1 || authority.cell.prepareCalls.Load() != 1 {
		t.Fatalf("production authorization counters generation/sample/capacity/prepare=%d/%d/%d/%d",
			authority.cell.generation, authority.cell.sampleCalls.Load(),
			authority.cell.capacityEvaluationCalls.Load(), authority.cell.prepareCalls.Load())
	}
}

func assertAuthorizedBuildMatchesIndependentCapacity(t *testing.T, spec ArtifactBuildSpec, permit ArtifactBuildPermit) {
	t.Helper()
	if permit.IsZero() || permit.lineage == nil || permit.lineage.owner == nil || spec.ValidateFrozenSemantics() != nil {
		t.Fatal("authorized build result is zero or semantically invalid")
	}
	report := permit.Report()
	if report.Spec != spec {
		t.Fatal("live permit report does not contain the returned build spec")
	}
	specRecord := mustMarshal(t, spec)
	permitRecord := mustMarshal(t, report)
	if got, err := permit.MarshalBinary(); err != nil || !reflect.DeepEqual(got, permitRecord) {
		t.Fatalf("live permit marshal mismatch: err=%v", err)
	}
	if permit.lineage.buildSpecIdentity != independentRecordIdentity(t, specRecord) ||
		permit.lineage.buildPermitIdentity != independentRecordIdentity(t, permitRecord) {
		t.Fatal("lineage build identities differ from independent records")
	}
	parsed, err := ParseArtifactBuildPermit(permitRecord)
	if err != nil || parsed != report || parsed.ValidateFrozenSemantics() != nil {
		t.Fatalf("inert permit round trip failed: parse=%v equal=%v semantic=%v", err, parsed == report, parsed.ValidateFrozenSemantics())
	}

	profile, err := secureprofile.NewGaoN16PackingL11Profile()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := secureprofile.NewGaoN16PackingL11CapacityPlan(
		profile, secureprofile.DefaultGaoN16PackingL11CapacityShape(), secureprofile.DefaultArtifactCapacityPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := secureprofile.PhysicalMemorySnapshot{
		SnapshotID: spec.Capacity.SnapshotID, TotalPhysicalBytes: spec.Capacity.TotalPhysicalBytes,
		AvailablePhysicalBytes: spec.Capacity.AvailablePhysicalBytes,
	}
	capacityReport, capacityPermit, err := plan.Evaluate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertDigestHex := func(name string, got RBAUTHDigest, want string) {
		t.Helper()
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("%s=%x, want %s", name, got, want)
		}
	}
	assertDigestHex("plan", spec.Capacity.CapacityPlanDigest, plan.Digest())
	assertDigestHex("probe", spec.Capacity.CapacityProbeDigest, capacityReport.ProbeDigest())
	assertDigestHex("report", spec.Capacity.CapacityReportDigest, capacityReport.Digest())
	assertDigestHex("permit", spec.Capacity.CapacityPermitDigest, capacityPermit.Digest())
	assertDigestHex("parameter", spec.Capacity.ParameterDigest, capacityReport.ParameterDigest())
	assertDigestHex("profile", spec.Capacity.ProfileDigest, capacityReport.ProfileDigest())
	assertDigestHex("shape", spec.Capacity.ShapeDigest, capacityReport.ShapeDigest())
	assertDigestHex("policy", spec.Capacity.PolicyDigest, capacityReport.PolicyDigest())
	assertDigestHex("prepared", spec.PreparedParameterDigest, gaoN16RouteBPreparedDigestHex)
	if permit.lineage.mintCapacityReportIdentity != spec.Capacity.CapacityReportDigest ||
		permit.lineage.mintCapacityPermitIdentity != spec.Capacity.CapacityPermitDigest {
		t.Fatal("lineage capacity anchors differ from the build spec")
	}
}
