package homchain_test

import (
	"math"
	"math/big"
	"math/cmplx"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	ckksdft "github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

type a2bFullFixture struct {
	params         ckks.Parameters
	refreshEncoder *ckks.Encoder
	kernelEncoder  *ckks.Encoder
	circuit        *homchain.A2BFullCircuit
	sourceCircuit  *homchain.A2BRefreshCircuit
	source         *bootstrapping.Evaluator
	evaluator      *homchain.A2BFullEvaluator
	ringZ          *z2n.Ring
	secretKey      *rlwe.SecretKey
	encryptor      *rlwe.Encryptor
	decryptor      *rlwe.Decryptor
}

func TestA2BFullProfileSealsSerialGraphAndIndependentSecondSTC(t *testing.T) {
	f := newA2BFullFixture(t)
	profile := f.circuit.Profile()
	if profile.Fidelity() != homchain.A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure ||
		profile.Schedule() != homchain.A2BFullSerialLowThenHigh || profile.WordBits() != z2n.Word8 ||
		profile.ChunkWidth() != 4 || profile.Depth() != 2 || profile.Words() != 4 || profile.Slots() != 16 ||
		profile.InputLevel() != 20 || !profile.InputScale().EqualScale(f.params.DefaultScale()) ||
		profile.Cutoff() != -16 || profile.OutputOrder() != [2]string{"low", "high"} || profile.BitOrder() != "LSB-first" {
		t.Fatalf("fixed serial profile changed: %+v", profile)
	}
	if profile.Digest() == "" || profile.ParameterDigest() == "" || profile.KeyProfileDigest() == "" ||
		profile.FirstRefreshDigest() == "" || profile.FirstSTCExecutionMatrixDigest() == "" ||
		profile.SharedCTSExecutionMatrixDigest() == "" || profile.KernelArtifactDigest() == "" ||
		profile.MaskSourceDigest() == "" || profile.IDScaleSourceDigest() == "" {
		t.Fatal("serial profile omits a sealed artifact digest")
	}
	if got, want := profile.Digest(), "d9c156fb3347daa8a10976b04c69a118f4b07cd34b4b6f4d92b1d71c133dfc90"; got != want {
		t.Fatalf("serial profile digest=%s, want %s", got, want)
	}
	if profile.FirstRefreshDigest() != f.sourceCircuit.Profile().Digest() ||
		profile.FirstSTCExecutionMatrixDigest() != f.sourceCircuit.Profile().DFT().SlotsToCoeffsExecutionMatrixDigest() ||
		profile.SharedCTSExecutionMatrixDigest() != f.sourceCircuit.Profile().DFT().CoeffsToSlotsExecutionMatrixDigest() ||
		!profile.CTSSharedAcrossRefreshes() {
		t.Fatal("serial profile does not explicitly bind first STC and one shared CTS")
	}
	second := profile.SecondSTC()
	raw, execution := second.RawLiteral(), second.ExecutionLiteral()
	if raw.Type != ckksdft.HomomorphicDecode || raw.Format != ckksdft.SplitRealAndImag || raw.LevelQ != 3 ||
		raw.LevelP != 0 || !reflect.DeepEqual(raw.Levels, []int{1, 1}) || raw.Scaling == nil ||
		raw.Scaling.Prec() != a2bRefreshTestPrecision || raw.Scaling.Cmp(new(big.Float).SetInt64(1)) != 0 {
		t.Fatalf("second raw paper STC changed: %+v", raw)
	}
	wantExecutionScaling := new(big.Float).SetPrec(a2bRefreshTestPrecision).SetInt64(1 << 15)
	if execution.LevelQ != 3 || !reflect.DeepEqual(execution.Levels, []int{1, 1}) ||
		execution.Scaling == nil || execution.Scaling.Prec() != a2bRefreshTestPrecision ||
		execution.Scaling.Cmp(wantExecutionScaling) != 0 || second.RawMatrixDigest() == "" ||
		second.ExecutionMatrixDigest() == "" || second.Digest() == "" ||
		second.ExecutionMatrixDigest() == profile.FirstSTCExecutionMatrixDigest() {
		t.Fatalf("second initialized STC is not independent L3/[1,1]/MR15: %+v", execution)
	}
	if got, want := second.RawMatrixDigest(), "b40ce04fb171af270ea77e0142bd7d695c58e670e733e5e09eab97a4cd2a854e"; got != want {
		t.Fatalf("second raw STC digest=%s, want %s", got, want)
	}
	if got, want := second.ExecutionMatrixDigest(), "6381e519b59a10832ad615399b29b416941c8c7185bff9a7802dc06418395ae0"; got != want {
		t.Fatalf("second execution STC digest=%s, want %s", got, want)
	}
	if got, want := second.Digest(), "b4d1cb37cf6cb73f9f3411266a04d3b9686064d56492f0cda01a691f6245b882"; got != want {
		t.Fatalf("second STC profile digest=%s, want %s", got, want)
	}
	counts := profile.OperationCounts()
	if counts != (homchain.A2BFullOperationCounts{
		SpecialB0Transforms: 1, MaskMulRescales: 2, RefreshInvocations: 2, KernelInvocations: 2,
		IDScaleMulRescales: 1, AlignmentDrops: 3, Subtractions: 3, ResidualRotations: 0, SharedCTSUses: 2,
	}) {
		t.Fatalf("serial operation ledger changed: %+v", counts)
	}
	if profile.NormalizedInputCertified() || !strings.Contains(profile.NormalizedInvariant(), "16*y-a integral") ||
		!strings.Contains(profile.NormalizedInvariant(), "source-secure sparse switching") ||
		!strings.Contains(profile.LevelLedger(), "iter1-mask3->stc1") {
		t.Fatalf("serial fidelity/normalization ledger changed: invariant=%q ledger=%q", profile.NormalizedInvariant(), profile.LevelLedger())
	}
	keys := f.circuit.RequiredKeyProfile()
	if !keys.RelinearizationRequired() || len(keys.All()) == 0 || len(keys.Residual()) != 0 || len(keys.Trace()) != 0 ||
		keys.Digest() != profile.KeyProfileDigest() || !reflect.DeepEqual(keys.All(), f.sourceCircuit.RequiredKeyProfile().All()) {
		t.Fatalf("serial key union is not exact or residual-free: %+v", keys)
	}
	raw.Levels[0] = 99
	execution.Scaling.SetInt64(1)
	if got := f.circuit.Profile().SecondSTC().RawLiteral().Levels; !reflect.DeepEqual(got, []int{1, 1}) {
		t.Fatal("second STC raw literal aliases caller-owned data")
	}
	if got := f.circuit.Profile().SecondSTC().ExecutionLiteral().Scaling; got.Cmp(wantExecutionScaling) != 0 {
		t.Fatal("second STC execution literal aliases caller-owned data")
	}
	for _, object := range []any{*f.circuit, *f.evaluator, homchain.A2BFullResult{}} {
		typeOf := reflect.TypeOf(object)
		for i := 0; i < typeOf.NumField(); i++ {
			if typeOf.Field(i).IsExported() {
				t.Fatalf("%s exposes mutable graph/result field %q", typeOf.Name(), typeOf.Field(i).Name)
			}
		}
	}
	t.Logf("A2B full digests: profile=%s second-raw=%s second-execution=%s second-profile=%s",
		profile.Digest(), second.RawMatrixDigest(), second.ExecutionMatrixDigest(), second.Digest())
}

func TestA2BFullSerialAll256FinalBitsAndLiftInvariance(t *testing.T) {
	f := newA2BFullFixture(t)
	var maxLowError, maxHighError, maxHighUpdateError, maxSelfRemovalError, maxIter0Lattice, maxIter1Lattice float64
	var maxIter0Root, maxIter1Root, maxID0Error, maxID1Error float64
	for batch := 0; batch < 64; batch++ {
		words := [4]uint64{uint64(4 * batch), uint64(4*batch + 1), uint64(4*batch + 2), uint64(4*batch + 3)}
		result, _, err := f.evaluator.EvaluateNew(f.encrypt(t, words))
		if err != nil {
			t.Fatalf("batch %d words=%v: %v", batch, words, err)
		}
		lowValues := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, result.LowMSB())
		highValues := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, result.HighMSB())
		iter0Values := decodeA2BRefresh(t, f.refreshEncoder, f.decryptor, result.Iter0Refreshed())
		iter1Values := decodeA2BRefresh(t, f.refreshEncoder, f.decryptor, result.Iter1Refreshed())
		highUpdatedValues := decodeA2BRefresh(t, f.refreshEncoder, f.decryptor, result.HighUpdated())
		id0Values := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, result.ID0())
		id1Values := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, result.ID1())
		lowSelfRemovedValues := decodeA2BRefresh(t, f.refreshEncoder, f.decryptor, result.LowSelfRemoved())
		highSelfRemovedValues := decodeA2BRefresh(t, f.refreshEncoder, f.decryptor, result.HighSelfRemoved())
		for wordIndex, word := range words {
			bits, oracleErr := z2n.A2BBooleanHalvesOracle(word, z2n.Word8)
			if oracleErr != nil {
				t.Fatal(oracleErr)
			}
			rawLow, _ := a2bRefreshSpecialB0Block(t, f.ringZ, word)
			wantID0 := a2bRefreshLowOracleBlock(t, word)
			wantHighResidual := a2bFullSourceScheduledHighResidualOracleBlock(t, f.ringZ, word)
			for slot := 0; slot < 4; slot++ {
				index := 4*wordIndex + slot
				lowError := math.Abs(real(lowValues[index]) - float64(bits.Low[slot]))
				highError := math.Abs(real(highValues[index]) - float64(bits.High[slot]))
				maxLowError = math.Max(maxLowError, lowError)
				maxHighError = math.Max(maxHighError, highError)
				if lowError > 3e-3 || highError > 3e-3 || math.Abs(imag(lowValues[index])) > 3e-3 || math.Abs(imag(highValues[index])) > 3e-3 {
					t.Fatalf("word=%#02x slot=%d final low/high got=%v/%v want=%d/%d", word, slot, lowValues[index], highValues[index], bits.Low[slot], bits.High[slot])
				}
				iter0Lift := math.Round(16*real(iter0Values[index]) - rawLow[slot])
				iter0Distance := math.Abs(16*real(iter0Values[index]) - rawLow[slot] - iter0Lift)
				iter0RootError := cmplx.Abs(cmplx.Exp(complex(0, 32*math.Pi)*iter0Values[index]) - cmplx.Exp(complex(0, 2*math.Pi*rawLow[slot])))
				maxIter0Lattice = math.Max(maxIter0Lattice, iter0Distance)
				maxIter0Root = math.Max(maxIter0Root, iter0RootError)
				id0Error := math.Abs(real(id0Values[index]) - wantID0[slot])
				maxID0Error = math.Max(maxID0Error, id0Error)

				iter1Residue := wantHighResidual[slot]
				highUpdateError := math.Abs(real(highUpdatedValues[index]) - iter1Residue)
				maxHighUpdateError = math.Max(maxHighUpdateError, highUpdateError)
				iter1Lift := math.Round(16*real(iter1Values[index]) - iter1Residue)
				iter1Distance := math.Abs(16*real(iter1Values[index]) - iter1Residue - iter1Lift)
				iter1RootError := cmplx.Abs(cmplx.Exp(complex(0, 32*math.Pi)*iter1Values[index]) - cmplx.Exp(complex(0, 2*math.Pi*iter1Residue)))
				maxIter1Lattice = math.Max(maxIter1Lattice, iter1Distance)
				maxIter1Root = math.Max(maxIter1Root, iter1RootError)
				wantID1 := iter1Residue - math.Ceil(iter1Residue)
				if math.Abs(iter1Residue-math.Round(iter1Residue)) < 1e-5 {
					wantID1 = 0
				}
				id1Error := math.Abs(real(id1Values[index]) - wantID1)
				maxID1Error = math.Max(maxID1Error, id1Error)
				wantLowSelfRemoved := rawLow[slot] - wantID0[slot]
				wantHighSelfRemoved := iter1Residue - wantID1
				selfRemovalError := math.Max(
					cmplx.Abs(lowSelfRemovedValues[index]-complex(wantLowSelfRemoved, 0)),
					cmplx.Abs(highSelfRemovedValues[index]-complex(wantHighSelfRemoved, 0)),
				)
				maxSelfRemovalError = math.Max(maxSelfRemovalError, selfRemovalError)
				if iter0Distance > 3e-3 || highUpdateError > 3e-3 || iter1Distance > 3e-3 || iter0RootError > 3e-2 || iter1RootError > 3e-2 || id0Error > 3e-3 || id1Error > 3e-3 || selfRemovalError > 3e-3 {
					t.Fatalf("word=%#02x slot=%d lift/root/ID error iter0=%.3g/%.3g/%.3g high-update=%.3g iter1=%.3g/%.3g/%.3g self-remove=%.3g", word, slot, iter0Distance, iter0RootError, id0Error, highUpdateError, iter1Distance, iter1RootError, id1Error, selfRemovalError)
				}
			}
		}
	}
	t.Logf("serial all256 max errors: final-low=%.3g final-high=%.3g iter0-lattice/root/ID=%.3g/%.3g/%.3g high-update=%.3g iter1-lattice/root/ID=%.3g/%.3g/%.3g self-remove=%.3g",
		maxLowError, maxHighError, maxIter0Lattice, maxIter0Root, maxID0Error,
		maxHighUpdateError, maxIter1Lattice, maxIter1Root, maxID1Error, maxSelfRemovalError,
	)
}

func TestA2BFullMissingAndSwappedKeysFailBeforeCiphertextMutation(t *testing.T) {
	f := newA2BFullFixture(t)
	input := f.encrypt(t, [4]uint64{0xa5, 0x5a, 0xff, 0})
	assertPreflightFailure := func(name string) {
		t.Helper()
		before := input.CopyNew()
		_, trace, err := f.evaluator.EvaluateNew(input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if len(trace.States()) != 0 || trace.OperationCounts() != (homchain.A2BFullOperationCounts{}) || !input.Equal(before) {
			t.Fatalf("%s reached a ciphertext operation/state or mutated input: counts=%+v states=%d err=%v",
				name, trace.OperationCounts(), len(trace.States()), err)
		}
	}

	keySet := f.source.MemEvaluationKeySet
	savedRelinearization := keySet.RelinearizationKey
	keySet.RelinearizationKey = nil
	assertPreflightFailure("missing relinearization key")
	keySet.RelinearizationKey = savedRelinearization

	for _, element := range f.circuit.RequiredKeyProfile().All() {
		saved := keySet.GaloisKeys[element]
		delete(keySet.GaloisKeys, element)
		assertPreflightFailure("missing Galois key")
		keySet.GaloisKeys[element] = saved
	}

	elements := f.circuit.RequiredKeyProfile().All()
	if len(elements) < 2 {
		t.Fatalf("need at least two Galois keys for swap negative, got %v", elements)
	}
	first, second := elements[0], elements[1]
	savedFirst := keySet.GaloisKeys[first]
	keySet.GaloisKeys[first] = keySet.GaloisKeys[second]
	assertPreflightFailure("swapped Galois key identity")
	keySet.GaloisKeys[first] = savedFirst

	foreignKeyGenerator := ckks.NewKeyGenerator(f.params)
	foreignSecret := foreignKeyGenerator.GenSecretKeyNew()
	foreignRelinearization := foreignKeyGenerator.GenRelinearizationKeyNew(foreignSecret)
	if foreignRelinearization == savedRelinearization {
		t.Fatal("foreign-secret relinearization replacement unexpectedly aliases the bound key")
	}
	keySet.RelinearizationKey = foreignRelinearization
	assertPreflightFailure("same-parameter foreign-secret relinearization key identity")
	keySet.RelinearizationKey = savedRelinearization

	foreignGalois := foreignKeyGenerator.GenGaloisKeyNew(first, foreignSecret)
	if foreignGalois == savedFirst || foreignGalois.GaloisElement != first {
		t.Fatalf("foreign-secret Galois replacement does not preserve element %d", first)
	}
	keySet.GaloisKeys[first] = foreignGalois
	assertPreflightFailure("same-element foreign-secret Galois key identity")
	keySet.GaloisKeys[first] = savedFirst

	f.source.MemEvaluationKeySet = rlwe.NewMemEvaluationKeySet(savedRelinearization)
	assertPreflightFailure("swapped MemEvaluationKeySet pointer")
	f.source.MemEvaluationKeySet = keySet

	if _, _, err := f.evaluator.EvaluateNew(input); err != nil {
		t.Fatalf("restored keyset did not recover: %v", err)
	}
}

func TestA2BFullParallelHighBackboneIsNotSerialIterationOne(t *testing.T) {
	f := newA2BFullFixture(t)
	input := f.encrypt(t, [4]uint64{0xa5, 0xa5, 0xa5, 0xa5})
	serial, serialTrace, err := f.evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	parallelRefresh, err := f.sourceCircuit.BindEvaluator(f.source)
	if err != nil {
		t.Fatal(err)
	}
	parallelBackbones, parallelTrace, err := parallelRefresh.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if parallelTrace.Schedule() != homchain.A2BRefreshFirstIterationParallelHalfBackbones ||
		serialTrace.ProfileDigest() == parallelTrace.ProfileDigest() {
		t.Fatal("parallel backbone was not profile-distinguished from the serial graph")
	}
	parallelKernelCircuit, err := homchain.NewGaoA2BKernelCircuit(f.params, f.kernelEncoder)
	if err != nil {
		t.Fatal(err)
	}
	parallelKernel, err := parallelKernelCircuit.BindEvaluator(ckks.NewEvaluator(f.params, f.source.MemEvaluationKeySet))
	if err != nil {
		t.Fatal(err)
	}
	parallelResult, err := parallelKernel.EvaluateNew(parallelBackbones.RefreshedHigh())
	if err != nil {
		t.Fatal(err)
	}
	parallelID := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, parallelResult.IDCiphertext())[:4]
	serialID := decodeA2BRefresh(t, f.kernelEncoder, f.decryptor, serial.ID1())[:4]
	_, rawHigh := a2bRefreshSpecialB0Block(t, f.ringZ, 0xa5)
	if math.Abs(16*rawHigh[0]-math.Round(16*rawHigh[0])) < 1e-6 {
		t.Fatal("A5 raw high fixture no longer distinguishes the non-code-point parallel ingress")
	}
	wantSerialID := []float64{-0.125, -0.5625, -0.25, -0.625}
	for slot := 0; slot < 4; slot++ {
		if math.Abs(real(serialID[slot])-wantSerialID[slot]) > 3e-3 ||
			math.Abs(real(parallelID[slot])-real(serialID[slot])) < 1e-3 {
			t.Fatalf("slot %d did not distinguish raw parallel ID from serial propagated ID: parallel=%v serial=%v", slot, parallelID[slot], serialID[slot])
		}
	}
}

func TestA2BFullOpaqueSeamRejectsWrongIngressOrderAndSecondSTCInjection(t *testing.T) {
	params := a2bRefreshFunctionalParameters(t)
	refreshEncoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	kernelEncoder := ckks.NewEncoder(params, 256)
	if _, err := homchain.NewA2BFullCircuit(params, nil, kernelEncoder); err == nil {
		t.Fatal("nil refresh encoder was accepted")
	}
	if _, err := homchain.NewA2BFullCircuit(params, refreshEncoder, nil); err == nil {
		t.Fatal("nil kernel encoder was accepted")
	}
	if _, err := homchain.NewA2BFullCircuit(params, ckks.NewEncoder(params, 128), kernelEncoder); err == nil {
		t.Fatal("non-192-bit refresh encoder was accepted")
	}
	if _, err := homchain.NewA2BFullCircuit(params, refreshEncoder, ckks.NewEncoder(params, 192)); err == nil {
		t.Fatal("non-256-bit kernel encoder was accepted")
	}

	f := newA2BFullFixture(t)
	if got := f.sourceCircuit.Profile().TransformNames(); !reflect.DeepEqual(got, []homchain.TransformName{homchain.V0SpecialB0, homchain.V1Normal}) {
		t.Fatalf("full circuit source ingress is not special-b0 plus normal V1: %v", got)
	}
	typeOfCircuit := reflect.TypeOf(f.circuit)
	methods := make([]string, typeOfCircuit.NumMethod())
	for i := range methods {
		methods[i] = typeOfCircuit.Method(i).Name
	}
	if want := []string{"BindEvaluator", "Profile", "RequiredKeyProfile"}; !reflect.DeepEqual(methods, want) {
		t.Fatalf("public seam permits graph injection or omits audit accessors: got %v want %v", methods, want)
	}
	if f.circuit.Profile().OutputOrder() != [2]string{"low", "high"} || f.circuit.Profile().BitOrder() != "LSB-first" || f.circuit.Profile().Cutoff() != -16 {
		t.Fatal("public profile admitted low/high swap, MSB-first order, or wrong cutoff")
	}
	wrongSecond := f.circuit.Profile().SecondSTC().ExecutionLiteral()
	wrongSecond.LevelQ = 18
	wrongSecond.Levels = []int{1, 1, 1}
	if sealed := f.circuit.Profile().SecondSTC().ExecutionLiteral(); sealed.LevelQ != 3 || !reflect.DeepEqual(sealed.Levels, []int{1, 1}) {
		t.Fatal("caller changed the private second STC through its detached accessor")
	}
	_, trace, err := f.evaluator.EvaluateNew(f.encrypt(t, [4]uint64{0xa5, 0x5a, 0xff, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if state, ok := trace.State(homchain.A2BFullStageIter1STC); !ok || state.Level != 1 {
		t.Fatalf("detached wrong-level second STC affected execution: ok=%t state=%+v", ok, state)
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate A2B full source")
	}
	sourceBytes, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "a2b_full.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, required := range []string{
		"iter0Masked, A2BRefreshLowHalf, e.circuit.refresh.stc, 18, 16",
		"SubNew(highAligned, id0Over16)", "SubNew(lowAligned, id0)",
		"iter1Masked, A2BRefreshHighHalf, e.circuit.secondSTC, 3, 1",
		"lowMSB: msb0", "highMSB: msb1", "a2bFullFixedS35Scale()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("production source omits sealed serial-order witness %q", required)
		}
	}
	if got := strings.Count(source, "refreshHalfWithSTC("); got != 2 {
		t.Fatalf("production has %d refresh invocations, want exactly two serial invocations", got)
	}
	if strings.Contains(source, "trace.operationCounts = e.circuit.profile.operationCounts") {
		t.Fatal("trace operation counts are copied from the sealed profile instead of derived from execution")
	}
	for _, witness := range []struct {
		token string
		want  int
	}{
		{"trace.operationCounts.SpecialB0Transforms++", 1},
		{"trace.operationCounts.MaskMulRescales++", 2},
		{"trace.operationCounts.RefreshInvocations++", 2},
		{"trace.operationCounts.KernelInvocations++", 2},
		{"trace.operationCounts.IDScaleMulRescales++", 1},
		{"trace.operationCounts.AlignmentDrops++", 3},
		{"trace.operationCounts.Subtractions++", 3},
		{"trace.operationCounts.SharedCTSUses++", 2},
	} {
		if got := strings.Count(source, witness.token); got != witness.want {
			t.Fatalf("execution-derived ledger witness %q count=%d, want %d", witness.token, got, witness.want)
		}
	}
	if !strings.Contains(source, "trace.operationCounts != e.circuit.profile.operationCounts") {
		t.Fatal("runtime operation ledger is not compared with the sealed profile before return")
	}
	for _, forbidden := range []string{
		".SetScale(", ".Rotate(", "V0Normal", "V0FusedT", "C2Z",
		"ciphertextScaleDefault", "under construction",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("production source contains forbidden hidden bridge/rotation/ingress %q", forbidden)
		}
	}
}

func TestA2BFullRejectsWrongCiphertextIngressBeforeOperation(t *testing.T) {
	f := newA2BFullFixture(t)
	base := f.encrypt(t, [4]uint64{0xa5, 0x5a, 0xff, 0})
	tests := []struct {
		name   string
		mutate func(*rlwe.Ciphertext)
	}{
		{"level19-core-instead-of-arithmetic-input", func(ct *rlwe.Ciphertext) { ct.Resize(ct.Degree(), 19) }},
		{"wrong-scale", func(ct *rlwe.Ciphertext) { ct.Scale = rlwe.NewScale(uint64(1) << 34) }},
		{"partial-packing", func(ct *rlwe.Ciphertext) { ct.LogDimensions.Cols = 3 }},
		{"degree-two", func(ct *rlwe.Ciphertext) { ct.Resize(2, ct.Level()) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base.CopyNew()
			test.mutate(input)
			before := input.CopyNew()
			_, trace, err := f.evaluator.EvaluateNew(input)
			if err == nil || len(trace.States()) != 0 || !input.Equal(before) {
				t.Fatalf("wrong ingress reached execution or mutated input: states=%d err=%v", len(trace.States()), err)
			}
		})
	}
}

func newA2BFullFixture(t *testing.T) a2bFullFixture {
	t.Helper()
	params := a2bRefreshFunctionalParameters(t)
	refreshEncoder := ckks.NewEncoder(params, a2bRefreshTestPrecision)
	kernelEncoder := ckks.NewEncoder(params, 256)
	circuit, err := homchain.NewA2BFullCircuit(params, refreshEncoder, kernelEncoder)
	if err != nil {
		t.Fatal(err)
	}
	keyGenerator := ckks.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	sourceCircuit, err := homchain.NewA2BRefreshCircuit(params, refreshEncoder)
	if err != nil {
		t.Fatal(err)
	}
	source := a2bRefreshBootstrapEvaluator(t, sourceCircuit, params, keyGenerator, secretKey)
	evaluator, err := circuit.BindEvaluator(source)
	if err != nil {
		t.Fatal(err)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, a2bRefreshTestPrecision)
	if err != nil {
		t.Fatal(err)
	}
	return a2bFullFixture{
		params: params, refreshEncoder: refreshEncoder, kernelEncoder: kernelEncoder,
		circuit: circuit, sourceCircuit: sourceCircuit, source: source, evaluator: evaluator,
		ringZ: ringZ, secretKey: secretKey, encryptor: ckks.NewEncryptor(params, secretKey),
		decryptor: ckks.NewDecryptor(params, secretKey),
	}
}

func (f a2bFullFixture) encrypt(t *testing.T, words [4]uint64) *rlwe.Ciphertext {
	t.Helper()
	return encryptA2BRefreshWords(t, f.sourceCircuit, f.params, f.ringZ, f.refreshEncoder, f.encryptor, words)
}

func a2bFullSourceScheduledHighResidualOracleBlock(t *testing.T, ringZ *z2n.Ring, word uint64) []float64 {
	t.Helper()
	_, rawHigh := a2bRefreshSpecialB0Block(t, ringZ, word)
	id0 := a2bRefreshLowOracleBlock(t, word)
	result := append([]float64(nil), rawHigh...)
	for slot := range result {
		// Upstream pin 08f1eb8, z-fhe.cpp:543-558: scale ID0 by 2^-4,
		// raw rotation -4 becomes effective rotation 0 after +n/2, then
		// subtract elementwise from core1.
		result[slot] -= id0[slot] / 16
	}
	return result
}

func TestA2BFullSerialA5ReturnsLSBFirstHalves(t *testing.T) {
	f := newA2BFullFixture(t)
	input := f.encrypt(t, [4]uint64{0xa5, 0xa5, 0xa5, 0xa5})
	inputBefore := input.CopyNew()
	sharedKeySet := f.source.MemEvaluationKeySet
	sharedRelinearization, err := sharedKeySet.GetRelinearizationKey()
	if err != nil {
		t.Fatal(err)
	}
	sharedGalois := make(map[uint64]*rlwe.GaloisKey)
	for _, element := range f.circuit.RequiredKeyProfile().All() {
		sharedGalois[element], err = sharedKeySet.GetGaloisKey(element)
		if err != nil {
			t.Fatal(err)
		}
	}
	result, trace, err := f.evaluator.EvaluateNew(input)
	if err != nil {
		t.Fatal(err)
	}
	if !input.Equal(inputBefore) {
		t.Fatal("serial A2B mutated its arithmetic input")
	}
	if f.source.MemEvaluationKeySet != sharedKeySet {
		t.Fatal("serial evaluation replaced the shared MemEvaluationKeySet pointer")
	}
	if after, getErr := sharedKeySet.GetRelinearizationKey(); getErr != nil || after != sharedRelinearization {
		t.Fatal("serial evaluation replaced the shared relinearization-key pointer")
	}
	for element, before := range sharedGalois {
		if after, getErr := sharedKeySet.GetGaloisKey(element); getErr != nil || after != before {
			t.Fatalf("serial evaluation replaced shared Galois-key %d pointer", element)
		}
	}
	assertRepeatedA2BRefreshBlock(t, f.kernelEncoder, f.decryptor, result.LowMSB(), []float64{1, 0, 1, 0}, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.kernelEncoder, f.decryptor, result.HighMSB(), []float64{0, 1, 0, 1}, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.kernelEncoder, f.decryptor, result.ID0(), []float64{-0.5, -0.25, -0.625, -0.3125}, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.refreshEncoder, f.decryptor, result.ID0Over16(), []float64{-0.03125, -0.015625, -0.0390625, -0.01953125}, 3e-3)
	wantHighUpdated := a2bFullSourceScheduledHighResidualOracleBlock(t, f.ringZ, 0xa5)
	if want := []float64{-0.125, -0.5625, -0.25, -0.625}; !reflect.DeepEqual(wantHighUpdated, want) {
		t.Fatalf("independent A5 source propagation oracle=%v, want %v", wantHighUpdated, want)
	}
	prefixReencode := a2bRefreshHalfOracleBlock(t, 0xa5, z2n.BooleanHighHalf)
	if want := []float64{0, -0.5, -0.25, -0.625}; !reflect.DeepEqual(prefixReencode, want) || reflect.DeepEqual(prefixReencode, wantHighUpdated) {
		t.Fatalf("stale prefix-reencode control was not distinguished: prefix=%v source-residual=%v", prefixReencode, wantHighUpdated)
	}
	assertRepeatedA2BRefreshBlock(t, f.refreshEncoder, f.decryptor, result.HighUpdated(), wantHighUpdated, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.refreshEncoder, f.decryptor, result.Iter1Masked(), wantHighUpdated, 3e-3)
	// Source z-fhe.cpp:543-558 propagates ID0*2^-4 elementwise; the cross-half
	// rotation is exactly zero for n=8,w=4. The second periodic ID therefore
	// equals this updated residue, while the final MSB is checked above against
	// the independent Boolean oracle.
	assertRepeatedA2BRefreshBlock(t, f.kernelEncoder, f.decryptor, result.ID1(), wantHighUpdated, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.refreshEncoder, f.decryptor, result.LowSelfRemoved(), []float64{0, 0, 0, 0}, 3e-3)
	assertRepeatedA2BRefreshBlock(t, f.refreshEncoder, f.decryptor, result.HighSelfRemoved(), []float64{0, 0, 0, 0}, 3e-3)

	wantStates := []struct {
		stage homchain.A2BFullStage
		level int
	}{
		{homchain.A2BFullStageInput, 20},
		{homchain.A2BFullStageSpecialLow, 19},
		{homchain.A2BFullStageSpecialHigh, 19},
		{homchain.A2BFullStageIter0Mask, 18},
		{homchain.A2BFullStageIter0STC, 16},
		{homchain.A2BFullStageIter0ScaleDown, 0},
		{homchain.A2BFullStageIter0ModUp, 20},
		{homchain.A2BFullStageIter0CTS, 17},
		{homchain.A2BFullStageIter0ID, 5},
		{homchain.A2BFullStageIter0MSB, 5},
		{homchain.A2BFullStageID0Over16, 4},
		{homchain.A2BFullStageHighAligned, 4},
		{homchain.A2BFullStageHighUpdated, 4},
		{homchain.A2BFullStageLowAligned, 5},
		{homchain.A2BFullStageLowSelfRemoved, 5},
		{homchain.A2BFullStageIter1Mask, 3},
		{homchain.A2BFullStageIter1STC, 1},
		{homchain.A2BFullStageIter1ScaleDown, 0},
		{homchain.A2BFullStageIter1ModUp, 20},
		{homchain.A2BFullStageIter1CTS, 17},
		{homchain.A2BFullStageIter1ID, 5},
		{homchain.A2BFullStageIter1MSB, 5},
		{homchain.A2BFullStageID1Aligned, 4},
		{homchain.A2BFullStageHighSelfRemoved, 4},
	}
	states := trace.States()
	if got, want := len(states), len(wantStates); got != want {
		t.Fatalf("serial trace states=%d, want %d", got, want)
	}
	for index, want := range wantStates {
		got := states[index]
		if got.Stage != want.stage || got.Level != want.level || got.Degree != 1 ||
			got.LogDimensions != f.params.LogMaxDimensions() || !got.Scale.EqualScale(f.params.DefaultScale()) {
			t.Fatalf("serial trace state[%d]=%+v, want stage=%s/L%d/degree1/dimensions=%+v/exact-S35",
				index, got, want.stage, want.level, f.params.LogMaxDimensions())
		}
	}
	for iteration := 0; iteration < 2; iteration++ {
		_, errLog2, ok := trace.ScaleDownError(iteration)
		if !ok || math.Abs(errLog2) > 1e-6 {
			t.Fatalf("iteration %d ScaleDown error missing or too large: ok=%t log2=%g", iteration, ok, errLog2)
		}
		provenance, ok := trace.KernelProvenance(iteration)
		if !ok || len(provenance.States()) == 0 || provenance.States()[0].Level != 17 {
			t.Fatalf("iteration %d kernel provenance missing exact L17 ingress", iteration)
		}
	}
	if !trace.KeyPreflight().GraphMatched || trace.ProfileDigest() != f.circuit.Profile().Digest() {
		t.Fatal("serial trace omitted preflight/profile evidence")
	}
	if trace.OperationCounts() != f.circuit.Profile().OperationCounts() {
		t.Fatalf("serial trace operation ledger=%+v, profile=%+v", trace.OperationCounts(), f.circuit.Profile().OperationCounts())
	}
	lowCopy := result.LowMSB()
	lowCopy.Resize(lowCopy.Degree(), 0)
	if result.LowMSB().Level() != 5 {
		t.Fatal("result accessors alias saved output ciphertexts")
	}
}
