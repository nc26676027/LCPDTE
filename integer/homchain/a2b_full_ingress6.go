package homchain

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	ckksdft "github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	ckkslintrans "github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

const (
	a2bFullIngress6RangeDigestSchema     = "a2b-full-ingress6-range-v1"
	a2bFullIngress6AdmissionDigestSchema = "a2b-full-ingress6-admission-v1"
	a2bFullIngress6InputBindingSchema    = "a2b-full-ingress6-input-binding-v1"
	a2bFullIngress6ProfileDigestSchema   = "a2b-full-ingress6-profile-v2"
	a2bFullIngress6EncodedFactorSchema   = "a2b-full-ingress6-encoded-factor-v1"
	a2bFullIngress6EncodedGroupSchema    = "a2b-full-ingress6-encoded-group-v1"
	a2bFullIngress6LevelLedger           = "input6->special5->mask4->first-stc-factor3/2->sd0->mu20->cts17->kernel5->id0/16-4->high5-drop4-sub->iter1-mask3->stc1->sd0->mu20->cts17->kernel5->low5/high5"
	A2BFullIngress6TrustedDeclaredOrigin = "trusted_declared_parameter_origin_not_a_cryptographic_ciphertext_origin_or_range_proof"
)

type A2BFullIngress6Schedule string

const A2BFullIngress6SerialLowThenHigh A2BFullIngress6Schedule = "fixed_l6_then_accepted_serial_low_then_high"

// A2BFullIngress6Source is a closed producer class. A source name is not an
// authorization token: construction accepts only the enumerated schemas and
// derives the admission digest from the complete sealed profile.
type A2BFullIngress6Source string

const (
	A2BFullIngress6Depth2PrefixL6V1        A2BFullIngress6Source = "depth2_prefix_l6_v1"
	A2BFullIngress6StandaloneTestFixtureV1 A2BFullIngress6Source = "standalone_test_fixture_v1"
)

func (s A2BFullIngress6Source) validate() error {
	switch s {
	case A2BFullIngress6Depth2PrefixL6V1, A2BFullIngress6StandaloneTestFixtureV1:
		return nil
	default:
		return fmt.Errorf("homchain: unsupported A2B ingress6 producer source %q", s)
	}
}

// A2BFullIngress6RangeCertificate is the immutable full Z_256 conversion
// range admitted by this operator. Signed subtraction/no-overflow proofs are
// owned by the future sibling comparator, not by this certificate.
type A2BFullIngress6RangeCertificate struct {
	wordBits z2n.WordBits
	minimum  uint64
	maximum  uint64
	digest   string
}

func NewA2BFullIngress6FullRingRangeCertificate() A2BFullIngress6RangeCertificate {
	result := A2BFullIngress6RangeCertificate{wordBits: z2n.Word8, minimum: 0, maximum: 255}
	result.digest = digestString(fmt.Sprintf(
		"%s|word-bits=%d|minimum=%d|maximum=%d|semantics=complete-z2^8-residue-domain",
		a2bFullIngress6RangeDigestSchema, result.wordBits, result.minimum, result.maximum,
	))
	return result
}

func (c A2BFullIngress6RangeCertificate) WordBits() z2n.WordBits { return c.wordBits }
func (c A2BFullIngress6RangeCertificate) Minimum() uint64        { return c.minimum }
func (c A2BFullIngress6RangeCertificate) Maximum() uint64        { return c.maximum }
func (c A2BFullIngress6RangeCertificate) Digest() string         { return c.digest }

func (c A2BFullIngress6RangeCertificate) validate() error {
	want := NewA2BFullIngress6FullRingRangeCertificate()
	if c != want {
		return fmt.Errorf("homchain: A2B ingress6 requires the sealed full Z_256 range certificate")
	}
	return nil
}

// A2BFullIngress6Profile is the immutable public projection of the fixed L6
// sibling. Further graph fields are added only as their executable slices are
// introduced through the red-green loop.
type A2BFullIngress6Profile struct {
	fidelity                       A2BFullFidelity
	schedule                       A2BFullIngress6Schedule
	inputLevel, outputLevel        int
	inputScale                     ExactScaleSnapshot
	firstSTCFactorOutputLevels     []int
	source                         A2BFullIngress6Source
	trustedOriginAssumption        string
	rangeDigest                    string
	parameterDigest                string
	admissionDigest                string
	suffixProfileDigest            string
	keyProfileDigest               string
	specialB0CompiledDigest        string
	maskPayloadDigest              string
	firstSTCRawMatrixDigest        string
	firstSTCExecutionMatrixDigest  string
	sharedCTSExecutionMatrixDigest string
	firstSTCEncodedPayloadDigest   string
	sharedCTSEncodedPayloadDigest  string
	secondSTCEncodedPayloadDigest  string
	operationCounts                A2BFullIngress6OperationCounts
	expectedStates                 []A2BFullIngress6CiphertextState
	serializedBytes                A2BFullIngress6SerializedBytes
	levelLedger                    string
	digest                         string
}

func (p A2BFullIngress6Profile) Fidelity() A2BFullFidelity         { return p.fidelity }
func (p A2BFullIngress6Profile) Schedule() A2BFullIngress6Schedule { return p.schedule }
func (p A2BFullIngress6Profile) InputLevel() int                   { return p.inputLevel }
func (p A2BFullIngress6Profile) OutputLevel() int                  { return p.outputLevel }
func (p A2BFullIngress6Profile) InputScale() ExactScaleSnapshot    { return p.inputScale }
func (p A2BFullIngress6Profile) FirstSTCFactorOutputLevels() []int {
	return append([]int(nil), p.firstSTCFactorOutputLevels...)
}
func (p A2BFullIngress6Profile) Source() A2BFullIngress6Source { return p.source }
func (p A2BFullIngress6Profile) TrustedOriginAssumption() string {
	return p.trustedOriginAssumption
}
func (p A2BFullIngress6Profile) RangeDigest() string         { return p.rangeDigest }
func (p A2BFullIngress6Profile) ParameterDigest() string     { return p.parameterDigest }
func (p A2BFullIngress6Profile) AdmissionDigest() string     { return p.admissionDigest }
func (p A2BFullIngress6Profile) SuffixProfileDigest() string { return p.suffixProfileDigest }
func (p A2BFullIngress6Profile) KeyProfileDigest() string    { return p.keyProfileDigest }
func (p A2BFullIngress6Profile) SpecialB0CompiledDigest() string {
	return p.specialB0CompiledDigest
}
func (p A2BFullIngress6Profile) MaskPayloadDigest() string { return p.maskPayloadDigest }
func (p A2BFullIngress6Profile) FirstSTCRawMatrixDigest() string {
	return p.firstSTCRawMatrixDigest
}
func (p A2BFullIngress6Profile) FirstSTCExecutionMatrixDigest() string {
	return p.firstSTCExecutionMatrixDigest
}
func (p A2BFullIngress6Profile) SharedCTSExecutionMatrixDigest() string {
	return p.sharedCTSExecutionMatrixDigest
}
func (p A2BFullIngress6Profile) FirstSTCEncodedPayloadDigest() string {
	return p.firstSTCEncodedPayloadDigest
}
func (p A2BFullIngress6Profile) SharedCTSEncodedPayloadDigest() string {
	return p.sharedCTSEncodedPayloadDigest
}
func (p A2BFullIngress6Profile) SecondSTCEncodedPayloadDigest() string {
	return p.secondSTCEncodedPayloadDigest
}
func (p A2BFullIngress6Profile) OperationCounts() A2BFullIngress6OperationCounts {
	return p.operationCounts
}
func (p A2BFullIngress6Profile) ExpectedStates() []A2BFullIngress6CiphertextState {
	return append([]A2BFullIngress6CiphertextState(nil), p.expectedStates...)
}
func (p A2BFullIngress6Profile) ExpectedSerializedBytes() A2BFullIngress6SerializedBytes {
	return cloneA2BFullIngress6SerializedBytes(p.serializedBytes)
}
func (p A2BFullIngress6Profile) LevelLedger() string { return p.levelLedger }
func (p A2BFullIngress6Profile) Digest() string      { return p.digest }

// A2BFullIngress6OperationCounts is incremented by the physical evaluator.
// It extends the accepted serial ledger with the two observed L4 STC factors.
type A2BFullIngress6OperationCounts struct {
	SpecialB0Transforms int
	MaskMulRescales     int
	FirstSTCFactors     int
	FirstSTCRescales    int
	GuardedScaleDowns   int
	DenseModUps         int
	CTSFactors          int
	RefreshInvocations  int
	KernelInvocations   int
	IDScaleMulRescales  int
	AlignmentDrops      int
	Subtractions        int
	SecondSTCFactors    int
	SecondSTCRescales   int
	SharedCTSUses       int
}

// A2BFullIngress6Circuit is a fixed sibling. It embeds the accepted serial
// graph as its suffix but never changes that graph's constructor or profile.
type A2BFullIngress6Circuit struct {
	params        ckks.Parameters
	suffix        *A2BFullCircuit
	specialSource PairSpec
	specialB0     CompiledPair
	lowMask       *rlwe.Plaintext
	firstSTC      ckksdft.Matrix
	firstSTCRaw   ckksdft.MatrixLiteral
	firstSTCExec  ckksdft.MatrixLiteral
	ranges        A2BFullIngress6RangeCertificate
	profile       A2BFullIngress6Profile
	keyProfile    A2BRefreshKeyProfile
	graph         a2bFullIngress6CircuitGraph
}

// A2BFullIngress6Input owns an admitted ciphertext copy. Its unexported source
// accessor is the typed package seam used by the future depth-2 prefix.
type A2BFullIngress6Input struct {
	ciphertext      *rlwe.Ciphertext
	pathDigest      string
	parameterDigest string
	producerSource  A2BFullIngress6Source
	rangeDigest     string
	admissionDigest string
	payloadDigest   string
	bindingDigest   string
}

func (i A2BFullIngress6Input) Level() int {
	if i.ciphertext == nil {
		return -1
	}
	return i.ciphertext.Level()
}
func (i A2BFullIngress6Input) ParameterDigest() string { return i.parameterDigest }
func (i A2BFullIngress6Input) RangeDigest() string     { return i.rangeDigest }
func (i A2BFullIngress6Input) AdmissionDigest() string { return i.admissionDigest }
func (i A2BFullIngress6Input) PayloadDigest() string   { return i.payloadDigest }
func (i A2BFullIngress6Input) BindingDigest() string   { return i.bindingDigest }
func (i A2BFullIngress6Input) producer() A2BFullIngress6Source {
	return i.producerSource
}

type A2BFullIngress6Stage string

const (
	A2BFullIngress6StageAdmission       A2BFullIngress6Stage = "admission"
	A2BFullIngress6StageKeyPreflight    A2BFullIngress6Stage = "key-preflight"
	A2BFullIngress6StageInput           A2BFullIngress6Stage = "input"
	A2BFullIngress6StageSpecialLow      A2BFullIngress6Stage = "special-b0-low"
	A2BFullIngress6StageSpecialHigh     A2BFullIngress6Stage = "special-b0-high"
	A2BFullIngress6StageIter0Mask       A2BFullIngress6Stage = "iter0-low-mask"
	A2BFullIngress6StageIter0STCFactor0 A2BFullIngress6Stage = "iter0-stc-factor0"
	A2BFullIngress6StageIter0STCFactor1 A2BFullIngress6Stage = "iter0-stc-factor1"
	A2BFullIngress6StageIter0ScaleDown  A2BFullIngress6Stage = "iter0-scale-down"
	A2BFullIngress6StageIter0ModUp      A2BFullIngress6Stage = "iter0-mod-up"
	A2BFullIngress6StageIter0CTS        A2BFullIngress6Stage = "iter0-cts"
	A2BFullIngress6StageIter0ID         A2BFullIngress6Stage = "iter0-id"
	A2BFullIngress6StageIter0MSB        A2BFullIngress6Stage = "iter0-msb"
	A2BFullIngress6StageID0Over16       A2BFullIngress6Stage = "id0-over-16"
	A2BFullIngress6StageHighAligned     A2BFullIngress6Stage = "high-core-aligned"
	A2BFullIngress6StageHighUpdated     A2BFullIngress6Stage = "high-core-minus-id0-over-16"
	A2BFullIngress6StageLowAligned      A2BFullIngress6Stage = "low-core-aligned"
	A2BFullIngress6StageLowSelfRemoved  A2BFullIngress6Stage = "low-core-minus-id0"
	A2BFullIngress6StageIter1Mask       A2BFullIngress6Stage = "iter1-high-mask"
	A2BFullIngress6StageIter1STC        A2BFullIngress6Stage = "iter1-stc"
	A2BFullIngress6StageIter1ScaleDown  A2BFullIngress6Stage = "iter1-scale-down"
	A2BFullIngress6StageIter1ModUp      A2BFullIngress6Stage = "iter1-mod-up"
	A2BFullIngress6StageIter1CTS        A2BFullIngress6Stage = "iter1-cts"
	A2BFullIngress6StageIter1ID         A2BFullIngress6Stage = "iter1-id"
	A2BFullIngress6StageIter1MSB        A2BFullIngress6Stage = "iter1-msb"
	A2BFullIngress6StageID1Aligned      A2BFullIngress6Stage = "id1-aligned"
	A2BFullIngress6StageHighSelfRemoved A2BFullIngress6Stage = "high-core-minus-id0-over-16-minus-id1"
)

type A2BFullIngress6CiphertextState struct {
	Stage           A2BFullIngress6Stage
	Level           int
	Degree          int
	LogDimensions   ring.Dimensions
	Scale           ExactScaleSnapshot
	SerializedBytes int
}

// A2BFullIngress6SerializedBoundary records one exact local checkpoint
// encoding. Retained boundaries are diagnostic storage and are not classified
// as communication.
type A2BFullIngress6SerializedBoundary struct {
	Stage A2BFullIngress6Stage
	Bytes int
}

// A2BFullIngress6SerializedBytes separates explicit online encodings from the
// ordered local checkpoint ledger. OnlineTotal does not assert that a transport
// occurred; the benchmark harness decides that protocol-level fact.
type A2BFullIngress6SerializedBytes struct {
	onlineInput, onlineLowOutput, onlineHighOutput int
	retainedBoundaries                             []A2BFullIngress6SerializedBoundary
}

func (s A2BFullIngress6SerializedBytes) OnlineInputBytes() int      { return s.onlineInput }
func (s A2BFullIngress6SerializedBytes) OnlineLowOutputBytes() int  { return s.onlineLowOutput }
func (s A2BFullIngress6SerializedBytes) OnlineHighOutputBytes() int { return s.onlineHighOutput }
func (s A2BFullIngress6SerializedBytes) OnlineTotal() int {
	return s.onlineInput + s.onlineLowOutput + s.onlineHighOutput
}
func (s A2BFullIngress6SerializedBytes) RetainedBoundaries() []A2BFullIngress6SerializedBoundary {
	return append([]A2BFullIngress6SerializedBoundary(nil), s.retainedBoundaries...)
}
func (s A2BFullIngress6SerializedBytes) RetainedTraceTotal() int {
	total := 0
	for _, boundary := range s.retainedBoundaries {
		total += boundary.Bytes
	}
	return total
}
func (s A2BFullIngress6SerializedBytes) Complete() bool {
	if s.onlineInput <= 0 || s.onlineLowOutput <= 0 || s.onlineHighOutput <= 0 || len(s.retainedBoundaries) != 25 {
		return false
	}
	for _, boundary := range s.retainedBoundaries {
		if boundary.Stage == "" || boundary.Bytes <= 0 {
			return false
		}
	}
	return true
}

func cloneA2BFullIngress6SerializedBytes(input A2BFullIngress6SerializedBytes) A2BFullIngress6SerializedBytes {
	input.retainedBoundaries = input.RetainedBoundaries()
	return input
}

type A2BFullIngress6Trace struct {
	profileDigest             string
	rangeDigest               string
	admissionDigest           string
	inputBindingDigest        string
	failureStage              A2BFullIngress6Stage
	states                    []A2BFullIngress6CiphertextState
	keyPreflight              A2BRefreshKeyPreflight
	runtimeGalois             []uint64
	relinearizationKeyMatched bool
	operationCounts           A2BFullIngress6OperationCounts
	serializedBytes           A2BFullIngress6SerializedBytes
	retainedCiphertexts       map[A2BFullIngress6Stage]*rlwe.Ciphertext
	iter0ErrScale             ExactScaleSnapshot
	iter0ErrLog2              float64
	iter1ErrScale             ExactScaleSnapshot
	iter1ErrLog2              float64
	iter0Kernel               GaoA2BKernelProvenance
	iter1Kernel               GaoA2BKernelProvenance
}

func (t A2BFullIngress6Trace) ProfileDigest() string              { return t.profileDigest }
func (t A2BFullIngress6Trace) RangeDigest() string                { return t.rangeDigest }
func (t A2BFullIngress6Trace) AdmissionDigest() string            { return t.admissionDigest }
func (t A2BFullIngress6Trace) InputBindingDigest() string         { return t.inputBindingDigest }
func (t A2BFullIngress6Trace) FailureStage() A2BFullIngress6Stage { return t.failureStage }
func (t A2BFullIngress6Trace) States() []A2BFullIngress6CiphertextState {
	return append([]A2BFullIngress6CiphertextState(nil), t.states...)
}
func (t A2BFullIngress6Trace) State(stage A2BFullIngress6Stage) (A2BFullIngress6CiphertextState, bool) {
	for _, state := range t.states {
		if state.Stage == stage {
			return state, true
		}
	}
	return A2BFullIngress6CiphertextState{}, false
}
func (t A2BFullIngress6Trace) KeyPreflight() A2BRefreshKeyPreflight {
	return cloneA2BRefreshKeyPreflight(t.keyPreflight)
}
func (t A2BFullIngress6Trace) OperationCounts() A2BFullIngress6OperationCounts {
	return t.operationCounts
}
func (t A2BFullIngress6Trace) RuntimeGaloisElements() []uint64 {
	return append([]uint64(nil), t.runtimeGalois...)
}
func (t A2BFullIngress6Trace) RelinearizationKeyMatched() bool { return t.relinearizationKeyMatched }
func (t A2BFullIngress6Trace) SerializedBytes() A2BFullIngress6SerializedBytes {
	return cloneA2BFullIngress6SerializedBytes(t.serializedBytes)
}

// RetainedCiphertext returns a detached copy of the real runtime ciphertext
// marshaled for the named local checkpoint. It is diagnostic evidence, not a
// communication artifact.
func (t A2BFullIngress6Trace) RetainedCiphertext(stage A2BFullIngress6Stage) (*rlwe.Ciphertext, bool) {
	ciphertext, ok := t.retainedCiphertexts[stage]
	if !ok || ciphertext == nil {
		return nil, false
	}
	return ciphertext.CopyNew(), true
}
func (t A2BFullIngress6Trace) ScaleDownError(iteration int) (ExactScaleSnapshot, float64, bool) {
	if iteration == 0 {
		return t.iter0ErrScale, t.iter0ErrLog2, t.iter0ErrScale.ValueHex() != ""
	}
	if iteration == 1 {
		return t.iter1ErrScale, t.iter1ErrLog2, t.iter1ErrScale.ValueHex() != ""
	}
	return ExactScaleSnapshot{}, 0, false
}
func (t A2BFullIngress6Trace) KernelProvenance(iteration int) (GaoA2BKernelProvenance, bool) {
	if iteration == 0 {
		return t.iter0Kernel, t.iter0Kernel.ProfileDigest() != ""
	}
	if iteration == 1 {
		return t.iter1Kernel, t.iter1Kernel.ProfileDigest() != ""
	}
	return GaoA2BKernelProvenance{}, false
}

type a2bFullIngress6CircuitGraph struct {
	circuit                 *A2BFullIngress6Circuit
	suffix                  *A2BFullCircuit
	specialLow              uintptr
	specialHigh             uintptr
	mask                    *rlwe.Plaintext
	maskSeal                *rlwe.Plaintext
	firstSTCFactors         []uintptr
	sharedCTSFactors        []uintptr
	secondSTCFactors        []uintptr
	firstSTCPayloadDigests  []string
	sharedCTSPayloadDigests []string
	secondSTCPayloadDigests []string
	firstSTCPayloadDigest   string
	sharedCTSPayloadDigest  string
	secondSTCPayloadDigest  string
	profileDigest           string
	keyDigest               string
}

type A2BFullIngress6Evaluator struct {
	circuit *A2BFullIngress6Circuit
	suffix  *A2BFullEvaluator
	graph   a2bFullIngress6CircuitGraph
}

func NewA2BFullIngress6Circuit(
	params ckks.Parameters,
	refreshEncoder, kernelEncoder *ckks.Encoder,
	source A2BFullIngress6Source,
	ranges A2BFullIngress6RangeCertificate,
) (*A2BFullIngress6Circuit, error) {
	if err := source.validate(); err != nil {
		return nil, err
	}
	if err := ranges.validate(); err != nil {
		return nil, err
	}
	suffix, err := NewA2BFullCircuit(params, refreshEncoder, kernelEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B ingress6 accepted suffix: %w", err)
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, refreshEncoder.Prec())
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B ingress6 Z2^8 ring: %w", err)
	}
	specifications, err := NewSpecificationsFromRing(ringZ, 4)
	if err != nil {
		return nil, fmt.Errorf("homchain: construct A2B ingress6 transform specifications: %w", err)
	}
	specialSource := specifications.VSpecialB0Pair()
	options := CompileOptions{
		LevelQ: 6, LevelP: params.MaxLevelP(), Scale: rlwe.NewScale(params.Q()[6]),
		LogBabyStepGiantStepRatio: 0,
	}
	specialB0, err := CompilePair(params, refreshEncoder, specialSource, options)
	if err != nil {
		return nil, fmt.Errorf("homchain: compile A2B ingress6 special-b0: %w", err)
	}
	if err = validateCompiledPairAtLevel("A2B ingress6 special-b0", specialB0, 6); err != nil {
		return nil, err
	}
	specialDigest, err := digestA2BFullIngress6CompiledPair(specialB0)
	if err != nil {
		return nil, err
	}

	firstRaw, _ := a2bRefreshDFTLiterals(params, refreshEncoder.Prec(), 4, params.MaxLevel())
	stcInitializationFactor, _, err := a2bRefreshDFTInitializationFactors(params)
	if err != nil {
		return nil, err
	}
	firstExecution := scaleA2BRefreshDFTLiteral(firstRaw, stcInitializationFactor, refreshEncoder.Prec())
	firstRawDigest := digestDFTMatrixNumericPayload(firstRaw, firstRaw.GenMatrices(params.LogN(), refreshEncoder.Prec()))
	firstSTC, firstExecutionDigest, err := newDFTMatrixFromLiteralAtPrecision(params, firstExecution, refreshEncoder)
	if err != nil {
		return nil, fmt.Errorf("homchain: encode A2B ingress6 first STC: %w", err)
	}
	if firstSTC.LevelQ != 4 || firstSTC.Depth(true) != 2 || len(firstSTC.Matrices) != 2 ||
		!reflect.DeepEqual(firstSTC.Levels, []int{1, 1}) {
		return nil, fmt.Errorf("homchain: A2B ingress6 first STC is not the fixed L4->[L3,L2] matrix")
	}
	factorLevels := make([]int, len(firstSTC.Levels))
	level := firstSTC.LevelQ
	for index := range firstSTC.Levels {
		level -= params.LevelsConsumedPerRescaling()
		factorLevels[index] = level
	}
	if !reflect.DeepEqual(factorLevels, []int{3, 2}) {
		return nil, fmt.Errorf("homchain: A2B ingress6 first STC factor outputs=%v, want [3 2]", factorLevels)
	}

	lowMask, err := newA2BRefreshMask(params, refreshEncoder, 5, rlwe.NewScale(params.Q()[5]))
	if err != nil {
		return nil, fmt.Errorf("homchain: encode A2B ingress6 low mask: %w", err)
	}
	maskBytes, err := lowMask.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B ingress6 low mask: %w", err)
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("homchain: marshal A2B ingress6 parameters: %w", err)
	}
	parameterDigest := sha256Hex(parameterBytes)
	inputScale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, fmt.Errorf("homchain: snapshot A2B ingress6 scale: %w", err)
	}
	expectedStates, err := newA2BFullIngress6ExpectedStates(params)
	if err != nil {
		return nil, fmt.Errorf("homchain: derive A2B ingress6 ordered states: %w", err)
	}
	serializedBytes, err := newA2BFullIngress6SerializedBytes(expectedStates)
	if err != nil {
		return nil, fmt.Errorf("homchain: derive A2B ingress6 serialized-byte profile: %w", err)
	}
	keyProfile := newA2BRefreshKeyProfile(params, specialB0, firstRaw, suffix.refresh.profile.dft.ctsLiteral)
	if !reflect.DeepEqual(keyProfile.All(), suffix.keyProfile.All()) || keyProfile.digest != suffix.keyProfile.digest {
		return nil, fmt.Errorf("homchain: A2B ingress6 prefix changes the accepted suffix key graph")
	}
	_, firstSTCPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", firstSTC.Matrices)
	if err != nil {
		return nil, err
	}
	_, sharedCTSPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", suffix.refresh.cts.Matrices)
	if err != nil {
		return nil, err
	}
	_, secondSTCPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("second-stc", suffix.secondSTC.Matrices)
	if err != nil {
		return nil, err
	}
	admissionDigest := digestString(fmt.Sprintf(
		"%s|params=%s|source=%s|range=%s|origin=%s",
		a2bFullIngress6AdmissionDigestSchema, parameterDigest, source, ranges.digest, A2BFullIngress6TrustedDeclaredOrigin,
	))
	profile := A2BFullIngress6Profile{
		fidelity:   A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure,
		schedule:   A2BFullIngress6SerialLowThenHigh,
		inputLevel: 6, outputLevel: 5, inputScale: inputScale,
		firstSTCFactorOutputLevels: factorLevels,
		source:                     source, trustedOriginAssumption: A2BFullIngress6TrustedDeclaredOrigin,
		rangeDigest: ranges.digest, parameterDigest: parameterDigest, admissionDigest: admissionDigest,
		suffixProfileDigest: suffix.profile.digest, keyProfileDigest: keyProfile.digest,
		specialB0CompiledDigest: specialDigest, maskPayloadDigest: sha256Hex(maskBytes),
		firstSTCRawMatrixDigest: firstRawDigest, firstSTCExecutionMatrixDigest: firstExecutionDigest,
		sharedCTSExecutionMatrixDigest: suffix.profile.sharedCTSDigest,
		firstSTCEncodedPayloadDigest:   firstSTCPayloadDigest,
		sharedCTSEncodedPayloadDigest:  sharedCTSPayloadDigest,
		secondSTCEncodedPayloadDigest:  secondSTCPayloadDigest,
		operationCounts: A2BFullIngress6OperationCounts{
			SpecialB0Transforms: 1, MaskMulRescales: 2, FirstSTCFactors: 2, FirstSTCRescales: 2,
			GuardedScaleDowns: 2, DenseModUps: 2, CTSFactors: 6, RefreshInvocations: 2,
			KernelInvocations: 2, IDScaleMulRescales: 1, AlignmentDrops: 2, Subtractions: 3,
			SecondSTCFactors: 2, SecondSTCRescales: 2, SharedCTSUses: 2,
		},
		expectedStates: expectedStates, serializedBytes: serializedBytes,
		levelLedger: a2bFullIngress6LevelLedger,
	}
	profile.digest = digestA2BFullIngress6Profile(profile)
	circuit := &A2BFullIngress6Circuit{
		params: params, suffix: suffix, specialSource: specialSource, specialB0: specialB0,
		lowMask: lowMask, firstSTC: firstSTC, firstSTCRaw: firstRaw, firstSTCExec: firstExecution,
		ranges: ranges, profile: profile, keyProfile: keyProfile,
	}
	circuit.graph, err = captureA2BFullIngress6CircuitGraph(circuit)
	if err != nil {
		return nil, err
	}
	return circuit, nil
}

func (c *A2BFullIngress6Circuit) Profile() A2BFullIngress6Profile {
	if c == nil {
		return A2BFullIngress6Profile{}
	}
	result := c.profile
	result.firstSTCFactorOutputLevels = c.profile.FirstSTCFactorOutputLevels()
	result.expectedStates = c.profile.ExpectedStates()
	result.serializedBytes = c.profile.ExpectedSerializedBytes()
	return result
}

func (c *A2BFullIngress6Circuit) RequiredKeyProfile() A2BRefreshKeyProfile {
	if c == nil {
		return A2BRefreshKeyProfile{}
	}
	return cloneA2BRefreshKeyProfile(c.keyProfile)
}

// BindInput admits only an exact L6/S35 arithmetic-root ciphertext under the
// circuit's closed producer and full-ring range certificate. The declared
// parameter origin is trusted protocol metadata; ciphertexts do not carry a
// cryptographically verifiable Q-chain or secret-key identity.
func (c *A2BFullIngress6Circuit) BindInput(
	ciphertext *rlwe.Ciphertext,
	declaredSource ckks.Parameters,
) (A2BFullIngress6Input, error) {
	if err := c.validate(); err != nil {
		return A2BFullIngress6Input{}, err
	}
	if err := c.graph.validate(); err != nil {
		return A2BFullIngress6Input{}, err
	}
	declaredBytes, err := declaredSource.MarshalBinary()
	if err != nil {
		return A2BFullIngress6Input{}, fmt.Errorf("homchain: marshal A2B ingress6 declared parameters: %w", err)
	}
	if !c.params.Equal(&declaredSource) || sha256Hex(declaredBytes) != c.profile.parameterDigest {
		return A2BFullIngress6Input{}, fmt.Errorf("homchain: A2B ingress6 declared parameter origin does not match the sealed profile")
	}
	if err = requireA2BFullIngress6State("admission", ciphertext, 6, c.params); err != nil {
		return A2BFullIngress6Input{}, err
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return A2BFullIngress6Input{}, fmt.Errorf("homchain: marshal A2B ingress6 input payload: %w", err)
	}
	payloadDigest := sha256Hex(payload)
	owned := ciphertext.CopyNew()
	bindingDigest := digestString(fmt.Sprintf(
		"%s|path=%s|params=%s|source=%s|range=%s|admission=%s|payload=%s",
		a2bFullIngress6InputBindingSchema, c.profile.digest, c.profile.parameterDigest,
		c.profile.source, c.profile.rangeDigest, c.profile.admissionDigest, payloadDigest,
	))
	return A2BFullIngress6Input{
		ciphertext: owned, pathDigest: c.profile.digest, parameterDigest: c.profile.parameterDigest,
		producerSource: c.profile.source, rangeDigest: c.profile.rangeDigest,
		admissionDigest: c.profile.admissionDigest, payloadDigest: payloadDigest, bindingDigest: bindingDigest,
	}, nil
}

func captureA2BFullIngress6CircuitGraph(c *A2BFullIngress6Circuit) (a2bFullIngress6CircuitGraph, error) {
	if err := c.validate(); err != nil {
		return a2bFullIngress6CircuitGraph{}, err
	}
	firstSTCDigests, firstSTCGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", c.firstSTC.Matrices)
	if err != nil {
		return a2bFullIngress6CircuitGraph{}, err
	}
	sharedCTSDigests, sharedCTSGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", c.suffix.refresh.cts.Matrices)
	if err != nil {
		return a2bFullIngress6CircuitGraph{}, err
	}
	secondSTCDigests, secondSTCGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("second-stc", c.suffix.secondSTC.Matrices)
	if err != nil {
		return a2bFullIngress6CircuitGraph{}, err
	}
	if firstSTCGroupDigest != c.profile.firstSTCEncodedPayloadDigest ||
		sharedCTSGroupDigest != c.profile.sharedCTSEncodedPayloadDigest ||
		secondSTCGroupDigest != c.profile.secondSTCEncodedPayloadDigest {
		return a2bFullIngress6CircuitGraph{}, fmt.Errorf("homchain: A2B ingress6 encoded payload differs from the public profile")
	}
	result := a2bFullIngress6CircuitGraph{
		circuit: c, suffix: c.suffix,
		specialLow:  a2bRefreshLinearIdentity(c.specialB0.Low),
		specialHigh: a2bRefreshLinearIdentity(c.specialB0.High),
		mask:        c.lowMask, maskSeal: c.lowMask.CopyNew(),
		firstSTCPayloadDigests:  append([]string(nil), firstSTCDigests...),
		sharedCTSPayloadDigests: append([]string(nil), sharedCTSDigests...),
		secondSTCPayloadDigests: append([]string(nil), secondSTCDigests...),
		firstSTCPayloadDigest:   firstSTCGroupDigest,
		sharedCTSPayloadDigest:  sharedCTSGroupDigest,
		secondSTCPayloadDigest:  secondSTCGroupDigest,
		profileDigest:           c.profile.digest,
		keyDigest:               c.keyProfile.digest,
	}
	for _, factor := range c.firstSTC.Matrices {
		result.firstSTCFactors = append(result.firstSTCFactors, a2bRefreshLinearIdentity(factor))
	}
	for _, factor := range c.suffix.refresh.cts.Matrices {
		result.sharedCTSFactors = append(result.sharedCTSFactors, a2bRefreshLinearIdentity(factor))
	}
	for _, factor := range c.suffix.secondSTC.Matrices {
		result.secondSTCFactors = append(result.secondSTCFactors, a2bRefreshLinearIdentity(factor))
	}
	if result.specialLow == 0 || result.specialHigh == 0 || len(result.firstSTCFactors) != 2 ||
		len(result.sharedCTSFactors) != 3 || len(result.secondSTCFactors) != 2 {
		return a2bFullIngress6CircuitGraph{}, fmt.Errorf("homchain: A2B ingress6 circuit graph is incomplete")
	}
	return result, nil
}

func (g a2bFullIngress6CircuitGraph) validate() error {
	c := g.circuit
	if len(g.firstSTCFactors) != 2 || len(g.sharedCTSFactors) != 3 || len(g.secondSTCFactors) != 2 ||
		len(g.firstSTCPayloadDigests) != 2 || len(g.sharedCTSPayloadDigests) != 3 || len(g.secondSTCPayloadDigests) != 2 {
		return fmt.Errorf("homchain: A2B ingress6 evaluator graph factor seals pointers=%d/%d/%d payloads=%d/%d/%d, want 2/3/2",
			len(g.firstSTCFactors), len(g.sharedCTSFactors), len(g.secondSTCFactors),
			len(g.firstSTCPayloadDigests), len(g.sharedCTSPayloadDigests), len(g.secondSTCPayloadDigests))
	}
	if c != nil {
		cached := c.graph
		if len(cached.firstSTCFactors) != 2 || len(cached.sharedCTSFactors) != 3 || len(cached.secondSTCFactors) != 2 ||
			len(cached.firstSTCPayloadDigests) != 2 || len(cached.sharedCTSPayloadDigests) != 3 || len(cached.secondSTCPayloadDigests) != 2 ||
			cached.circuit != g.circuit || cached.suffix != g.suffix ||
			cached.specialLow != g.specialLow || cached.specialHigh != g.specialHigh ||
			cached.mask != g.mask || cached.maskSeal != g.maskSeal ||
			cached.firstSTCPayloadDigest != g.firstSTCPayloadDigest ||
			cached.sharedCTSPayloadDigest != g.sharedCTSPayloadDigest ||
			cached.secondSTCPayloadDigest != g.secondSTCPayloadDigest ||
			cached.profileDigest != g.profileDigest || cached.keyDigest != g.keyDigest ||
			!reflect.DeepEqual(cached.firstSTCFactors, g.firstSTCFactors) ||
			!reflect.DeepEqual(cached.sharedCTSFactors, g.sharedCTSFactors) ||
			!reflect.DeepEqual(cached.secondSTCFactors, g.secondSTCFactors) ||
			!reflect.DeepEqual(cached.firstSTCPayloadDigests, g.firstSTCPayloadDigests) ||
			!reflect.DeepEqual(cached.sharedCTSPayloadDigests, g.sharedCTSPayloadDigests) ||
			!reflect.DeepEqual(cached.secondSTCPayloadDigests, g.secondSTCPayloadDigests) {
			return fmt.Errorf("homchain: A2B ingress6 evaluator graph seal diverged from the circuit graph cache")
		}
	}
	if c == nil || c.suffix != g.suffix || c.lowMask != g.mask || !c.lowMask.Equal(g.maskSeal) ||
		c.profile.digest != g.profileDigest || c.keyProfile.digest != g.keyDigest ||
		a2bRefreshLinearIdentity(c.specialB0.Low) != g.specialLow ||
		a2bRefreshLinearIdentity(c.specialB0.High) != g.specialHigh {
		return fmt.Errorf("homchain: A2B ingress6 circuit object graph changed")
	}
	firstSTCDigests, firstSTCGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", c.firstSTC.Matrices)
	if err != nil {
		return err
	}
	sharedCTSDigests, sharedCTSGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", c.suffix.refresh.cts.Matrices)
	if err != nil {
		return err
	}
	secondSTCDigests, secondSTCGroupDigest, err := digestA2BFullIngress6EncodedFactorGroup("second-stc", c.suffix.secondSTC.Matrices)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(firstSTCDigests, g.firstSTCPayloadDigests) ||
		!reflect.DeepEqual(sharedCTSDigests, g.sharedCTSPayloadDigests) ||
		!reflect.DeepEqual(secondSTCDigests, g.secondSTCPayloadDigests) ||
		firstSTCGroupDigest != g.firstSTCPayloadDigest || sharedCTSGroupDigest != g.sharedCTSPayloadDigest ||
		secondSTCGroupDigest != g.secondSTCPayloadDigest ||
		firstSTCGroupDigest != c.profile.firstSTCEncodedPayloadDigest ||
		sharedCTSGroupDigest != c.profile.sharedCTSEncodedPayloadDigest ||
		secondSTCGroupDigest != c.profile.secondSTCEncodedPayloadDigest {
		return fmt.Errorf("homchain: A2B ingress6 encoded transformation payload changed")
	}
	if err := c.validate(); err != nil {
		return err
	}
	for index, pointer := range g.firstSTCFactors {
		if index >= len(c.firstSTC.Matrices) || a2bRefreshLinearIdentity(c.firstSTC.Matrices[index]) != pointer {
			return fmt.Errorf("homchain: A2B ingress6 first STC factor %d changed", index)
		}
	}
	for index, pointer := range g.sharedCTSFactors {
		if index >= len(c.suffix.refresh.cts.Matrices) || a2bRefreshLinearIdentity(c.suffix.refresh.cts.Matrices[index]) != pointer {
			return fmt.Errorf("homchain: A2B ingress6 shared CTS factor %d changed", index)
		}
	}
	for index, pointer := range g.secondSTCFactors {
		if index >= len(c.suffix.secondSTC.Matrices) || a2bRefreshLinearIdentity(c.suffix.secondSTC.Matrices[index]) != pointer {
			return fmt.Errorf("homchain: A2B ingress6 second STC factor %d changed", index)
		}
	}
	return nil
}

func (c *A2BFullIngress6Circuit) BindEvaluator(source *bootstrapping.Evaluator) (*A2BFullIngress6Evaluator, error) {
	if c == nil || source == nil {
		return nil, fmt.Errorf("homchain: nil A2B ingress6 circuit or evaluator")
	}
	if err := c.graph.validate(); err != nil {
		return nil, err
	}
	suffix, err := c.suffix.BindEvaluator(source)
	if err != nil {
		return nil, err
	}
	return &A2BFullIngress6Evaluator{circuit: c, suffix: suffix, graph: c.graph}, nil
}

func (e *A2BFullIngress6Evaluator) runtimeKeyGraph() ([]uint64, bool, error) {
	if e == nil || e.circuit == nil || e.suffix == nil || e.suffix.keySet == nil {
		return nil, false, fmt.Errorf("homchain: nil A2B ingress6 runtime key graph")
	}
	relinearizationKey, err := e.suffix.keySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey != e.suffix.relinearizationKey {
		return nil, false, fmt.Errorf("homchain: A2B ingress6 runtime relinearization key identity changed: %v", err)
	}
	elements := make([]uint64, 0, len(e.suffix.galoisKeys))
	for element, expected := range e.suffix.galoisKeys {
		key, keyErr := e.suffix.keySet.GetGaloisKey(element)
		if keyErr != nil || key == nil || key != expected {
			return nil, false, fmt.Errorf("homchain: A2B ingress6 runtime Galois key %d identity changed: %v", element, keyErr)
		}
		elements = append(elements, element)
	}
	sort.Slice(elements, func(i, j int) bool { return elements[i] < elements[j] })
	if !reflect.DeepEqual(elements, e.circuit.keyProfile.all) {
		return nil, false, fmt.Errorf("homchain: A2B ingress6 runtime Galois graph=%v, sealed=%v", elements, e.circuit.keyProfile.all)
	}
	return elements, true, nil
}

func (e *A2BFullIngress6Evaluator) EvaluateNew(input A2BFullIngress6Input) (A2BFullResult, A2BFullIngress6Trace, error) {
	trace := A2BFullIngress6Trace{}
	if e == nil || e.circuit == nil || e.suffix == nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: nil A2B ingress6 evaluator")
	}
	trace.profileDigest = e.circuit.profile.digest
	trace.rangeDigest = e.circuit.profile.rangeDigest
	trace.admissionDigest = e.circuit.profile.admissionDigest
	trace.inputBindingDigest = input.bindingDigest
	if err := e.circuit.validateInput(input); err != nil {
		trace.failureStage = A2BFullIngress6StageAdmission
		return A2BFullResult{}, trace, err
	}
	if err := e.graph.validate(); err != nil {
		trace.failureStage = A2BFullIngress6StageKeyPreflight
		return A2BFullResult{}, trace, err
	}
	preflight, err := e.suffix.preflight()
	trace.keyPreflight = preflight
	if err != nil {
		trace.failureStage = A2BFullIngress6StageKeyPreflight
		return A2BFullResult{}, trace, err
	}
	runtimeGalois, relinearizationMatched, err := e.runtimeKeyGraph()
	if err != nil {
		trace.failureStage = A2BFullIngress6StageKeyPreflight
		return A2BFullResult{}, trace, err
	}
	trace.runtimeGalois = runtimeGalois
	trace.relinearizationKeyMatched = relinearizationMatched
	trace.retainedCiphertexts = make(map[A2BFullIngress6Stage]*rlwe.Ciphertext, len(e.circuit.profile.expectedStates))
	appendState := func(stage A2BFullIngress6Stage, ciphertext *rlwe.Ciphertext) error {
		if _, exists := trace.retainedCiphertexts[stage]; exists {
			return fmt.Errorf("homchain: A2B ingress6 runtime stage %s was retained more than once", stage)
		}
		state, stateErr := snapshotA2BFullIngress6State(stage, ciphertext)
		if stateErr == nil {
			trace.states = append(trace.states, state)
			trace.retainedCiphertexts[stage] = ciphertext.CopyNew()
		}
		return stateErr
	}
	if err = appendState(A2BFullIngress6StageInput, input.ciphertext); err != nil {
		return A2BFullResult{}, trace, err
	}
	inputBefore := input.ciphertext.CopyNew()

	halves, err := e.suffix.refresh.triangle.ZToCNew(input.ciphertext.CopyNew(), e.circuit.specialB0)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 special-b0 Z-To-C: %w", err)
	}
	trace.operationCounts.SpecialB0Transforms++
	if err = validateCiphertextPairState("A2B ingress6 special-b0", halves); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullIngress6State("special low", halves[0], 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullIngress6State("special high", halves[1], 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	specialLow, specialHigh := halves[0].CopyNew(), halves[1].CopyNew()
	if err = appendState(A2BFullIngress6StageSpecialLow, halves[0]); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageSpecialHigh, halves[1]); err != nil {
		return A2BFullResult{}, trace, err
	}

	iter0Masked, err := e.suffix.refresh.bootstrap.Evaluator.MulNew(halves[0], e.circuit.lowMask)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter0 mask multiply: %w", err)
	}
	if err = e.suffix.refresh.bootstrap.Evaluator.Rescale(iter0Masked, iter0Masked); err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter0 mask rescale: %w", err)
	}
	trace.operationCounts.MaskMulRescales++
	if err = requireA2BFullIngress6State("iter0 mask", iter0Masked, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter0Mask, iter0Masked); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter0MaskedSaved := iter0Masked.CopyNew()

	iter0Refreshed, iter0ErrScale, iter0ErrLog2, err := e.refreshIter0(iter0Masked, &trace, appendState)
	if err != nil {
		return A2BFullResult{}, trace, err
	}
	trace.iter0ErrScale, trace.iter0ErrLog2 = iter0ErrScale, iter0ErrLog2
	iter0, err := e.suffix.kernel0.EvaluateNew(iter0Refreshed)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter0 Gao kernel: %w", err)
	}
	trace.operationCounts.KernelInvocations++
	trace.iter0Kernel = iter0.Provenance()
	id0, msb0 := iter0.IDCiphertext(), iter0.MSBCiphertext()
	if err = requireA2BFullIngress6State("iter0 ID", id0, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullIngress6State("iter0 MSB", msb0, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter0ID, id0); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter0MSB, msb0); err != nil {
		return A2BFullResult{}, trace, err
	}
	id0Saved := id0.CopyNew()
	id0Over16, err := e.suffix.refresh.bootstrap.Evaluator.MulNew(id0, e.circuit.suffix.idScale)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 ID0/16 multiply: %w", err)
	}
	if err = e.suffix.refresh.bootstrap.Evaluator.Rescale(id0Over16, id0Over16); err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 ID0/16 rescale: %w", err)
	}
	trace.operationCounts.IDScaleMulRescales++
	if err = requireA2BFullIngress6State("ID0/16", id0Over16, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageID0Over16, id0Over16); err != nil {
		return A2BFullResult{}, trace, err
	}
	id0Over16Saved := id0Over16.CopyNew()

	highAligned := specialHigh.CopyNew()
	e.suffix.refresh.bootstrap.Evaluator.DropLevel(highAligned, highAligned.Level()-4)
	trace.operationCounts.AlignmentDrops++
	if err = requireA2BFullIngress6State("high aligned", highAligned, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageHighAligned, highAligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	highAlignedSaved := highAligned.CopyNew()
	highUpdated, err := e.suffix.refresh.bootstrap.Evaluator.SubNew(highAligned, id0Over16)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 high update: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullIngress6State("high updated", highUpdated, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageHighUpdated, highUpdated); err != nil {
		return A2BFullResult{}, trace, err
	}
	highUpdatedSaved := highUpdated.CopyNew()

	lowAligned := specialLow.CopyNew()
	if err = requireA2BFullIngress6State("low aligned", lowAligned, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageLowAligned, lowAligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	lowAlignedSaved := lowAligned.CopyNew()
	lowSelfRemoved, err := e.suffix.refresh.bootstrap.Evaluator.SubNew(lowAligned, id0)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 remove iter0 ID: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullIngress6State("low self removed", lowSelfRemoved, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageLowSelfRemoved, lowSelfRemoved); err != nil {
		return A2BFullResult{}, trace, err
	}

	iter1Masked, err := e.suffix.refresh.bootstrap.Evaluator.MulNew(highUpdated, e.circuit.suffix.iter1Mask)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter1 mask multiply: %w", err)
	}
	if err = e.suffix.refresh.bootstrap.Evaluator.Rescale(iter1Masked, iter1Masked); err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter1 mask rescale: %w", err)
	}
	trace.operationCounts.MaskMulRescales++
	if err = requireA2BFullIngress6State("iter1 mask", iter1Masked, 3, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter1Mask, iter1Masked); err != nil {
		return A2BFullResult{}, trace, err
	}
	iter1MaskedSaved := iter1Masked.CopyNew()
	iter1Refreshed, iter1ErrScale, iter1ErrLog2, err := e.refreshIter1(iter1Masked, &trace, appendState)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter1 refresh: %w", err)
	}
	trace.iter1ErrScale, trace.iter1ErrLog2 = iter1ErrScale, iter1ErrLog2
	iter1, err := e.suffix.kernel1.EvaluateNew(iter1Refreshed)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 iter1 Gao kernel: %w", err)
	}
	trace.operationCounts.KernelInvocations++
	trace.iter1Kernel = iter1.Provenance()
	id1, msb1 := iter1.IDCiphertext(), iter1.MSBCiphertext()
	if err = requireA2BFullIngress6State("iter1 ID", id1, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = requireA2BFullIngress6State("iter1 MSB", msb1, 5, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter1ID, id1); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageIter1MSB, msb1); err != nil {
		return A2BFullResult{}, trace, err
	}
	id1Saved := id1.CopyNew()
	id1Aligned := id1.CopyNew()
	e.suffix.refresh.bootstrap.Evaluator.DropLevel(id1Aligned, id1Aligned.Level()-4)
	trace.operationCounts.AlignmentDrops++
	if err = requireA2BFullIngress6State("ID1 aligned", id1Aligned, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageID1Aligned, id1Aligned); err != nil {
		return A2BFullResult{}, trace, err
	}
	highSelfRemoved, err := e.suffix.refresh.bootstrap.Evaluator.SubNew(highUpdated, id1Aligned)
	if err != nil {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 remove iter1 ID: %w", err)
	}
	trace.operationCounts.Subtractions++
	if err = requireA2BFullIngress6State("high self removed", highSelfRemoved, 4, e.circuit.params); err != nil {
		return A2BFullResult{}, trace, err
	}
	if err = appendState(A2BFullIngress6StageHighSelfRemoved, highSelfRemoved); err != nil {
		return A2BFullResult{}, trace, err
	}

	if !input.ciphertext.Equal(inputBefore) || !specialLow.Equal(halves[0]) || !specialHigh.Equal(halves[1]) ||
		!iter0Masked.Equal(iter0MaskedSaved) || !id0.Equal(id0Saved) || !id0Over16.Equal(id0Over16Saved) ||
		!highAligned.Equal(highAlignedSaved) || !highUpdated.Equal(highUpdatedSaved) ||
		!lowAligned.Equal(lowAlignedSaved) || !iter1Masked.Equal(iter1MaskedSaved) || !id1.Equal(id1Saved) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 mutated an admitted input or saved serial core")
	}
	if trace.operationCounts != e.circuit.profile.operationCounts {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 runtime operation ledger=%+v, sealed=%+v", trace.operationCounts, e.circuit.profile.operationCounts)
	}
	if !reflect.DeepEqual(trace.states, e.circuit.profile.expectedStates) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 runtime ordered states differ from the sealed ledger")
	}
	trace.serializedBytes, err = measureA2BFullIngress6RuntimeSerializedBytes(trace.states, trace.retainedCiphertexts)
	if err != nil {
		return A2BFullResult{}, trace, err
	}
	if !reflect.DeepEqual(trace.serializedBytes, e.circuit.profile.serializedBytes) {
		return A2BFullResult{}, trace, fmt.Errorf("homchain: A2B ingress6 runtime serialized-byte ledger differs from the sealed profile")
	}
	return A2BFullResult{
		lowMSB: msb0, highMSB: msb1, specialLow: specialLow, specialHigh: specialHigh,
		iter0Refreshed: iter0Refreshed, id0: id0, id0Over16: id0Over16,
		highUpdated: highUpdated, lowSelfRemoved: lowSelfRemoved,
		iter1Masked: iter1Masked, iter1Refreshed: iter1Refreshed, id1: id1,
		highSelfRemoved: highSelfRemoved,
	}, trace, nil
}

func (e *A2BFullIngress6Evaluator) refreshIter0(
	input *rlwe.Ciphertext,
	trace *A2BFullIngress6Trace,
	appendState func(A2BFullIngress6Stage, *rlwe.Ciphertext) error,
) (*rlwe.Ciphertext, ExactScaleSnapshot, float64, error) {
	current := input
	stages := []A2BFullIngress6Stage{A2BFullIngress6StageIter0STCFactor0, A2BFullIngress6StageIter0STCFactor1}
	for index, factor := range e.circuit.firstSTC.Matrices {
		next, err := e.suffix.refresh.bootstrap.DFTEvaluator.LTEvaluator.EvaluateNew(current, factor)
		if err != nil {
			return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter0 STC factor %d: %w", index, err)
		}
		if err = e.suffix.refresh.bootstrap.Evaluator.Rescale(next, next); err != nil {
			return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter0 STC factor %d rescale: %w", index, err)
		}
		trace.operationCounts.FirstSTCFactors++
		trace.operationCounts.FirstSTCRescales++
		if err = requireA2BFullIngress6State("iter0 STC factor", next, e.circuit.profile.firstSTCFactorOutputLevels[index], e.circuit.params); err != nil {
			return nil, ExactScaleSnapshot{}, 0, err
		}
		if err = appendState(stages[index], next); err != nil {
			return nil, ExactScaleSnapshot{}, 0, err
		}
		current = next
	}
	stcSaved := current.CopyNew()
	scaledDown, errScale, err := e.suffix.refresh.bootstrap.ScaleDown(current.CopyNew())
	if err != nil || errScale == nil {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter0 guarded ScaleDown: %w", err)
	}
	trace.operationCounts.GuardedScaleDowns++
	trace.operationCounts.RefreshInvocations++
	if !current.Equal(stcSaved) {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 ScaleDown mutated the first STC core")
	}
	errLog2 := errScale.Log2()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 ScaleDown |log2(errScale)|=%g exceeds 1e-6", math.Abs(errLog2))
	}
	errSnapshot, err := NewExactScaleSnapshot(*errScale)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	if err = requireA2BFullIngress6State("iter0 ScaleDown", scaledDown, 0, e.circuit.params); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	targetScale := rlwe.NewScale(e.circuit.params.Q()[0]).Div(rlwe.NewScale(e.suffix.refresh.bootstrap.Mod1Parameters.MessageRatio()))
	if !scaledDown.Scale.Div(targetScale).Equal(*errScale) {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 ScaleDown raw scale changed")
	}
	if err = appendState(A2BFullIngress6StageIter0ScaleDown, scaledDown); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	preModUpScale, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	requested := e.suffix.refresh.bootstrap.Mod1Parameters.ScalingFactor().Float64() / e.suffix.refresh.bootstrap.Mod1Parameters.MessageRatio()
	if requested/scaledDown.Scale.Float64() > 1 {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 ModUp would relabel the raw scale")
	}
	raised, err := e.suffix.refresh.bootstrap.ModUp(scaledDown)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter0 ModUp: %w", err)
	}
	trace.operationCounts.DenseModUps++
	if err = requireA2BFullIngress6State("iter0 ModUp", raised, 20, e.circuit.params); err != nil || !preModUpScale.EqualScale(raised.Scale) {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter0 ModUp level/scale changed: %w", err)
	}
	if err = appendState(A2BFullIngress6StageIter0ModUp, raised); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	realOutput, imaginaryOutput, err := e.suffix.refresh.bootstrap.DFTEvaluator.CoeffsToSlotsNew(raised, e.circuit.suffix.refresh.cts)
	if err != nil || imaginaryOutput == nil || imaginaryOutput == realOutput {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter0 shared CTS failed: %w", err)
	}
	trace.operationCounts.CTSFactors += len(e.circuit.suffix.refresh.cts.Matrices)
	trace.operationCounts.SharedCTSUses++
	if err = requireA2BFullIngress6State("iter0 CTS", realOutput, 17, e.circuit.params); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	if err = appendState(A2BFullIngress6StageIter0CTS, realOutput); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	return realOutput, errSnapshot, errLog2, nil
}

func (e *A2BFullIngress6Evaluator) refreshIter1(
	input *rlwe.Ciphertext,
	trace *A2BFullIngress6Trace,
	appendState func(A2BFullIngress6Stage, *rlwe.Ciphertext) error,
) (*rlwe.Ciphertext, ExactScaleSnapshot, float64, error) {
	if input == nil || input.MetaData == nil || input.Level() != 3 || input.Degree() != 1 ||
		!b2aExactScaleEqual(input.Scale, e.circuit.params.DefaultScale()) || e.circuit.suffix.secondSTC.LevelQ != 3 {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter1 STC ingress is not sealed L3/S35")
	}
	stc, err := e.suffix.refresh.bootstrap.DFTEvaluator.SlotsToCoeffsNew(input, nil, e.circuit.suffix.secondSTC)
	if err != nil {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter1 Slots-To-Coeffs: %w", err)
	}
	trace.operationCounts.SecondSTCFactors += len(e.circuit.suffix.secondSTC.Matrices)
	trace.operationCounts.SecondSTCRescales += len(e.circuit.suffix.secondSTC.Matrices)
	if err = requireA2BFullIngress6State("iter1 STC", stc, 1, e.circuit.params); err != nil {
		return nil, ExactScaleSnapshot{}, 0, err
	}
	if err = appendState(A2BFullIngress6StageIter1STC, stc); err != nil {
		return nil, ExactScaleSnapshot{}, 0, err
	}
	stcSaved := stc.CopyNew()
	scaledDown, errScale, err := e.suffix.refresh.bootstrap.ScaleDown(stc.CopyNew())
	if err != nil || errScale == nil {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter1 guarded ScaleDown: %w", err)
	}
	trace.operationCounts.GuardedScaleDowns++
	trace.operationCounts.RefreshInvocations++
	if !stc.Equal(stcSaved) {
		return nil, ExactScaleSnapshot{}, 0, fmt.Errorf("homchain: A2B ingress6 iter1 ScaleDown mutated the STC core")
	}
	errLog2 := errScale.Log2()
	if math.IsNaN(errLog2) || math.IsInf(errLog2, 0) || math.Abs(errLog2) > 1e-6 {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 ScaleDown |log2(errScale)|=%g exceeds 1e-6", math.Abs(errLog2))
	}
	errSnapshot, err := NewExactScaleSnapshot(*errScale)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	if err = requireA2BFullIngress6State("iter1 ScaleDown", scaledDown, 0, e.circuit.params); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	targetScale := rlwe.NewScale(e.circuit.params.Q()[0]).Div(rlwe.NewScale(e.suffix.refresh.bootstrap.Mod1Parameters.MessageRatio()))
	if !scaledDown.Scale.Div(targetScale).Equal(*errScale) {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 ScaleDown raw scale changed")
	}
	if err = appendState(A2BFullIngress6StageIter1ScaleDown, scaledDown); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	preModUpScale, err := NewExactScaleSnapshot(scaledDown.Scale)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	requested := e.suffix.refresh.bootstrap.Mod1Parameters.ScalingFactor().Float64() / e.suffix.refresh.bootstrap.Mod1Parameters.MessageRatio()
	if requested/scaledDown.Scale.Float64() > 1 {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 ModUp would relabel the raw scale")
	}
	raised, err := e.suffix.refresh.bootstrap.ModUp(scaledDown)
	if err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 ModUp: %w", err)
	}
	trace.operationCounts.DenseModUps++
	if err = requireA2BFullIngress6State("iter1 ModUp", raised, 20, e.circuit.params); err != nil || !preModUpScale.EqualScale(raised.Scale) {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 ModUp level/scale changed: %w", err)
	}
	if err = appendState(A2BFullIngress6StageIter1ModUp, raised); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	realOutput, imaginaryOutput, err := e.suffix.refresh.bootstrap.DFTEvaluator.CoeffsToSlotsNew(raised, e.circuit.suffix.refresh.cts)
	if err != nil || imaginaryOutput == nil || imaginaryOutput == realOutput {
		return nil, ExactScaleSnapshot{}, errLog2, fmt.Errorf("homchain: A2B ingress6 iter1 shared CTS failed: %w", err)
	}
	trace.operationCounts.CTSFactors += len(e.circuit.suffix.refresh.cts.Matrices)
	trace.operationCounts.SharedCTSUses++
	if err = requireA2BFullIngress6State("iter1 CTS", realOutput, 17, e.circuit.params); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	if err = appendState(A2BFullIngress6StageIter1CTS, realOutput); err != nil {
		return nil, ExactScaleSnapshot{}, errLog2, err
	}
	return realOutput, errSnapshot, errLog2, nil
}

func snapshotA2BFullIngress6State(stage A2BFullIngress6Stage, ciphertext *rlwe.Ciphertext) (A2BFullIngress6CiphertextState, error) {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return A2BFullIngress6CiphertextState{}, fmt.Errorf("homchain: cannot snapshot nil A2B ingress6 %s ciphertext", stage)
	}
	scale, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return A2BFullIngress6CiphertextState{}, err
	}
	payload, err := ciphertext.MarshalBinary()
	if err != nil {
		return A2BFullIngress6CiphertextState{}, fmt.Errorf("homchain: marshal A2B ingress6 %s state: %w", stage, err)
	}
	return A2BFullIngress6CiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		LogDimensions: ciphertext.LogDimensions, Scale: scale, SerializedBytes: len(payload),
	}, nil
}

func newA2BFullIngress6ExpectedStates(params ckks.Parameters) ([]A2BFullIngress6CiphertextState, error) {
	stages := []A2BFullIngress6Stage{
		A2BFullIngress6StageInput,
		A2BFullIngress6StageSpecialLow, A2BFullIngress6StageSpecialHigh,
		A2BFullIngress6StageIter0Mask,
		A2BFullIngress6StageIter0STCFactor0, A2BFullIngress6StageIter0STCFactor1,
		A2BFullIngress6StageIter0ScaleDown, A2BFullIngress6StageIter0ModUp, A2BFullIngress6StageIter0CTS,
		A2BFullIngress6StageIter0ID, A2BFullIngress6StageIter0MSB,
		A2BFullIngress6StageID0Over16,
		A2BFullIngress6StageHighAligned, A2BFullIngress6StageHighUpdated,
		A2BFullIngress6StageLowAligned, A2BFullIngress6StageLowSelfRemoved,
		A2BFullIngress6StageIter1Mask,
		A2BFullIngress6StageIter1STC, A2BFullIngress6StageIter1ScaleDown,
		A2BFullIngress6StageIter1ModUp, A2BFullIngress6StageIter1CTS,
		A2BFullIngress6StageIter1ID, A2BFullIngress6StageIter1MSB,
		A2BFullIngress6StageID1Aligned, A2BFullIngress6StageHighSelfRemoved,
	}
	levels := []int{6, 5, 5, 4, 3, 2, 0, 20, 17, 5, 5, 4, 4, 4, 5, 5, 3, 1, 0, 20, 17, 5, 5, 4, 4}
	serializedBytes := []int{
		3998, 3470, 3470, 2942, 2414, 1886, 830, 11390, 9806, 3470, 3470, 2942, 2942,
		2942, 3470, 3470, 2414, 1358, 830, 11390, 9806, 3470, 3470, 2942, 2942,
	}
	if len(stages) != len(levels) || len(stages) != len(serializedBytes) {
		return nil, fmt.Errorf("homchain: A2B ingress6 state schema length mismatch")
	}
	scale, err := NewExactScaleSnapshot(params.DefaultScale())
	if err != nil {
		return nil, err
	}
	states := make([]A2BFullIngress6CiphertextState, len(stages))
	for index := range stages {
		states[index] = A2BFullIngress6CiphertextState{
			Stage: stages[index], Level: levels[index], Degree: 1,
			LogDimensions: params.LogMaxDimensions(), Scale: scale, SerializedBytes: serializedBytes[index],
		}
	}
	return states, nil
}

func newA2BFullIngress6SerializedBytes(states []A2BFullIngress6CiphertextState) (A2BFullIngress6SerializedBytes, error) {
	if len(states) != 25 {
		return A2BFullIngress6SerializedBytes{}, fmt.Errorf("homchain: A2B ingress6 serialized-byte ledger has %d states, want 25", len(states))
	}
	result := A2BFullIngress6SerializedBytes{retainedBoundaries: make([]A2BFullIngress6SerializedBoundary, len(states))}
	for index, state := range states {
		if state.Stage == "" || state.SerializedBytes <= 0 {
			return A2BFullIngress6SerializedBytes{}, fmt.Errorf("homchain: incomplete A2B ingress6 serialized state %d: %+v", index, state)
		}
		result.retainedBoundaries[index] = A2BFullIngress6SerializedBoundary{Stage: state.Stage, Bytes: state.SerializedBytes}
		switch state.Stage {
		case A2BFullIngress6StageInput:
			result.onlineInput = state.SerializedBytes
		case A2BFullIngress6StageIter0MSB:
			result.onlineLowOutput = state.SerializedBytes
		case A2BFullIngress6StageIter1MSB:
			result.onlineHighOutput = state.SerializedBytes
		}
	}
	if !result.Complete() {
		return A2BFullIngress6SerializedBytes{}, fmt.Errorf("homchain: incomplete A2B ingress6 serialized-byte profile")
	}
	return result, nil
}

func measureA2BFullIngress6RuntimeSerializedBytes(
	states []A2BFullIngress6CiphertextState,
	retained map[A2BFullIngress6Stage]*rlwe.Ciphertext,
) (A2BFullIngress6SerializedBytes, error) {
	if len(states) != 25 || len(retained) != len(states) {
		return A2BFullIngress6SerializedBytes{}, fmt.Errorf(
			"homchain: A2B ingress6 runtime serialized ledger has states/real-ciphertexts=%d/%d, want 25/25",
			len(states), len(retained),
		)
	}
	runtimeStates := append([]A2BFullIngress6CiphertextState(nil), states...)
	for index := range runtimeStates {
		ciphertext, ok := retained[runtimeStates[index].Stage]
		if !ok || ciphertext == nil {
			return A2BFullIngress6SerializedBytes{}, fmt.Errorf("homchain: A2B ingress6 runtime stage %s has no real retained ciphertext", runtimeStates[index].Stage)
		}
		payload, err := ciphertext.MarshalBinary()
		if err != nil {
			return A2BFullIngress6SerializedBytes{}, fmt.Errorf("homchain: marshal retained A2B ingress6 stage %s: %w", runtimeStates[index].Stage, err)
		}
		if len(payload) != runtimeStates[index].SerializedBytes {
			return A2BFullIngress6SerializedBytes{}, fmt.Errorf(
				"homchain: A2B ingress6 stage %s snapshot/runtime serialized bytes=%d/%d",
				runtimeStates[index].Stage, runtimeStates[index].SerializedBytes, len(payload),
			)
		}
		runtimeStates[index].SerializedBytes = len(payload)
	}
	return newA2BFullIngress6SerializedBytes(runtimeStates)
}

func (c *A2BFullIngress6Circuit) validateInput(input A2BFullIngress6Input) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := requireA2BFullIngress6State("bound input", input.ciphertext, 6, c.params); err != nil {
		return err
	}
	payload, err := input.ciphertext.MarshalBinary()
	if err != nil {
		return fmt.Errorf("homchain: remarshal A2B ingress6 bound payload: %w", err)
	}
	payloadDigest := sha256Hex(payload)
	wantBinding := digestString(fmt.Sprintf(
		"%s|path=%s|params=%s|source=%s|range=%s|admission=%s|payload=%s",
		a2bFullIngress6InputBindingSchema, c.profile.digest, c.profile.parameterDigest,
		c.profile.source, c.profile.rangeDigest, c.profile.admissionDigest, payloadDigest,
	))
	if input.pathDigest != c.profile.digest || input.parameterDigest != c.profile.parameterDigest ||
		input.producer() != c.profile.source || input.rangeDigest != c.profile.rangeDigest ||
		input.admissionDigest != c.profile.admissionDigest || input.payloadDigest != payloadDigest ||
		input.bindingDigest != wantBinding {
		return fmt.Errorf("homchain: A2B ingress6 input certificate, payload, or producer binding changed")
	}
	return nil
}

func requireA2BFullIngress6State(name string, ciphertext *rlwe.Ciphertext, level int, params ckks.Parameters) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level || ciphertext.Degree() != 1 ||
		!ciphertext.IsBatched || !ciphertext.IsNTT || ciphertext.LogDimensions != params.LogMaxDimensions() ||
		ciphertext.Slots() != params.MaxSlots() || !b2aExactScaleEqual(ciphertext.Scale, params.DefaultScale()) {
		return fmt.Errorf("homchain: A2B ingress6 %s is not exact L%d/S35/degree1/full-dense/NTT", name, level)
	}
	return nil
}

func (c *A2BFullIngress6Circuit) validate() error {
	if c == nil || c.suffix == nil || c.lowMask == nil || len(c.firstSTC.Matrices) != 2 {
		return fmt.Errorf("homchain: nil or incomplete A2B ingress6 circuit")
	}
	if err := validateA2BRefreshParameters(c.params); err != nil {
		return err
	}
	if err := c.suffix.validate(); err != nil {
		return err
	}
	if err := c.ranges.validate(); err != nil {
		return err
	}
	if err := c.profile.source.validate(); err != nil {
		return err
	}
	parameterBytes, err := c.params.MarshalBinary()
	if err != nil {
		return err
	}
	specialDigest, err := digestA2BFullIngress6CompiledPair(c.specialB0)
	if err != nil {
		return err
	}
	maskBytes, err := c.lowMask.MarshalBinary()
	if err != nil {
		return err
	}
	rawDigest := digestDFTMatrixNumericPayload(c.firstSTCRaw, c.firstSTCRaw.GenMatrices(c.params.LogN(), a2bRefreshGeneratorEncoderPrecision))
	executionDigest := digestDFTMatrixNumericPayload(c.firstSTCExec, c.firstSTCExec.GenMatrices(c.params.LogN(), a2bRefreshGeneratorEncoderPrecision))
	_, firstSTCPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("first-stc", c.firstSTC.Matrices)
	if err != nil {
		return err
	}
	_, sharedCTSPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("shared-cts", c.suffix.refresh.cts.Matrices)
	if err != nil {
		return err
	}
	_, secondSTCPayloadDigest, err := digestA2BFullIngress6EncodedFactorGroup("second-stc", c.suffix.secondSTC.Matrices)
	if err != nil {
		return err
	}
	keyProfile := newA2BRefreshKeyProfile(c.params, c.specialB0, c.firstSTCRaw, c.suffix.refresh.profile.dft.ctsLiteral)
	wantStates, err := newA2BFullIngress6ExpectedStates(c.params)
	if err != nil {
		return err
	}
	wantSerializedBytes, err := newA2BFullIngress6SerializedBytes(wantStates)
	if err != nil {
		return err
	}
	wantAdmission := digestString(fmt.Sprintf(
		"%s|params=%s|source=%s|range=%s|origin=%s",
		a2bFullIngress6AdmissionDigestSchema, sha256Hex(parameterBytes), c.profile.source,
		c.ranges.digest, A2BFullIngress6TrustedDeclaredOrigin,
	))
	if c.profile.digest != digestA2BFullIngress6Profile(c.profile) ||
		c.profile.fidelity != A2BFullFunctionalLattigoAdaptationNotSecureNotSourceSecure ||
		c.profile.schedule != A2BFullIngress6SerialLowThenHigh || c.profile.inputLevel != 6 || c.profile.outputLevel != 5 ||
		!c.profile.inputScale.EqualScale(c.params.DefaultScale()) ||
		!reflect.DeepEqual(c.profile.firstSTCFactorOutputLevels, []int{3, 2}) ||
		c.profile.trustedOriginAssumption != A2BFullIngress6TrustedDeclaredOrigin ||
		c.profile.rangeDigest != c.ranges.digest || c.profile.parameterDigest != sha256Hex(parameterBytes) ||
		c.profile.admissionDigest != wantAdmission || c.profile.suffixProfileDigest != c.suffix.profile.digest ||
		c.profile.keyProfileDigest != keyProfile.digest || c.profile.specialB0CompiledDigest != specialDigest ||
		c.profile.maskPayloadDigest != sha256Hex(maskBytes) || c.profile.firstSTCRawMatrixDigest != rawDigest ||
		c.profile.firstSTCExecutionMatrixDigest != executionDigest ||
		c.profile.sharedCTSExecutionMatrixDigest != c.suffix.profile.sharedCTSDigest ||
		c.profile.firstSTCEncodedPayloadDigest != firstSTCPayloadDigest ||
		c.profile.sharedCTSEncodedPayloadDigest != sharedCTSPayloadDigest ||
		c.profile.secondSTCEncodedPayloadDigest != secondSTCPayloadDigest ||
		c.profile.operationCounts != (A2BFullIngress6OperationCounts{
			SpecialB0Transforms: 1, MaskMulRescales: 2, FirstSTCFactors: 2, FirstSTCRescales: 2,
			GuardedScaleDowns: 2, DenseModUps: 2, CTSFactors: 6, RefreshInvocations: 2,
			KernelInvocations: 2, IDScaleMulRescales: 1, AlignmentDrops: 2, Subtractions: 3,
			SecondSTCFactors: 2, SecondSTCRescales: 2, SharedCTSUses: 2,
		}) ||
		!reflect.DeepEqual(c.profile.expectedStates, wantStates) ||
		!reflect.DeepEqual(c.profile.serializedBytes, wantSerializedBytes) ||
		c.profile.levelLedger != a2bFullIngress6LevelLedger || c.lowMask.Level() != 5 ||
		!rlwe.NewScale(c.params.Q()[5]).Equal(c.lowMask.Scale) || c.firstSTC.LevelQ != 4 ||
		c.firstSTC.Depth(true) != 2 || !reflect.DeepEqual(c.firstSTC.Levels, []int{1, 1}) ||
		!a2bRefreshLiteralEqual(c.firstSTC.MatrixLiteral, c.firstSTCExec) ||
		!reflect.DeepEqual(c.keyProfile, keyProfile) || c.keyProfile.digest != c.suffix.keyProfile.digest {
		return fmt.Errorf("homchain: A2B ingress6 sealed prefix, admission, or suffix binding changed")
	}
	return nil
}

// digestA2BFullIngress6EncodedFactorGroup seals the exact compiled payload
// evaluated online. It binds each factor's complete RLWE metadata, structural
// levels, sorted diagonal indexes, and the binary encoding of every diagonal
// polynomial. The group digest additionally binds factor order and count.
func digestA2BFullIngress6EncodedFactorGroup(
	group string,
	factors []ckkslintrans.LinearTransformation,
) (factorDigests []string, groupDigest string, err error) {
	want := 0
	switch group {
	case "first-stc", "second-stc":
		want = 2
	case "shared-cts":
		want = 3
	default:
		return nil, "", fmt.Errorf("homchain: unknown A2B ingress6 encoded factor group %q", group)
	}
	if len(factors) != want {
		return nil, "", fmt.Errorf("homchain: A2B ingress6 encoded %s factors=%d, want %d", group, len(factors), want)
	}

	factorDigests = make([]string, len(factors))
	for factorIndex, factor := range factors {
		if factor.MetaData == nil || len(factor.Vec) == 0 {
			return nil, "", fmt.Errorf("homchain: incomplete A2B ingress6 encoded %s factor %d", group, factorIndex)
		}
		metadata, marshalErr := factor.MetaData.MarshalBinary()
		if marshalErr != nil {
			return nil, "", fmt.Errorf("homchain: marshal A2B ingress6 encoded %s factor %d metadata: %w", group, factorIndex, marshalErr)
		}
		indexes := make([]int, 0, len(factor.Vec))
		for diagonal := range factor.Vec {
			indexes = append(indexes, diagonal)
		}
		sort.Ints(indexes)
		var canonical strings.Builder
		fmt.Fprintf(&canonical,
			"%s|group=%s|factor=%d|level-q=%d|level-p=%d|bsgs=%d|n1=%d|metadata=%s|diagonals=%v",
			a2bFullIngress6EncodedFactorSchema, group, factorIndex, factor.LevelQ, factor.LevelP,
			factor.LogBabyStepGiantStepRatio, factor.N1, sha256Hex(metadata), indexes)
		for _, diagonal := range indexes {
			payload, marshalErr := factor.Vec[diagonal].MarshalBinary()
			if marshalErr != nil {
				return nil, "", fmt.Errorf("homchain: marshal A2B ingress6 encoded %s factor %d diagonal %d: %w",
					group, factorIndex, diagonal, marshalErr)
			}
			fmt.Fprintf(&canonical, "|diagonal=%d/payload=%s", diagonal, sha256Hex(payload))
		}
		factorDigests[factorIndex] = digestString(canonical.String())
	}
	return factorDigests, digestString(fmt.Sprintf(
		"%s|group=%s|count=%d|factors=%v",
		a2bFullIngress6EncodedGroupSchema, group, len(factorDigests), factorDigests,
	)), nil
}

func digestA2BFullIngress6CompiledPair(pair CompiledPair) (string, error) {
	var canonical strings.Builder
	canonical.WriteString("a2b-full-ingress6-special-b0-compiled-v1")
	for index, transformation := range []ckkslintrans.LinearTransformation{pair.Low, pair.High} {
		if transformation.MetaData == nil || transformation.Vec == nil {
			return "", fmt.Errorf("homchain: incomplete A2B ingress6 compiled transform %d", index)
		}
		scale, err := NewExactScaleSnapshot(transformation.Scale)
		if err != nil {
			return "", err
		}
		indexes := make([]int, 0, len(transformation.Vec))
		for diagonal := range transformation.Vec {
			indexes = append(indexes, diagonal)
		}
		sort.Ints(indexes)
		fmt.Fprintf(&canonical, "|transform=%d/Q%d/P%d/scale=%s/dimensions=%d,%d/bsgs=%d/n1=%d/diagonals=%v",
			index, transformation.LevelQ, transformation.LevelP, scale.canonicalString(),
			transformation.LogDimensions.Rows, transformation.LogDimensions.Cols,
			transformation.LogBabyStepGiantStepRatio, transformation.N1, indexes)
		for _, diagonal := range indexes {
			payload, marshalErr := transformation.Vec[diagonal].MarshalBinary()
			if marshalErr != nil {
				return "", fmt.Errorf("homchain: marshal A2B ingress6 transform %d diagonal %d: %w", index, diagonal, marshalErr)
			}
			fmt.Fprintf(&canonical, "/%d=%s", diagonal, sha256Hex(payload))
		}
	}
	return digestString(canonical.String()), nil
}

func digestA2BFullIngress6Profile(profile A2BFullIngress6Profile) string {
	return digestString(fmt.Sprintf(
		"%s|fidelity=%s|schedule=%s|input=%d|output=%d|scale=%s|first-stc-factor-levels=%v|source=%s|origin=%s|range=%s|params=%s|admission=%s|suffix=%s|keys=%s|special=%s|mask=%s|first-stc-raw=%s|first-stc-execution=%s|shared-cts=%s|first-stc-encoded=%s|shared-cts-encoded=%s|second-stc-encoded=%s|counts=%+v|states=%s|serialized=%s|ledger=%s",
		a2bFullIngress6ProfileDigestSchema, profile.fidelity, profile.schedule,
		profile.inputLevel, profile.outputLevel, profile.inputScale.canonicalString(), profile.firstSTCFactorOutputLevels,
		profile.source, profile.trustedOriginAssumption, profile.rangeDigest, profile.parameterDigest,
		profile.admissionDigest, profile.suffixProfileDigest, profile.keyProfileDigest,
		profile.specialB0CompiledDigest, profile.maskPayloadDigest, profile.firstSTCRawMatrixDigest,
		profile.firstSTCExecutionMatrixDigest, profile.sharedCTSExecutionMatrixDigest,
		profile.firstSTCEncodedPayloadDigest, profile.sharedCTSEncodedPayloadDigest, profile.secondSTCEncodedPayloadDigest,
		profile.operationCounts,
		canonicalA2BFullIngress6States(profile.expectedStates), canonicalA2BFullIngress6SerializedBytes(profile.serializedBytes), profile.levelLedger,
	))
}

func canonicalA2BFullIngress6States(states []A2BFullIngress6CiphertextState) string {
	var canonical strings.Builder
	for index, state := range states {
		fmt.Fprintf(&canonical, "%d:%s/L%d/D%d/dims%d,%d/scale=%s/bytes=%d;",
			index, state.Stage, state.Level, state.Degree, state.LogDimensions.Rows, state.LogDimensions.Cols,
			state.Scale.canonicalString(), state.SerializedBytes)
	}
	return canonical.String()
}

func canonicalA2BFullIngress6SerializedBytes(serialized A2BFullIngress6SerializedBytes) string {
	var canonical strings.Builder
	fmt.Fprintf(&canonical, "online=%d/%d/%d;", serialized.onlineInput, serialized.onlineLowOutput, serialized.onlineHighOutput)
	for index, boundary := range serialized.retainedBoundaries {
		fmt.Fprintf(&canonical, "%d:%s=%d;", index, boundary.Stage, boundary.Bytes)
	}
	return canonical.String()
}
