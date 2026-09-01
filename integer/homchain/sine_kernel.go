package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ckkspolynomial "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	gaoSinePrecision       = uint(256)
	gaoSineDenominatorBits = uint(128)
)

// GaoSineFidelity is the implementation claim attached to the isolated sine
// kernel. It deliberately does not claim the full A2A-e circuit.
type GaoSineFidelity string

const (
	GaoSineLattigoAdaptation GaoSineFidelity = "lattigo_adaptation"
)

// GaoSineMaturity is the security maturity of the fixed LogN=5 vertical slice.
type GaoSineMaturity string

const (
	GaoSineFunctionalNotSecure GaoSineMaturity = "functional_not_secure"
)

// GaoSineSchedule separates the pinned OpenFHE ledger from the semantic
// Lattigo ledger. Padding the latter is not source-schedule reproduction.
type GaoSineSchedule struct {
	PolynomialLevels  int
	DoubleAngleLevels int
}

func (s GaoSineSchedule) TotalLevels() int {
	return s.PolynomialLevels + s.DoubleAngleLevels
}

var gaoSineCoefficientNumeratorStrings = [...]string{
	"83554883558593341156762503528993204567",
	"-16306012819143647948975713401021095753",
	"96601747242705937627150555596486294472",
	"-10189598517276305072350718402058306820",
	"121060633236220369893857061438096148094",
	"5140496634290316194783058668439513777",
	"100495409965487171893958806222693651962",
	"24229330335422135436851604093583455254",
	"-35210198440953349910397135793057630914",
	"15311886605351491773147017323171236363",
	"-145473136138920781961207264747490262523",
	"-30741833736894896715423726116380449398",
	"125097585517474914520603377430295523953",
	"16782068243828144697612532317579843330",
	"-49463398143066233903337385547582654922",
	"-5140624783945922523649698647368979137",
	"12233809707070413755946479415658393860",
	"1056120164830265392342384475687453176",
	"-2131685501108436666954167368614470691",
	"-158603673235989998134290690894975991",
	"279469820658646095142599816571795196",
	"18344804074901673392718736965820196",
	"-28771401482185452351376264247803869",
	"-1693714708314538678609151232741534",
	"2397854839256579916125159675533236",
	"128149684565346523194831948305107",
	"-165542301805254342444294230167176",
	"-8109019875829502650635810444033",
	"9640100595106718768996691169391",
	"436164392778452373087215310130",
	"-480554329501726644416052973191",
	"-20180875894855208537597014500",
	"21539486933367133352719181825",
}

var gaoSineRecurrenceNumeratorStrings = [...]string{
	"-214928732683141070416123562033692253131",
	"-135753023439836232162591007175785461952",
	"-54157620742477409023451113735280473968",
}

// GaoSineKernelProfile is an immutable description of the pinned degree-32
// polynomial and three fixed double-angle rounds. All accessors that expose
// mutable numeric values return deep copies.
type GaoSineKernelProfile struct {
	precision             uint
	denominatorBits       uint
	coefficientNumerators []*big.Int
	recurrenceNumerators  []*big.Int
	polynomial            bignum.Polynomial
	coefficientDigest     string
	recurrenceDigest      string
	digest                string
}

// NewGaoSineKernelProfile imports the 33 pinned OpenFHE coefficients as exact
// dyadics. OpenFHE halves c0 while evaluating a Chebyshev series, so only c0 is
// divided by two during the Lattigo import.
func NewGaoSineKernelProfile() (GaoSineKernelProfile, error) {
	coefficients, err := parseSignedIntegers(gaoSineCoefficientNumeratorStrings[:])
	if err != nil {
		return GaoSineKernelProfile{}, fmt.Errorf("homchain: parse Gao sine coefficients: %w", err)
	}
	recurrence, err := parseSignedIntegers(gaoSineRecurrenceNumeratorStrings[:])
	if err != nil {
		return GaoSineKernelProfile{}, fmt.Errorf("homchain: parse Gao sine recurrence: %w", err)
	}

	imported := make([]*bignum.Complex, len(coefficients))
	for i, numerator := range coefficients {
		denominatorBits := gaoSineDenominatorBits
		if i == 0 {
			denominatorBits++
		}
		imported[i] = &bignum.Complex{
			exactDyadicFloat(numerator, denominatorBits, gaoSinePrecision),
			new(big.Float).SetPrec(gaoSinePrecision),
		}
	}
	interval := &bignum.Interval{
		A: *new(big.Float).SetPrec(gaoSinePrecision).SetInt64(-1),
		B: *new(big.Float).SetPrec(gaoSinePrecision).SetInt64(1),
	}
	polynomial := bignum.NewPolynomial(bignum.Chebyshev, imported, interval)
	// The phase shift makes the polynomial neither even nor odd. In Lattigo's
	// evaluator, enabling both flags retains both parity classes.
	polynomial.IsOdd = true
	polynomial.IsEven = true

	coefficientDigest := digestText(
		"basis=chebyshev;denominator=2^128;c0=source-openfhe-half-convention;numerators=" +
			strings.Join(gaoSineCoefficientNumeratorStrings[:], ","),
	)
	recurrenceDigest := digestText(
		"denominator=2^128;numerators=" + strings.Join(gaoSineRecurrenceNumeratorStrings[:], ","),
	)
	profile := GaoSineKernelProfile{
		precision:             gaoSinePrecision,
		denominatorBits:       gaoSineDenominatorBits,
		coefficientNumerators: coefficients,
		recurrenceNumerators:  recurrence,
		polynomial:            polynomial,
		coefficientDigest:     coefficientDigest,
		recurrenceDigest:      recurrenceDigest,
	}
	profile.digest = digestText(fmt.Sprintf(
		"fidelity=%s;maturity=%s;precision=%d;input=%s;source=6+3;lattigo-measured=6+3;vendored-simulator-prediction=5-falsified;coefficients=%s;recurrence=%s",
		GaoSineLattigoAdaptation, GaoSineFunctionalNotSecure, profile.precision,
		profile.InputNormalization(), coefficientDigest, recurrenceDigest,
	))
	return profile, nil
}

func (p GaoSineKernelProfile) Fidelity() GaoSineFidelity { return GaoSineLattigoAdaptation }
func (p GaoSineKernelProfile) Maturity() GaoSineMaturity { return GaoSineFunctionalNotSecure }
func (p GaoSineKernelProfile) Precision() uint           { return p.precision }
func (p GaoSineKernelProfile) DenominatorBits() uint     { return p.denominatorBits }
func (p GaoSineKernelProfile) InputNormalization() string {
	return "x=u/16;u-in-[-16,16];x-in-[-1,1]"
}
func (p GaoSineKernelProfile) SourceSchedule() GaoSineSchedule {
	return GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}
}
func (p GaoSineKernelProfile) LattigoSchedule() GaoSineSchedule {
	return GaoSineSchedule{PolynomialLevels: 6, DoubleAngleLevels: 3}
}
func (p GaoSineKernelProfile) VendoredPolynomialDepthPrediction() int { return 5 }
func (p GaoSineKernelProfile) ScheduleEvidence() string {
	return "lattigo-v6.1.1:degree32-chebyshev-ciphertext-trace=6;simEvaluator.PolynomialDepth=5;prediction=falsified"
}
func (p GaoSineKernelProfile) CoefficientDigest() string { return p.coefficientDigest }
func (p GaoSineKernelProfile) RecurrenceDigest() string  { return p.recurrenceDigest }
func (p GaoSineKernelProfile) Digest() string            { return p.digest }

func (p GaoSineKernelProfile) CoefficientNumerators() []*big.Int {
	return cloneBigInts(p.coefficientNumerators)
}

func (p GaoSineKernelProfile) RecurrenceNumerators() []*big.Int {
	return cloneBigInts(p.recurrenceNumerators)
}

func (p GaoSineKernelProfile) SourceCoefficientValues() []*big.Float {
	return dyadicValues(p.coefficientNumerators, p.denominatorBits, p.precision)
}

func (p GaoSineKernelProfile) LattigoCoefficientValues() []*big.Float {
	result := dyadicValues(p.coefficientNumerators, p.denominatorBits, p.precision)
	result[0].Quo(result[0], new(big.Float).SetPrec(p.precision).SetInt64(2))
	return result
}

func (p GaoSineKernelProfile) RecurrenceValues() []*big.Float {
	return dyadicValues(p.recurrenceNumerators, p.denominatorBits, p.precision)
}

func (p GaoSineKernelProfile) LattigoPolynomial() bignum.Polynomial {
	return cloneGaoSinePolynomial(p.polynomial)
}

// GaoSineOracleResult separates polynomial approximation error from the final
// fixed-kernel error. Accessors return detached values.
type GaoSineOracleResult struct {
	precision             uint
	basePolynomial        *big.Float
	baseTarget            *big.Float
	fixedKernel           *big.Float
	analyticSine          *big.Float
	baseApproximationErr  *big.Float
	finalApproximationErr *big.Float
}

func (r GaoSineOracleResult) Precision() uint { return r.precision }
func (r GaoSineOracleResult) BasePolynomial() *big.Float {
	return cloneBigFloat(r.basePolynomial)
}
func (r GaoSineOracleResult) BaseTarget() *big.Float { return cloneBigFloat(r.baseTarget) }
func (r GaoSineOracleResult) FixedKernel() *big.Float {
	return cloneBigFloat(r.fixedKernel)
}
func (r GaoSineOracleResult) AnalyticSine() *big.Float {
	return cloneBigFloat(r.analyticSine)
}
func (r GaoSineOracleResult) BaseApproximationError() *big.Float {
	return cloneBigFloat(r.baseApproximationErr)
}
func (r GaoSineOracleResult) FinalApproximationError() *big.Float {
	return cloneBigFloat(r.finalApproximationErr)
}

// EvaluateGaoSineKernelOracle evaluates the imported Chebyshev series with an
// independent Clenshaw recurrence, applies the three exact fixed dyadic
// recurrences, and compares both stages to their analytic targets.
func EvaluateGaoSineKernelOracle(profile GaoSineKernelProfile, x *big.Float) (GaoSineOracleResult, error) {
	if x == nil {
		return GaoSineOracleResult{}, fmt.Errorf("homchain: Gao sine oracle input is nil")
	}
	if profile.digest == "" || profile.precision < gaoSinePrecision || len(profile.coefficientNumerators) != 33 || len(profile.recurrenceNumerators) != 3 {
		return GaoSineOracleResult{}, fmt.Errorf("homchain: invalid Gao sine profile")
	}
	prec := x.Prec()
	if prec < profile.precision {
		return GaoSineOracleResult{}, fmt.Errorf("homchain: Gao sine oracle precision=%d, want >=%d", prec, profile.precision)
	}
	one := new(big.Float).SetPrec(prec).SetInt64(1)
	minusOne := new(big.Float).SetPrec(prec).SetInt64(-1)
	if x.Cmp(minusOne) < 0 || x.Cmp(one) > 0 {
		return GaoSineOracleResult{}, fmt.Errorf("homchain: Gao sine oracle x is outside [-1,1]")
	}

	coefficients := dyadicValues(profile.coefficientNumerators, profile.denominatorBits, prec)
	coefficients[0].Quo(coefficients[0], new(big.Float).SetPrec(prec).SetInt64(2))
	base := clenshawChebyshev(coefficients, new(big.Float).SetPrec(prec).Set(x), prec)
	recurrence := dyadicValues(profile.recurrenceNumerators, profile.denominatorBits, prec)
	fixed := new(big.Float).SetPrec(prec).Set(base)
	for _, constant := range recurrence {
		fixed.Mul(fixed, fixed)
		fixed.Add(fixed, fixed)
		fixed.Add(fixed, constant)
	}

	two := new(big.Float).SetPrec(prec).SetInt64(2)
	sixteen := new(big.Float).SetPrec(prec).SetInt64(16)
	eight := new(big.Float).SetPrec(prec).SetInt64(8)
	quarter := new(big.Float).SetPrec(prec).Quo(one, new(big.Float).SetPrec(prec).SetInt64(4))
	twoPi := new(big.Float).SetPrec(prec).Mul(two, bignum.Pi(prec))
	phase := new(big.Float).SetPrec(prec).Mul(sixteen, x)
	phase.Sub(phase, quarter)
	phase.Mul(phase, twoPi)
	phase.Quo(phase, eight)
	amplitudeRoot := new(big.Float).SetPrec(prec).Sqrt(twoPi)
	amplitudeRoot.Sqrt(amplitudeRoot)
	amplitudeRoot.Sqrt(amplitudeRoot)
	amplitude := new(big.Float).SetPrec(prec).Quo(one, amplitudeRoot)
	baseTarget := bignum.Cos(phase)
	baseTarget.Mul(baseTarget, amplitude)

	argument := new(big.Float).SetPrec(prec).Mul(bignum.Pi(prec), new(big.Float).SetPrec(prec).SetInt64(32))
	argument.Mul(argument, x)
	analytic := bignum.Sin(argument)
	analytic.Quo(analytic, twoPi)

	return GaoSineOracleResult{
		precision:             prec,
		basePolynomial:        base,
		baseTarget:            baseTarget,
		fixedKernel:           fixed,
		analyticSine:          analytic,
		baseApproximationErr:  absoluteDifference(base, baseTarget),
		finalApproximationErr: absoluteDifference(fixed, analytic),
	}, nil
}

// GaoSineDomainVerification makes the encrypted-domain evidence boundary
// explicit. The package integrity-checks the artifact but cannot inspect an
// encrypted slot to prove that it lies in x=u/16, x in [-1,1].
type GaoSineDomainVerification string

const (
	GaoSineDomainExternalUnverified GaoSineDomainVerification = "external_unverified"
)

// GaoSineKernelInputCertificate is an immutable, profile-bound declaration of
// the exact level, scale, packing, and encrypted input domain admitted by the
// isolated functional slice.
type GaoSineKernelInputCertificate struct {
	profileDigest      string
	level              int
	scale              ExactScaleSnapshot
	logDimensions      ring.Dimensions
	slots              int
	domain             string
	evidenceArtifact   string
	evidenceDigest     string
	verificationStatus GaoSineDomainVerification
	maturity           GaoSineMaturity
	digest             string
}

// NewGaoSineKernelInputCertificate constructs a fixed-domain certificate. A
// caller cannot promote the domain claim beyond external_unverified or the
// parameter maturity beyond functional_not_secure.
func NewGaoSineKernelInputCertificate(
	profile GaoSineKernelProfile,
	inputScale rlwe.Scale,
	evidenceArtifact, evidenceDigest string,
) (GaoSineKernelInputCertificate, error) {
	if err := profile.validate(); err != nil {
		return GaoSineKernelInputCertificate{}, err
	}
	if inputScale.Mod != nil {
		return GaoSineKernelInputCertificate{}, fmt.Errorf("homchain: Gao sine input scale must be non-modular")
	}
	scale, err := NewExactScaleSnapshot(inputScale)
	if err != nil {
		return GaoSineKernelInputCertificate{}, fmt.Errorf("homchain: snapshot Gao sine input scale: %w", err)
	}
	if evidenceArtifact == "" {
		return GaoSineKernelInputCertificate{}, fmt.Errorf("homchain: Gao sine domain evidence artifact is empty")
	}
	if evidenceDigest != digestText(evidenceArtifact) {
		return GaoSineKernelInputCertificate{}, fmt.Errorf("homchain: Gao sine domain evidence digest mismatch")
	}
	certificate := GaoSineKernelInputCertificate{
		profileDigest:      profile.digest,
		level:              profile.LattigoSchedule().TotalLevels(),
		scale:              scale,
		logDimensions:      ring.Dimensions{Rows: 0, Cols: 4},
		slots:              16,
		domain:             profile.InputNormalization(),
		evidenceArtifact:   evidenceArtifact,
		evidenceDigest:     evidenceDigest,
		verificationStatus: GaoSineDomainExternalUnverified,
		maturity:           GaoSineFunctionalNotSecure,
	}
	certificate.digest = digestText(certificate.canonicalString())
	return certificate, nil
}

func (c GaoSineKernelInputCertificate) ProfileDigest() string { return c.profileDigest }
func (c GaoSineKernelInputCertificate) Level() int            { return c.level }
func (c GaoSineKernelInputCertificate) Scale() ExactScaleSnapshot {
	return c.scale
}
func (c GaoSineKernelInputCertificate) LogDimensions() ring.Dimensions {
	return c.logDimensions
}
func (c GaoSineKernelInputCertificate) Slots() int     { return c.slots }
func (c GaoSineKernelInputCertificate) Domain() string { return c.domain }
func (c GaoSineKernelInputCertificate) EvidenceArtifact() string {
	return c.evidenceArtifact
}
func (c GaoSineKernelInputCertificate) EvidenceDigest() string { return c.evidenceDigest }
func (c GaoSineKernelInputCertificate) VerificationStatus() GaoSineDomainVerification {
	return c.verificationStatus
}
func (c GaoSineKernelInputCertificate) Maturity() GaoSineMaturity { return c.maturity }
func (c GaoSineKernelInputCertificate) Digest() string            { return c.digest }
func (c GaoSineKernelInputCertificate) DomainInternallyVerified() bool {
	return false
}

func (c GaoSineKernelInputCertificate) canonicalString() string {
	return fmt.Sprintf(
		"profile=%s;level=%d;scale={%s};dimensions=%d,%d;slots=%d;domain=%s;evidence=%s;verification=%s;maturity=%s",
		c.profileDigest, c.level, c.scale.canonicalString(), c.logDimensions.Rows,
		c.logDimensions.Cols, c.slots, c.domain, c.evidenceDigest,
		c.verificationStatus, c.maturity,
	)
}

func (c GaoSineKernelInputCertificate) validate(profile GaoSineKernelProfile) error {
	if c.profileDigest != profile.digest || c.level != 9 || c.logDimensions != (ring.Dimensions{Rows: 0, Cols: 4}) ||
		c.slots != 16 || c.domain != profile.InputNormalization() || c.evidenceArtifact == "" ||
		c.evidenceDigest != digestText(c.evidenceArtifact) || c.verificationStatus != GaoSineDomainExternalUnverified ||
		c.maturity != GaoSineFunctionalNotSecure || c.digest != digestText(c.canonicalString()) {
		return fmt.Errorf("homchain: invalid Gao sine input certificate")
	}
	if _, err := c.scale.Scale(); err != nil || c.scale.HasMod() {
		return fmt.Errorf("homchain: invalid Gao sine certificate scale")
	}
	return nil
}

// GaoSineKernelFunctionalParameters returns the fixed, tiny parameter set for
// this isolated vertical slice. LogN=5 is intentionally not secure. The
// 35-bit Q primes match the 2^35 working scale. In the Paterson-Stockmeyer
// power basis, scale exponents follow s[2k] = 2*s[k] - q: Q60/S55 collapses
// 55 -> 50 -> 40 -> 20 -> -20 -> -100, whereas Q35/S35 remains near 35.
// A P60 auxiliary prime supports relinearization but cannot repair that scale
// collapse. Ten Q primes provide the nine consumable Lattigo levels measured
// for this exact degree-32 polynomial (six polynomial plus three double-angle
// levels).
func GaoSineKernelFunctionalParameters() (ckks.Parameters, error) {
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            []int{35, 35, 35, 35, 35, 35, 35, 35, 35, 35},
		LogP:            []int{60},
		LogDefaultScale: 35,
	})
}

// GaoSineKernelStage identifies the exact state boundaries of the isolated
// polynomial-plus-three-double-angle circuit.
type GaoSineKernelStage string

const (
	GaoSineStageInput        GaoSineKernelStage = "input-x-equals-u-over-16"
	GaoSineStagePolynomial   GaoSineKernelStage = "degree-32-chebyshev"
	GaoSineStageDoubleAngle0 GaoSineKernelStage = "double-angle-0"
	GaoSineStageDoubleAngle1 GaoSineKernelStage = "double-angle-1"
	GaoSineStageDoubleAngle2 GaoSineKernelStage = "double-angle-2"
)

// GaoSineCiphertextState is an immutable exact scale/level/degree snapshot.
type GaoSineCiphertextState struct {
	Stage         GaoSineKernelStage
	Level         int
	Degree        int
	Scale         ExactScaleSnapshot
	ExpectedScale ExactScaleSnapshot
	ScaleExact    bool
}

// GaoSineOperandEncoding identifies the concrete CKKS evaluator dispatch used
// for plaintext coefficients and recurrence constants.
type GaoSineOperandEncoding string

const (
	// GaoSinePackedVectorEncoding selects CKKS's vector operand branch, which
	// encodes through the evaluator's bound Encoder instead of quantizing a
	// scalar with Parameters.EncodingPrecision().
	GaoSinePackedVectorEncoding GaoSineOperandEncoding = "packed-vector/Encoder.Encode"
)

// GaoSineOperandEncodingTrace is a comparable, immutable summary of the exact
// operands supplied to the polynomial and recurrence evaluators.
type GaoSineOperandEncodingTrace struct {
	polynomialEncoding  GaoSineOperandEncoding
	polynomialSlots     int
	recurrenceEncodings [3]GaoSineOperandEncoding
	recurrenceSlots     [3]int
}

func (t GaoSineOperandEncodingTrace) PolynomialEncoding() GaoSineOperandEncoding {
	return t.polynomialEncoding
}
func (t GaoSineOperandEncodingTrace) PolynomialMappedSlots() int { return t.polynomialSlots }
func (t GaoSineOperandEncodingTrace) RecurrenceEncodings() [3]GaoSineOperandEncoding {
	return t.recurrenceEncodings
}
func (t GaoSineOperandEncodingTrace) RecurrenceVectorSlots() [3]int {
	return t.recurrenceSlots
}

// GaoSineKernelProvenance is the detached audit record of one evaluation.
type GaoSineKernelProvenance struct {
	profileDigest           string
	inputCertificateDigest  string
	operationalEncoderPrec  uint
	operandEncodingTrace    GaoSineOperandEncodingTrace
	fidelity                GaoSineFidelity
	maturity                GaoSineMaturity
	sourceSchedule          GaoSineSchedule
	lattigoSchedule         GaoSineSchedule
	states                  []GaoSineCiphertextState
	finalDesiredScale       ExactScaleSnapshot
	finalScalePrecisionBits float64
}

func (p GaoSineKernelProvenance) ProfileDigest() string { return p.profileDigest }
func (p GaoSineKernelProvenance) InputCertificateDigest() string {
	return p.inputCertificateDigest
}
func (p GaoSineKernelProvenance) OperationalEncoderPrecision() uint {
	return p.operationalEncoderPrec
}
func (p GaoSineKernelProvenance) OperandEncodingTrace() GaoSineOperandEncodingTrace {
	return p.operandEncodingTrace
}
func (p GaoSineKernelProvenance) Fidelity() GaoSineFidelity { return p.fidelity }
func (p GaoSineKernelProvenance) Maturity() GaoSineMaturity { return p.maturity }
func (p GaoSineKernelProvenance) SourceSchedule() GaoSineSchedule {
	return p.sourceSchedule
}
func (p GaoSineKernelProvenance) LattigoSchedule() GaoSineSchedule {
	return p.lattigoSchedule
}
func (p GaoSineKernelProvenance) States() []GaoSineCiphertextState {
	return append([]GaoSineCiphertextState(nil), p.states...)
}
func (p GaoSineKernelProvenance) FinalDesiredScale() ExactScaleSnapshot {
	return p.finalDesiredScale
}
func (p GaoSineKernelProvenance) FinalScalePrecisionBits() float64 {
	return p.finalScalePrecisionBits
}

// GaoSineKernelResult owns the output and its immutable provenance.
type GaoSineKernelResult struct {
	ciphertext *rlwe.Ciphertext
	provenance GaoSineKernelProvenance
}

func (r GaoSineKernelResult) Ciphertext() *rlwe.Ciphertext {
	if r.ciphertext == nil {
		return nil
	}
	return r.ciphertext.CopyNew()
}
func (r GaoSineKernelResult) Provenance() GaoSineKernelProvenance { return r.provenance }

// GaoSineKernelEvaluator is fixed to the guarded LogN=5 functional profile.
// It contains no mod1 evaluator and performs no scale metadata retagging.
type GaoSineKernelEvaluator struct {
	params                ckks.Parameters
	profile               GaoSineKernelProfile
	certificate           GaoSineKernelInputCertificate
	ckks                  *ckks.Evaluator
	polynomial            *ckkspolynomial.Evaluator
	polynomialOperand     ckkspolynomial.PolynomialVector
	recurrenceOperands    [3][]*big.Float
	operandEncodingPlan   GaoSineOperandEncodingTrace
	polynomialTargetScale rlwe.Scale
	expectedScales        []rlwe.Scale
}

// NewGaoSineKernelEvaluator preflights the exact fixed parameters, arbitrary-
// precision encoder, evaluator parameters, relinearization key, and the
// level-scale-domain input certificate before any ciphertext operation.
func NewGaoSineKernelEvaluator(
	params ckks.Parameters,
	encoder *ckks.Encoder,
	evaluator *ckks.Evaluator,
	certificate GaoSineKernelInputCertificate,
) (*GaoSineKernelEvaluator, error) {
	profile, err := NewGaoSineKernelProfile()
	if err != nil {
		return nil, err
	}
	expectedParams, err := GaoSineKernelFunctionalParameters()
	if err != nil {
		return nil, fmt.Errorf("homchain: construct fixed Gao sine parameters: %w", err)
	}
	if !params.Equal(&expectedParams) {
		return nil, fmt.Errorf("homchain: Gao sine kernel requires the exact fixed functional parameters")
	}
	if params.RingType() != ring.Standard || params.MaxSlots() != 16 || params.MaxLevel() != 9 ||
		params.LevelsConsumedPerRescaling() != 1 {
		return nil, fmt.Errorf("homchain: Gao sine fixed parameters do not expose 16 slots and nine one-prime levels")
	}
	if encoder == nil {
		return nil, fmt.Errorf("homchain: Gao sine encoder is nil")
	}
	encoderParams := encoder.GetParameters()
	if !params.Equal(&encoderParams) || encoder.Prec() < profile.precision {
		return nil, fmt.Errorf("homchain: Gao sine encoder parameters or precision do not match the profile")
	}
	if evaluator == nil || evaluator.GetParameters() == nil || !params.Equal(evaluator.GetParameters()) {
		return nil, fmt.Errorf("homchain: Gao sine evaluator parameters do not match the profile")
	}
	if evaluator.EvaluationKeySet == nil {
		return nil, fmt.Errorf("homchain: Gao sine evaluation key set is nil")
	}
	relinearizationKey, err := evaluator.EvaluationKeySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return nil, fmt.Errorf("homchain: Gao sine relinearization key is missing: %w", err)
	}
	if relinearizationKey.LevelQ() < params.MaxLevel() || relinearizationKey.LevelP() != params.MaxLevelP() {
		return nil, fmt.Errorf("homchain: Gao sine relinearization key has insufficient Q/P levels")
	}
	if err = certificate.validate(profile); err != nil {
		return nil, err
	}
	if !certificate.scale.EqualScale(params.DefaultScale()) {
		return nil, fmt.Errorf("homchain: Gao sine certificate scale is not the exact default input scale")
	}

	targetScale, expectedScales, err := gaoSineNaturalScaleSchedule(params)
	if err != nil {
		return nil, err
	}
	// CKKS vector operand branches encode through the evaluator's Encoder,
	// whereas scalar branches quantize through Parameters.EncodingPrecision().
	// Bind a private copy of the validated arbitrary-precision encoder; the
	// full-slot vector operands constructed below force coefficients and
	// recurrence constants through that encoder. Both caller-owned objects
	// remain unchanged and retain independent mutable buffers.
	operationalEvaluator := evaluator.ShallowCopy()
	operationalEvaluator.Encoder = encoder.ShallowCopy()
	if operationalEvaluator.Encoder.Prec() < profile.precision {
		return nil, fmt.Errorf("homchain: Gao sine operational encoder precision is below the profile precision")
	}
	polynomialOperand, recurrenceOperands, operandEncodingPlan, err := newGaoSinePackedOperands(profile, params.MaxSlots())
	if err != nil {
		return nil, err
	}
	return &GaoSineKernelEvaluator{
		params:                params,
		profile:               profile,
		certificate:           certificate,
		ckks:                  operationalEvaluator,
		polynomial:            ckkspolynomial.NewEvaluator(params, operationalEvaluator),
		polynomialOperand:     polynomialOperand,
		recurrenceOperands:    recurrenceOperands,
		operandEncodingPlan:   operandEncodingPlan,
		polynomialTargetScale: targetScale,
		expectedScales:        expectedScales,
	}, nil
}

// OperandEncodingPlan reports the concrete, full-slot operand shapes held by
// the evaluator. EvaluateNew re-derives this trace from fresh operand copies and
// fails closed if they differ.
func (e *GaoSineKernelEvaluator) OperandEncodingPlan() GaoSineOperandEncodingTrace {
	if e == nil {
		return GaoSineOperandEncodingTrace{}
	}
	return e.operandEncodingPlan
}

func (e *GaoSineKernelEvaluator) Profile() GaoSineKernelProfile {
	if e == nil {
		return GaoSineKernelProfile{}
	}
	return e.profile
}

// OperationalEncoderPrecision reports the precision of the private encoder
// actually used by polynomial coefficients and recurrence constants.
func (e *GaoSineKernelEvaluator) OperationalEncoderPrecision() uint {
	if e == nil || e.ckks == nil || e.ckks.Encoder == nil {
		return 0
	}
	return e.ckks.Encoder.Prec()
}

// EvaluateNew evaluates the exact imported Chebyshev polynomial and then
// executes exactly three MulRelinNew -> Rescale -> Add(y,y) -> Add(r_i)
// rounds. The input is never used as an output buffer.
func (e *GaoSineKernelEvaluator) EvaluateNew(input *rlwe.Ciphertext) (GaoSineKernelResult, error) {
	if e == nil || e.ckks == nil || e.polynomial == nil {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: nil Gao sine evaluator")
	}
	if err := e.validateInput(input); err != nil {
		return GaoSineKernelResult{}, err
	}
	if err := e.preflightRelinearizationKey(); err != nil {
		return GaoSineKernelResult{}, err
	}
	inputBefore := input.CopyNew()
	polynomialOperand, err := cloneGaoSinePolynomialVector(e.polynomialOperand)
	if err != nil {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: clone Gao sine packed polynomial operand: %w", err)
	}
	recurrenceOperands := cloneGaoSineRecurrenceOperands(e.recurrenceOperands)
	operandEncodingTrace, err := inspectGaoSinePackedOperands(polynomialOperand, recurrenceOperands, e.params.MaxSlots())
	if err != nil {
		return GaoSineKernelResult{}, err
	}
	if operandEncodingTrace != e.operandEncodingPlan {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine operand encoding plan changed before evaluation")
	}
	states := make([]GaoSineCiphertextState, 0, 5)
	state, err := snapshotGaoSineState(GaoSineStageInput, input, e.expectedScales[0])
	if err != nil {
		return GaoSineKernelResult{}, err
	}
	if !state.ScaleExact {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine input scale drifted from the exact natural schedule")
	}
	states = append(states, state)

	y, err := e.polynomial.Evaluate(input, polynomialOperand, e.polynomialTargetScale)
	if err != nil {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine Chebyshev evaluation: %w", err)
	}
	if y.Level() != 3 || y.Degree() != 1 {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine polynomial state level=%d degree=%d, want level=3 degree=1", y.Level(), y.Degree())
	}
	state, err = snapshotGaoSineState(GaoSineStagePolynomial, y, e.expectedScales[1])
	if err != nil {
		return GaoSineKernelResult{}, err
	}
	if !state.ScaleExact {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine polynomial scale did not naturally reach the exact target")
	}
	states = append(states, state)

	stages := [...]GaoSineKernelStage{GaoSineStageDoubleAngle0, GaoSineStageDoubleAngle1, GaoSineStageDoubleAngle2}
	for i := range recurrenceOperands {
		y, err = e.ckks.MulRelinNew(y, y)
		if err != nil {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d MulRelinNew: %w", i, err)
		}
		if err = e.ckks.Rescale(y, y); err != nil {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d Rescale: %w", i, err)
		}
		if err = e.ckks.Add(y, y, y); err != nil {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d double: %w", i, err)
		}
		if err = e.ckks.Add(y, recurrenceOperands[i], y); err != nil {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d add recurrence: %w", i, err)
		}
		if y.Level() != 2-i || y.Degree() != 1 {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d state level=%d degree=%d", i, y.Level(), y.Degree())
		}
		state, err = snapshotGaoSineState(stages[i], y, e.expectedScales[i+2])
		if err != nil {
			return GaoSineKernelResult{}, err
		}
		if !state.ScaleExact {
			return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine double-angle %d scale drifted from the exact natural schedule", i)
		}
		states = append(states, state)
	}
	if !input.Equal(inputBefore) {
		return GaoSineKernelResult{}, fmt.Errorf("homchain: Gao sine evaluator mutated its input")
	}
	desiredScale := e.params.DefaultScale()
	desiredSnapshot, err := NewExactScaleSnapshot(desiredScale)
	if err != nil {
		return GaoSineKernelResult{}, err
	}
	precisionBits := y.Scale.Log2Delta(desiredScale)
	return GaoSineKernelResult{
		ciphertext: y,
		provenance: GaoSineKernelProvenance{
			profileDigest: e.profile.digest, inputCertificateDigest: e.certificate.digest,
			operationalEncoderPrec: e.OperationalEncoderPrecision(),
			operandEncodingTrace:   operandEncodingTrace,
			fidelity:               GaoSineLattigoAdaptation, maturity: GaoSineFunctionalNotSecure,
			sourceSchedule: e.profile.SourceSchedule(), lattigoSchedule: e.profile.LattigoSchedule(),
			states: states, finalDesiredScale: desiredSnapshot, finalScalePrecisionBits: precisionBits,
		},
	}, nil
}

func (e *GaoSineKernelEvaluator) preflightRelinearizationKey() error {
	if e.ckks.EvaluationKeySet == nil {
		return fmt.Errorf("homchain: Gao sine evaluation key set disappeared before nonlinear evaluation")
	}
	relinearizationKey, err := e.ckks.EvaluationKeySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil {
		return fmt.Errorf("homchain: Gao sine relinearization key preflight failed before nonlinear evaluation: %w", err)
	}
	if relinearizationKey.LevelQ() < e.params.MaxLevel() || relinearizationKey.LevelP() != e.params.MaxLevelP() {
		return fmt.Errorf("homchain: Gao sine relinearization key changed to insufficient Q/P levels before nonlinear evaluation")
	}
	return nil
}

func (e *GaoSineKernelEvaluator) validateInput(input *rlwe.Ciphertext) error {
	if input == nil || input.MetaData == nil {
		return fmt.Errorf("homchain: Gao sine input is nil or has nil metadata")
	}
	if input.Level() != e.certificate.level || input.Degree() != 1 {
		return fmt.Errorf("homchain: Gao sine input level=%d degree=%d, want level=%d degree=1", input.Level(), input.Degree(), e.certificate.level)
	}
	if !input.IsBatched || !input.IsNTT || input.LogDimensions != e.certificate.logDimensions || input.Slots() != e.certificate.slots {
		return fmt.Errorf("homchain: Gao sine input is not full-packed over the certified 16-slot domain")
	}
	if !e.certificate.scale.EqualScale(input.Scale) {
		return fmt.Errorf("homchain: Gao sine input exact scale does not match its certificate")
	}
	return nil
}

func snapshotGaoSineState(stage GaoSineKernelStage, ciphertext *rlwe.Ciphertext, expected rlwe.Scale) (GaoSineCiphertextState, error) {
	actualSnapshot, err := NewExactScaleSnapshot(ciphertext.Scale)
	if err != nil {
		return GaoSineCiphertextState{}, fmt.Errorf("homchain: snapshot Gao sine %s scale: %w", stage, err)
	}
	expectedSnapshot, err := NewExactScaleSnapshot(expected)
	if err != nil {
		return GaoSineCiphertextState{}, fmt.Errorf("homchain: snapshot Gao sine %s expected scale: %w", stage, err)
	}
	return GaoSineCiphertextState{
		Stage: stage, Level: ciphertext.Level(), Degree: ciphertext.Degree(),
		Scale: actualSnapshot, ExpectedScale: expectedSnapshot,
		ScaleExact: actualSnapshot.Equal(expectedSnapshot),
	}, nil
}

// gaoSineNaturalScaleSchedule derives the degree-32 target scale backward
// from the desired final scale, then independently predicts each forward
// rescale state. No ciphertext scale metadata is assigned by this function.
func gaoSineNaturalScaleSchedule(params ckks.Parameters) (rlwe.Scale, []rlwe.Scale, error) {
	if params.MaxLevel() != 9 || len(params.Q()) != 10 {
		return rlwe.Scale{}, nil, fmt.Errorf("homchain: Gao sine scale schedule requires levels 9 through 0")
	}
	target := params.DefaultScale()
	for level := 1; level <= 3; level++ {
		product := target.Mul(rlwe.NewScale(params.Q()[level]))
		root := new(big.Float).SetPrec(rlwe.ScalePrecision).Sqrt(&product.Value)
		target = rlwe.NewScale(root)
	}
	result := make([]rlwe.Scale, 5)
	result[0] = params.DefaultScale()
	result[1] = target
	current := target
	for round, level := 0, 3; round < 3; round, level = round+1, level-1 {
		current = current.Mul(current).Div(rlwe.NewScale(params.Q()[level]))
		result[round+2] = current
	}
	return target, result, nil
}

func (p GaoSineKernelProfile) validate() error {
	if p.precision != gaoSinePrecision || p.denominatorBits != gaoSineDenominatorBits ||
		len(p.coefficientNumerators) != 33 || len(p.recurrenceNumerators) != 3 ||
		p.polynomial.Basis != bignum.Chebyshev || p.polynomial.Degree() != 32 ||
		p.coefficientDigest != digestText("basis=chebyshev;denominator=2^128;c0=source-openfhe-half-convention;numerators="+strings.Join(gaoSineCoefficientNumeratorStrings[:], ",")) ||
		p.recurrenceDigest != digestText("denominator=2^128;numerators="+strings.Join(gaoSineRecurrenceNumeratorStrings[:], ",")) || p.digest == "" {
		return fmt.Errorf("homchain: invalid Gao sine kernel profile")
	}
	return nil
}

func clenshawChebyshev(coefficients []*big.Float, x *big.Float, prec uint) *big.Float {
	bNext := new(big.Float).SetPrec(prec)
	bNextNext := new(big.Float).SetPrec(prec)
	twoX := new(big.Float).SetPrec(prec).Add(x, x)
	for i := len(coefficients) - 1; i >= 1; i-- {
		current := new(big.Float).SetPrec(prec).Mul(twoX, bNext)
		current.Sub(current, bNextNext)
		current.Add(current, coefficients[i])
		bNextNext, bNext = bNext, current
	}
	result := new(big.Float).SetPrec(prec).Mul(x, bNext)
	result.Sub(result, bNextNext)
	return result.Add(result, coefficients[0])
}

func parseSignedIntegers(values []string) ([]*big.Int, error) {
	result := make([]*big.Int, len(values))
	for i, value := range values {
		result[i] = new(big.Int)
		if _, ok := result[i].SetString(value, 10); !ok {
			return nil, fmt.Errorf("index %d is not a signed decimal integer", i)
		}
	}
	return result, nil
}

func exactDyadicFloat(numerator *big.Int, denominatorBits, prec uint) *big.Float {
	denominator := new(big.Int).Lsh(big.NewInt(1), denominatorBits)
	return new(big.Float).SetPrec(prec).Quo(
		new(big.Float).SetPrec(prec).SetInt(numerator),
		new(big.Float).SetPrec(prec).SetInt(denominator),
	)
}

func dyadicValues(numerators []*big.Int, denominatorBits, prec uint) []*big.Float {
	result := make([]*big.Float, len(numerators))
	for i, numerator := range numerators {
		result[i] = exactDyadicFloat(numerator, denominatorBits, prec)
	}
	return result
}

func newGaoSinePackedOperands(
	profile GaoSineKernelProfile,
	slots int,
) (ckkspolynomial.PolynomialVector, [3][]*big.Float, GaoSineOperandEncodingTrace, error) {
	mapping := make(map[int][]int, 1)
	mapping[0] = make([]int, slots)
	for i := range mapping[0] {
		mapping[0][i] = i
	}
	polynomialOperand, err := ckkspolynomial.NewPolynomialVector(
		[]bignum.Polynomial{cloneGaoSinePolynomial(profile.polynomial)},
		mapping,
	)
	if err != nil {
		return ckkspolynomial.PolynomialVector{}, [3][]*big.Float{}, GaoSineOperandEncodingTrace{},
			fmt.Errorf("homchain: construct Gao sine packed polynomial operand: %w", err)
	}

	values := profile.RecurrenceValues()
	if len(values) != 3 {
		return ckkspolynomial.PolynomialVector{}, [3][]*big.Float{}, GaoSineOperandEncodingTrace{},
			fmt.Errorf("homchain: Gao sine recurrence count=%d, want 3", len(values))
	}
	var recurrenceOperands [3][]*big.Float
	for i := range recurrenceOperands {
		recurrenceOperands[i] = make([]*big.Float, slots)
		for j := range recurrenceOperands[i] {
			recurrenceOperands[i][j] = cloneBigFloat(values[i])
		}
	}
	trace, err := inspectGaoSinePackedOperands(polynomialOperand, recurrenceOperands, slots)
	if err != nil {
		return ckkspolynomial.PolynomialVector{}, [3][]*big.Float{}, GaoSineOperandEncodingTrace{}, err
	}
	return polynomialOperand, recurrenceOperands, trace, nil
}

func inspectGaoSinePackedOperands(
	polynomialOperand ckkspolynomial.PolynomialVector,
	recurrenceOperands [3][]*big.Float,
	slots int,
) (GaoSineOperandEncodingTrace, error) {
	if slots <= 0 || len(polynomialOperand.Value) != 1 || len(polynomialOperand.Mapping) != 1 {
		return GaoSineOperandEncodingTrace{}, fmt.Errorf("homchain: Gao sine polynomial operand is not one mapped packed polynomial")
	}
	mapped, ok := polynomialOperand.Mapping[0]
	if !ok || len(mapped) != slots {
		return GaoSineOperandEncodingTrace{}, fmt.Errorf("homchain: Gao sine polynomial mapping covers %d slots, want %d", len(mapped), slots)
	}
	seen := make([]bool, slots)
	for _, slot := range mapped {
		if slot < 0 || slot >= slots || seen[slot] {
			return GaoSineOperandEncodingTrace{}, fmt.Errorf("homchain: Gao sine polynomial mapping is not a one-to-one full-slot mapping")
		}
		seen[slot] = true
	}

	trace := GaoSineOperandEncodingTrace{
		polynomialEncoding: GaoSinePackedVectorEncoding,
		polynomialSlots:    slots,
	}
	for i := range recurrenceOperands {
		if len(recurrenceOperands[i]) != slots {
			return GaoSineOperandEncodingTrace{}, fmt.Errorf("homchain: Gao sine recurrence %d covers %d slots, want %d", i, len(recurrenceOperands[i]), slots)
		}
		for _, value := range recurrenceOperands[i] {
			if value == nil || value.Prec() < gaoSinePrecision {
				return GaoSineOperandEncodingTrace{}, fmt.Errorf("homchain: Gao sine recurrence %d contains a nil or low-precision packed value", i)
			}
		}
		trace.recurrenceEncodings[i] = GaoSinePackedVectorEncoding
		trace.recurrenceSlots[i] = len(recurrenceOperands[i])
	}
	return trace, nil
}

func cloneGaoSinePolynomialVector(value ckkspolynomial.PolynomialVector) (ckkspolynomial.PolynomialVector, error) {
	polynomials := make([]bignum.Polynomial, len(value.Value))
	for i := range value.Value {
		polynomials[i] = cloneGaoSinePolynomial(value.Value[i].Polynomial)
	}
	mapping := make(map[int][]int, len(value.Mapping))
	for polynomialIndex, slots := range value.Mapping {
		mapping[polynomialIndex] = append([]int(nil), slots...)
	}
	return ckkspolynomial.NewPolynomialVector(polynomials, mapping)
}

func cloneGaoSineRecurrenceOperands(value [3][]*big.Float) (result [3][]*big.Float) {
	for i := range value {
		result[i] = make([]*big.Float, len(value[i]))
		for j := range value[i] {
			result[i][j] = cloneBigFloat(value[i][j])
		}
	}
	return
}

func cloneBigInts(values []*big.Int) []*big.Int {
	result := make([]*big.Int, len(values))
	for i, value := range values {
		result[i] = new(big.Int).Set(value)
	}
	return result
}

func cloneBigFloat(value *big.Float) *big.Float {
	if value == nil {
		return nil
	}
	return new(big.Float).SetPrec(value.Prec()).Set(value)
}

func cloneGaoSinePolynomial(value bignum.Polynomial) bignum.Polynomial {
	result := value.Clone()
	result.Interval.A = *new(big.Float).SetPrec(value.Interval.A.Prec()).Set(&value.Interval.A)
	result.Interval.B = *new(big.Float).SetPrec(value.Interval.B.Prec()).Set(&value.Interval.B)
	return result
}

func absoluteDifference(a, b *big.Float) *big.Float {
	return new(big.Float).SetPrec(maxUint(a.Prec(), b.Prec())).Abs(new(big.Float).Sub(a, b))
}

func maxUint(a, b uint) uint {
	if a > b {
		return a
	}
	return b
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
