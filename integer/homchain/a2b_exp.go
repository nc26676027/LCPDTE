package homchain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

const (
	gaoA2BExpPrecision       = uint(256)
	gaoA2BExpDenominatorBits = uint(128)
	gaoA2BExpDegree          = 46
	gaoA2BExpSquaringRounds  = 2
	gaoA2BExpSourceCommit    = "08f1eb87434e7be072cba889270a8400bbffc08e"
	gaoA2BExpArtifactDigest  = "a960edc18c4c7dee294d0f452eb3ef377c1d2094dadc0a046f49a68902e36e4d"
)

// GaoA2BExpMaturity states the boundary of this prerequisite artifact. It is
// not an encrypted A2B implementation or evidence for such an implementation.
type GaoA2BExpMaturity string

const (
	GaoA2BExpPrerequisiteOnly GaoA2BExpMaturity = "prerequisite_artifact_only_not_encrypted_a2b"
)

// GaoA2BExpSecurity is the security claim carried by this scalar prerequisite.
type GaoA2BExpSecurity string

const (
	GaoA2BExpNoSecurityClaim GaoA2BExpSecurity = "none"
)

type gaoA2BExpRow struct {
	real      string
	imaginary string
}

// These are the exact LF-canonical signed numerators extracted from the
// pinned OpenFHE source. Both components have denominator 2^128. They are
// embedded so construction never depends on a runtime TSV or approximation.
var gaoA2BExpRows = [...]gaoA2BExpRow{
	{"76201359508406144086108162329195173168", "0"},
	{"0", "-75462327482981010929732591801834267864"},
	{"82206460726474050179385148728921771719", "0"},
	{"0", "-62378762904272904571622519573888623801"},
	{"97098293416732629097600305219456855499", "0"},
	{"0", "-31471416178152430358852601914596611953"},
	{"109620372043870639737320939173783651180", "0"},
	{"0", "20868456044911447829692299230268924062"},
	{"97995759274018037306194755132115244812", "0"},
	{"0", "83254494006925109073099868507868875949"},
	{"38369120122842855712446721811003263673", "0"},
	{"0", "113787669655110863451684674786681535734"},
	{"-61235165364009198111122209480690033571", "0"},
	{"0", "55312394102720757898644017695156241698"},
	{"-118456231446026759188540160451923974650", "0"},
	{"0", "-76657869319988643285788486120509014816"},
	{"-26952640227261194763905894118541892848", "0"},
	{"0", "-110975036692357318664215943018894133477"},
	{"123176277792580374930872323065723168814", "0"},
	{"0", "65461984648789268549752845623099323173"},
	{"24199592598704844843639018288912304640", "0"},
	{"0", "103976832477728479972166721438522536183"},
	{"-149558889387913469944174072103565069088", "0"},
	{"0", "-157856569345896333137462968783752189608"},
	{"139363123687758077275148952782773192202", "0"},
	{"0", "108307390889710558441768332456126937807"},
	{"-76107584230786263566865857621046575334", "0"},
	{"0", "-49160286192750883756104910817563002643"},
	{"29517800212959227902043865999503838345", "0"},
	{"0", "16610367190529583398134186375537330573"},
	{"-8814719438731980321657801606283511560", "0"},
	{"0", "-4433225369106595370001465513431931046"},
	{"2121611396940476700602011891396966522", "0"},
	{"0", "969413689184253022482741228740206533"},
	{"-424123781880829375906288741430021479", "0"},
	{"0", "-178110049091476168426565764511850484"},
	{"71950375846198071501808575521349862", "0"},
	{"0", "28012594426088261941483051060830883"},
	{"-10528967284487014070098235228834198", "0"},
	{"0", "-3826412149487927199644353100957528"},
	{"1346384732986646374141373576436026", "0"},
	{"0", "459263298931367865662987911923740"},
	{"-152043828833303538796249154920542", "0"},
	{"0", "-48901534948157653133922884776047"},
	{"15305417609139069281700626960548", "0"},
	{"0", "4626479749297127615445055291356"},
	{"-1494210995158446546673318351371", "0"},
}

// GaoA2BExpProfile is an immutable exact-dyadic import of Gao's degree-46
// complex Chebyshev exponential prerequisite. It describes plaintext
// coefficients and a scalar oracle only; it is not encrypted A2B and carries
// no security claim. Every mutable numeric accessor returns a deep copy.
type GaoA2BExpProfile struct {
	precision           uint
	denominatorBits     uint
	degree              int
	basis               bignum.Basis
	realNumerators      []*big.Int
	imaginaryNumerators []*big.Int
	polynomial          bignum.Polynomial
	canonicalTable      string
	artifactDigest      string
	importDigest        string
	digest              string
}

// NewGaoA2BExpProfile authenticates the embedded source artifact and imports
// its coefficients at 256-bit precision. OpenFHE's Chebyshev PS evaluator
// divides the free term by two, so the Lattigo polynomial divides c0 by two
// exactly once and leaves c1..c46 unchanged.
func NewGaoA2BExpProfile() (GaoA2BExpProfile, error) {
	canonical := canonicalGaoA2BExpTable()
	artifactDigest := a2bExpDigestText(canonical)
	if artifactDigest != gaoA2BExpArtifactDigest {
		return GaoA2BExpProfile{}, fmt.Errorf("homchain: Gao A2B exponential artifact digest mismatch: got %s, want %s", artifactDigest, gaoA2BExpArtifactDigest)
	}
	if len(gaoA2BExpRows) != gaoA2BExpDegree+1 {
		return GaoA2BExpProfile{}, fmt.Errorf("homchain: Gao A2B exponential has %d coefficients, want %d", len(gaoA2BExpRows), gaoA2BExpDegree+1)
	}

	realNumerators := make([]*big.Int, len(gaoA2BExpRows))
	imaginaryNumerators := make([]*big.Int, len(gaoA2BExpRows))
	imported := make([]*bignum.Complex, len(gaoA2BExpRows))
	for index, row := range gaoA2BExpRows {
		var ok bool
		realNumerators[index], ok = new(big.Int).SetString(row.real, 10)
		if !ok {
			return GaoA2BExpProfile{}, fmt.Errorf("homchain: Gao A2B exponential real numerator %d is invalid", index)
		}
		imaginaryNumerators[index], ok = new(big.Int).SetString(row.imaginary, 10)
		if !ok {
			return GaoA2BExpProfile{}, fmt.Errorf("homchain: Gao A2B exponential imaginary numerator %d is invalid", index)
		}
		denominatorBits := gaoA2BExpDenominatorBits
		if index == 0 {
			denominatorBits++
		}
		imported[index] = &bignum.Complex{
			a2bExpExactDyadic(realNumerators[index], denominatorBits, gaoA2BExpPrecision),
			a2bExpExactDyadic(imaginaryNumerators[index], denominatorBits, gaoA2BExpPrecision),
		}
	}
	interval := &bignum.Interval{
		A: *new(big.Float).SetPrec(gaoA2BExpPrecision).SetInt64(-1),
		B: *new(big.Float).SetPrec(gaoA2BExpPrecision).SetInt64(1),
	}
	polynomial := bignum.NewPolynomial(bignum.Chebyshev, imported, interval)
	polynomial.IsOdd = true
	polynomial.IsEven = true

	importDigest := a2bExpDigestText(fmt.Sprintf(
		"artifact=%s;basis=chebyshev;degree=%d;precision=%d;denominator=2^128;interval=[-1,1];free-term=openfhe-ps-c0-over-2;lattigo-import=c0-over-2-once",
		artifactDigest, gaoA2BExpDegree, gaoA2BExpPrecision,
	))
	profile := GaoA2BExpProfile{
		precision: gaoA2BExpPrecision, denominatorBits: gaoA2BExpDenominatorBits,
		degree: gaoA2BExpDegree, basis: bignum.Chebyshev,
		realNumerators: realNumerators, imaginaryNumerators: imaginaryNumerators,
		polynomial: polynomial, canonicalTable: canonical,
		artifactDigest: artifactDigest, importDigest: importDigest,
	}
	profile.digest = a2bExpDigestText(fmt.Sprintf(
		"source=%s;maturity=%s;security=%s;normalization=%s;base=%s;squares=%d;final=%s;import=%s",
		gaoA2BExpSourceCommit, GaoA2BExpPrerequisiteOnly, GaoA2BExpNoSecurityClaim,
		profile.InputNormalization(), profile.BaseTarget(), profile.SquaringRounds(), profile.FinalTarget(), importDigest,
	))
	return profile, nil
}

func (p GaoA2BExpProfile) Precision() uint                  { return p.precision }
func (p GaoA2BExpProfile) DenominatorBits() uint            { return p.denominatorBits }
func (p GaoA2BExpProfile) Degree() int                      { return p.degree }
func (p GaoA2BExpProfile) Basis() bignum.Basis              { return p.basis }
func (p GaoA2BExpProfile) SourceCommit() string             { return gaoA2BExpSourceCommit }
func (p GaoA2BExpProfile) Maturity() GaoA2BExpMaturity      { return GaoA2BExpPrerequisiteOnly }
func (p GaoA2BExpProfile) SecurityClaim() GaoA2BExpSecurity { return GaoA2BExpNoSecurityClaim }
func (p GaoA2BExpProfile) ArtifactDigest() string           { return p.artifactDigest }
func (p GaoA2BExpProfile) ImportDigest() string             { return p.importDigest }
func (p GaoA2BExpProfile) Digest() string                   { return p.digest }
func (p GaoA2BExpProfile) CanonicalTable() string           { return p.canonicalTable }
func (p GaoA2BExpProfile) SquaringRounds() int              { return gaoA2BExpSquaringRounds }
func (p GaoA2BExpProfile) BaseTarget() string               { return "exp(i*8*pi*x)" }
func (p GaoA2BExpProfile) FinalTarget() string              { return "exp(i*32*pi*x)=exp(i*2*pi*u)" }
func (p GaoA2BExpProfile) FreeTermConvention() string {
	return "openfhe-ps-c0-over-2;lattigo-import-c0-over-2-once"
}
func (p GaoA2BExpProfile) InputNormalization() string { return "x=u/16;u-in-[-16,16];x-in-[-1,1]" }

// CoefficientNumerators returns detached source numerators in ascending
// Chebyshev order. Both component arrays have the common denominator 2^128.
func (p GaoA2BExpProfile) CoefficientNumerators() (real, imaginary []*big.Int) {
	return cloneA2BExpBigInts(p.realNumerators), cloneA2BExpBigInts(p.imaginaryNumerators)
}

// SourceCoefficientValues returns the unmodified OpenFHE source values. Its
// c0 has not yet received the PS evaluator's free-term division by two.
func (p GaoA2BExpProfile) SourceCoefficientValues() []*bignum.Complex {
	return a2bExpDyadicValues(p.realNumerators, p.imaginaryNumerators, p.denominatorBits, p.precision)
}

// LattigoCoefficientValues returns the exact imported values: c0/2 once and
// all non-free coefficients unchanged.
func (p GaoA2BExpProfile) LattigoCoefficientValues() []*bignum.Complex {
	result := p.SourceCoefficientValues()
	if len(result) != 0 {
		two := new(big.Float).SetPrec(p.precision).SetInt64(2)
		result[0].Real().Quo(result[0].Real(), two)
		result[0].Imag().Quo(result[0].Imag(), two)
	}
	return result
}

// LattigoPolynomial returns a detached degree-46 Chebyshev polynomial over
// the normalized interval [-1,1].
func (p GaoA2BExpProfile) LattigoPolynomial() bignum.Polynomial {
	return cloneA2BExpPolynomial(p.polynomial)
}

// GaoA2BExpOracleResult separates the imported base approximation from the
// result after two pure complex squarings. All accessors return deep copies.
type GaoA2BExpOracleResult struct {
	precision             uint
	basePolynomial        *bignum.Complex
	baseTarget            *bignum.Complex
	finalPolynomial       *bignum.Complex
	finalTarget           *bignum.Complex
	baseApproximationErr  *big.Float
	finalApproximationErr *big.Float
}

func (r GaoA2BExpOracleResult) Precision() uint { return r.precision }
func (r GaoA2BExpOracleResult) BasePolynomial() *bignum.Complex {
	return cloneA2BExpComplex(r.basePolynomial)
}
func (r GaoA2BExpOracleResult) BaseTargetValue() *bignum.Complex {
	return cloneA2BExpComplex(r.baseTarget)
}
func (r GaoA2BExpOracleResult) FinalPolynomial() *bignum.Complex {
	return cloneA2BExpComplex(r.finalPolynomial)
}
func (r GaoA2BExpOracleResult) FinalTargetValue() *bignum.Complex {
	return cloneA2BExpComplex(r.finalTarget)
}
func (r GaoA2BExpOracleResult) BaseApproximationError() *big.Float {
	return cloneA2BExpFloat(r.baseApproximationErr)
}
func (r GaoA2BExpOracleResult) FinalApproximationError() *big.Float {
	return cloneA2BExpFloat(r.finalApproximationErr)
}

// EvaluateGaoA2BExpOracle evaluates the imported polynomial with an
// independent arbitrary-precision complex Clenshaw recurrence, then applies
// exactly two pure complex squarings. x is the normalized x=u/16 and must lie
// in [-1,1]. This scalar oracle makes no encrypted-evaluation claim.
func EvaluateGaoA2BExpOracle(profile GaoA2BExpProfile, x *big.Float) (GaoA2BExpOracleResult, error) {
	if x == nil {
		return GaoA2BExpOracleResult{}, fmt.Errorf("homchain: Gao A2B exponential oracle input is nil")
	}
	if err := profile.validate(); err != nil {
		return GaoA2BExpOracleResult{}, err
	}
	precision := x.Prec()
	if precision < profile.precision {
		return GaoA2BExpOracleResult{}, fmt.Errorf("homchain: Gao A2B exponential oracle precision=%d, want >=%d", precision, profile.precision)
	}
	one := new(big.Float).SetPrec(precision).SetInt64(1)
	minusOne := new(big.Float).SetPrec(precision).SetInt64(-1)
	if x.Cmp(minusOne) < 0 || x.Cmp(one) > 0 {
		return GaoA2BExpOracleResult{}, fmt.Errorf("homchain: Gao A2B exponential normalized x is outside [-1,1]")
	}

	coefficients := a2bExpDyadicValues(profile.realNumerators, profile.imaginaryNumerators, profile.denominatorBits, precision)
	two := new(big.Float).SetPrec(precision).SetInt64(2)
	coefficients[0].Real().Quo(coefficients[0].Real(), two)
	coefficients[0].Imag().Quo(coefficients[0].Imag(), two)
	base := clenshawA2BExpComplex(coefficients, new(big.Float).SetPrec(precision).Set(x), precision)
	final := cloneA2BExpComplex(base)
	for round := 0; round < profile.SquaringRounds(); round++ {
		final = squareA2BExpComplex(final, precision)
	}
	baseTarget := analyticA2BExpComplex(x, 8, precision)
	finalTarget := analyticA2BExpComplex(x, 32, precision)
	return GaoA2BExpOracleResult{
		precision: precision, basePolynomial: base, baseTarget: baseTarget,
		finalPolynomial: final, finalTarget: finalTarget,
		baseApproximationErr:  distanceA2BExpComplex(base, baseTarget, precision),
		finalApproximationErr: distanceA2BExpComplex(final, finalTarget, precision),
	}, nil
}

func (p GaoA2BExpProfile) validate() error {
	if p.precision != gaoA2BExpPrecision || p.denominatorBits != gaoA2BExpDenominatorBits ||
		p.degree != gaoA2BExpDegree || p.basis != bignum.Chebyshev ||
		len(p.realNumerators) != gaoA2BExpDegree+1 || len(p.imaginaryNumerators) != gaoA2BExpDegree+1 ||
		p.polynomial.Basis != bignum.Chebyshev || p.polynomial.Degree() != gaoA2BExpDegree ||
		p.canonicalTable != canonicalGaoA2BExpTable() || p.artifactDigest != gaoA2BExpArtifactDigest ||
		len(p.importDigest) != sha256.Size*2 || len(p.digest) != sha256.Size*2 {
		return fmt.Errorf("homchain: invalid Gao A2B exponential profile")
	}
	return nil
}

func canonicalGaoA2BExpTable() string {
	var builder strings.Builder
	for degree, row := range gaoA2BExpRows {
		fmt.Fprintf(&builder, "exp\t%d\t%s\t%s\n", degree, row.real, row.imaginary)
	}
	return builder.String()
}

func clenshawA2BExpComplex(coefficients []*bignum.Complex, x *big.Float, precision uint) *bignum.Complex {
	bNextReal := new(big.Float).SetPrec(precision)
	bNextImaginary := new(big.Float).SetPrec(precision)
	bNextNextReal := new(big.Float).SetPrec(precision)
	bNextNextImaginary := new(big.Float).SetPrec(precision)
	twoX := new(big.Float).SetPrec(precision).Add(x, x)
	for index := len(coefficients) - 1; index >= 1; index-- {
		currentReal := new(big.Float).SetPrec(precision).Mul(twoX, bNextReal)
		currentReal.Sub(currentReal, bNextNextReal)
		currentReal.Add(currentReal, coefficients[index].Real())
		currentImaginary := new(big.Float).SetPrec(precision).Mul(twoX, bNextImaginary)
		currentImaginary.Sub(currentImaginary, bNextNextImaginary)
		currentImaginary.Add(currentImaginary, coefficients[index].Imag())
		bNextNextReal, bNextReal = bNextReal, currentReal
		bNextNextImaginary, bNextImaginary = bNextImaginary, currentImaginary
	}
	resultReal := new(big.Float).SetPrec(precision).Mul(x, bNextReal)
	resultReal.Sub(resultReal, bNextNextReal)
	resultReal.Add(resultReal, coefficients[0].Real())
	resultImaginary := new(big.Float).SetPrec(precision).Mul(x, bNextImaginary)
	resultImaginary.Sub(resultImaginary, bNextNextImaginary)
	resultImaginary.Add(resultImaginary, coefficients[0].Imag())
	return &bignum.Complex{resultReal, resultImaginary}
}

func squareA2BExpComplex(value *bignum.Complex, precision uint) *bignum.Complex {
	realSquared := new(big.Float).SetPrec(precision).Mul(value.Real(), value.Real())
	imaginarySquared := new(big.Float).SetPrec(precision).Mul(value.Imag(), value.Imag())
	real := new(big.Float).SetPrec(precision).Sub(realSquared, imaginarySquared)
	imaginary := new(big.Float).SetPrec(precision).Mul(value.Real(), value.Imag())
	imaginary.Add(imaginary, imaginary)
	return &bignum.Complex{real, imaginary}
}

func analyticA2BExpComplex(x *big.Float, phaseMultiplier int64, precision uint) *bignum.Complex {
	phase := new(big.Float).SetPrec(precision).Mul(bignum.Pi(precision), x)
	phase.Mul(phase, new(big.Float).SetPrec(precision).SetInt64(phaseMultiplier))
	return &bignum.Complex{bignum.Cos(phase), bignum.Sin(phase)}
}

func distanceA2BExpComplex(left, right *bignum.Complex, precision uint) *big.Float {
	real := new(big.Float).SetPrec(precision).Sub(left.Real(), right.Real())
	imaginary := new(big.Float).SetPrec(precision).Sub(left.Imag(), right.Imag())
	real.Mul(real, real)
	imaginary.Mul(imaginary, imaginary)
	return new(big.Float).SetPrec(precision).Sqrt(new(big.Float).SetPrec(precision).Add(real, imaginary))
}

func a2bExpDyadicValues(realNumerators, imaginaryNumerators []*big.Int, denominatorBits, precision uint) []*bignum.Complex {
	result := make([]*bignum.Complex, len(realNumerators))
	for index := range result {
		result[index] = &bignum.Complex{
			a2bExpExactDyadic(realNumerators[index], denominatorBits, precision),
			a2bExpExactDyadic(imaginaryNumerators[index], denominatorBits, precision),
		}
	}
	return result
}

func a2bExpExactDyadic(numerator *big.Int, denominatorBits, precision uint) *big.Float {
	denominator := new(big.Int).Lsh(big.NewInt(1), denominatorBits)
	return new(big.Float).SetPrec(precision).Quo(
		new(big.Float).SetPrec(precision).SetInt(numerator),
		new(big.Float).SetPrec(precision).SetInt(denominator),
	)
}

func cloneA2BExpBigInts(values []*big.Int) []*big.Int {
	result := make([]*big.Int, len(values))
	for index, value := range values {
		result[index] = new(big.Int).Set(value)
	}
	return result
}

func cloneA2BExpPolynomial(value bignum.Polynomial) bignum.Polynomial {
	result := value.Clone()
	result.Interval.A = *new(big.Float).SetPrec(value.Interval.A.Prec()).Set(&value.Interval.A)
	result.Interval.B = *new(big.Float).SetPrec(value.Interval.B.Prec()).Set(&value.Interval.B)
	return result
}

func cloneA2BExpComplex(value *bignum.Complex) *bignum.Complex {
	if value == nil {
		return nil
	}
	return &bignum.Complex{
		new(big.Float).SetPrec(value.Real().Prec()).Set(value.Real()),
		new(big.Float).SetPrec(value.Imag().Prec()).Set(value.Imag()),
	}
}

func cloneA2BExpFloat(value *big.Float) *big.Float {
	if value == nil {
		return nil
	}
	return new(big.Float).SetPrec(value.Prec()).Set(value)
}

func a2bExpDigestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
