package homchain

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	gaoA2BLUTPrecision       = uint(256)
	gaoA2BLUTDenominatorBits = uint(128)
	gaoA2BLUTDegree          = 15
	gaoA2BLUTSourceCommit    = "08f1eb87434e7be072cba889270a8400bbffc08e"
	gaoA2BLUTTableDigest     = "f3aa5c55fa47acd6c5a0f96d362d442948c6b2999d3bd4a6061870d3d21564e3"
)

// GaoA2BLUTKind identifies one member of the shared-power two-LUT A2B stage.
type GaoA2BLUTKind string

const (
	// GaoA2BLUTMSB is Gao's negated-MSB convention: one on points 1..8 and
	// zero on point 0 and points 9..15.
	GaoA2BLUTMSB GaoA2BLUTKind = "msb"
	// GaoA2BLUTIdentity maps zero to zero and every other point x to
	// (x-16)/16.
	GaoA2BLUTIdentity GaoA2BLUTKind = "id"
)

type gaoA2BLUTRow struct {
	kind      GaoA2BLUTKind
	real      string
	imaginary string
}

// These signed numerators are the exact LF-normalized output of
// research/scripts/dump_a2b_lut_coefficients.cpp. Both components have
// denominator 2^128. They preserve the pinned C++ double/libm artifacts;
// they are not regenerated with Go complex arithmetic.
var gaoA2BLUTRows = [...]gaoA2BLUTRow{
	{GaoA2BLUTMSB, "85070591730234615865843651857942052864", "0"},
	{GaoA2BLUTMSB, "-19938419936773723926457657295269527552", "-100237205958731969533923198816426655744"},
	{GaoA2BLUTMSB, "-8264141345021879123968", "8690008141561076908032"},
	{GaoA2BLUTMSB, "-17279963945203911070115974653289693184", "-25861293619044044415348644517817352192"},
	{GaoA2BLUTMSB, "0", "730057365495766056960"},
	{GaoA2BLUTMSB, "-14621507953634076963125119097906397184", "-9769779268785393325822078805470085120"},
	{GaoA2BLUTMSB, "-2951479051793528258560", "21572925069424404201472"},
	{GaoA2BLUTMSB, "-11963051962064231050218056368410066944", "-2379598986860040841829089931459297280"},
	{GaoA2BLUTMSB, "0", "5209071393200155918336"},
	{GaoA2BLUTMSB, "-9304595970494404026776925117494591488", "1850799212002243559529975831779606528"},
	{GaoA2BLUTMSB, "-17708874310761169551360", "27127991331649486848"},
	{GaoA2BLUTMSB, "-6646139978924591170435242475514757120", "4440808758538804898419146864960995328"},
	{GaoA2BLUTMSB, "-15347691069326346944512", "4271832227647999442944"},
	{GaoA2BLUTMSB, "-3987683987354728138949679343554527232", "5967990835164020965835167554460450816"},
	{GaoA2BLUTMSB, "9149585060559937601536", "7509416520843664556032"},
	{GaoA2BLUTMSB, "-1329227995784938304144600691095109632", "6682480397248779000756173728020168704"},
	{GaoA2BLUTIdentity, "-79753679747094952374228423616820674560", "0"},
	{GaoA2BLUTIdentity, "9969209968386876130328277256570404864", "50118602979365994211694565147503755264"},
	{GaoA2BLUTIdentity, "9304595970494411110326649421962412032", "22463281784369660210687793850512048128"},
	{GaoA2BLUTIdentity, "8639981972601964979790953065935273984", "12930646809522012762941356519618248704"},
	{GaoA2BLUTIdentity, "7975367974709509404522290970617708544", "7975367974709497598606083796504674304"},
	{GaoA2BLUTIdentity, "7310753976817046745703904570832322560", "4884889634392688398769694380855918592"},
	{GaoA2BLUTIdentity, "6646139978924591170435242475514757120", "2752921316700591312104683454892867584"},
	{GaoA2BLUTIdentity, "5981525981032111983334166031971123200", "1189799493430021749080118272817364992"},
	{GaoA2BLUTIdentity, "5316911983139663491615228241121378304", "7734683648454484295680"},
	{GaoA2BLUTIdentity, "4652297985247208506642376504509464576", "-925399606001121779764987915889803264"},
	{GaoA2BLUTIdentity, "3987683987354759424627628354954067968", "-1651752790020348766245544414138073088"},
	{GaoA2BLUTIdentity, "3323069989462289091963707291995209728", "-2220404379269408942463487378242666496"},
	{GaoA2BLUTIdentity, "2658455991569852406160976675258499072", "-2658455991569825842849510533504172032"},
	{GaoA2BLUTIdentity, "1993841993677362003439503416307482624", "-2983995417582003399367859472762404864"},
	{GaoA2BLUTIdentity, "1329227995784911002963371600958717952", "-3209040254909952723589278461585260544"},
	{GaoA2BLUTIdentity, "664613997892459559765382016580714496", "-3341240198624386548899035070481825792"},
}

type gaoA2BLUTData struct {
	realNumerators      []*big.Int
	imaginaryNumerators []*big.Int
	polynomial          bignum.Polynomial
}

// GaoA2BLUTProfile is the immutable, exact-dyadic import of the two p=16,
// order-1 Hermite LUTs. It is a prerequisite artifact, not an encrypted A2B
// implementation or a security claim.
type GaoA2BLUTProfile struct {
	precision       uint
	denominatorBits uint
	degree          int
	canonicalTable  string
	tableDigest     string
	msb             gaoA2BLUTData
	identity        gaoA2BLUTData
}

// NewGaoA2BLUTProfile parses and authenticates the frozen C++-generated
// coefficient table and imports each component as an exact 256-bit dyadic.
func NewGaoA2BLUTProfile() (GaoA2BLUTProfile, error) {
	canonical := canonicalGaoA2BLUTTable()
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	if digest != gaoA2BLUTTableDigest {
		return GaoA2BLUTProfile{}, fmt.Errorf("homchain: Gao A2B LUT table digest mismatch: got %s, want %s", digest, gaoA2BLUTTableDigest)
	}

	msb, err := newGaoA2BLUTData(GaoA2BLUTMSB)
	if err != nil {
		return GaoA2BLUTProfile{}, err
	}
	identity, err := newGaoA2BLUTData(GaoA2BLUTIdentity)
	if err != nil {
		return GaoA2BLUTProfile{}, err
	}

	return GaoA2BLUTProfile{
		precision:       gaoA2BLUTPrecision,
		denominatorBits: gaoA2BLUTDenominatorBits,
		degree:          gaoA2BLUTDegree,
		canonicalTable:  canonical,
		tableDigest:     digest,
		msb:             msb,
		identity:        identity,
	}, nil
}

func (p GaoA2BLUTProfile) Precision() uint       { return p.precision }
func (p GaoA2BLUTProfile) DenominatorBits() uint { return p.denominatorBits }
func (p GaoA2BLUTProfile) Degree() int           { return p.degree }
func (p GaoA2BLUTProfile) SourceCommit() string  { return gaoA2BLUTSourceCommit }
func (p GaoA2BLUTProfile) TableDigest() string   { return p.tableDigest }
func (p GaoA2BLUTProfile) CanonicalTable() string {
	return p.canonicalTable
}

// Numerators returns detached real and imaginary numerator arrays for kind.
// Every returned numerator has denominator 2^128.
func (p GaoA2BLUTProfile) Numerators(kind GaoA2BLUTKind) (real, imaginary []*big.Int, err error) {
	data, err := p.data(kind)
	if err != nil {
		return nil, nil, err
	}
	return cloneA2BBigInts(data.realNumerators), cloneA2BBigInts(data.imaginaryNumerators), nil
}

// LattigoPolynomial returns a detached degree-15 monomial-basis polynomial.
func (p GaoA2BLUTProfile) LattigoPolynomial(kind GaoA2BLUTKind) (bignum.Polynomial, error) {
	data, err := p.data(kind)
	if err != nil {
		return bignum.Polynomial{}, err
	}
	return data.polynomial.Clone(), nil
}

func (p GaoA2BLUTProfile) data(kind GaoA2BLUTKind) (gaoA2BLUTData, error) {
	switch kind {
	case GaoA2BLUTMSB:
		if len(p.msb.realNumerators) != gaoA2BLUTDegree+1 {
			return gaoA2BLUTData{}, fmt.Errorf("homchain: invalid Gao A2B MSB LUT profile")
		}
		return p.msb, nil
	case GaoA2BLUTIdentity:
		if len(p.identity.realNumerators) != gaoA2BLUTDegree+1 {
			return gaoA2BLUTData{}, fmt.Errorf("homchain: invalid Gao A2B identity LUT profile")
		}
		return p.identity, nil
	default:
		return gaoA2BLUTData{}, fmt.Errorf("homchain: unknown Gao A2B LUT kind %q", kind)
	}
}

func canonicalGaoA2BLUTTable() string {
	var builder strings.Builder
	for index, row := range gaoA2BLUTRows {
		degree := index
		if row.kind == GaoA2BLUTIdentity {
			degree -= gaoA2BLUTDegree + 1
		}
		fmt.Fprintf(&builder, "%s\t%d\t%s\t%s\n", row.kind, degree, row.real, row.imaginary)
	}
	return builder.String()
}

func newGaoA2BLUTData(kind GaoA2BLUTKind) (gaoA2BLUTData, error) {
	realNumerators := make([]*big.Int, 0, gaoA2BLUTDegree+1)
	imaginaryNumerators := make([]*big.Int, 0, gaoA2BLUTDegree+1)
	coefficients := make([]*bignum.Complex, 0, gaoA2BLUTDegree+1)
	for index, row := range gaoA2BLUTRows {
		if row.kind != kind {
			continue
		}
		realNumerator, ok := new(big.Int).SetString(row.real, 10)
		if !ok {
			return gaoA2BLUTData{}, fmt.Errorf("homchain: Gao A2B %s real numerator %d is invalid", kind, index)
		}
		imaginaryNumerator, ok := new(big.Int).SetString(row.imaginary, 10)
		if !ok {
			return gaoA2BLUTData{}, fmt.Errorf("homchain: Gao A2B %s imaginary numerator %d is invalid", kind, index)
		}
		realNumerators = append(realNumerators, realNumerator)
		imaginaryNumerators = append(imaginaryNumerators, imaginaryNumerator)
		coefficients = append(coefficients, &bignum.Complex{
			a2bExactDyadic(realNumerator),
			a2bExactDyadic(imaginaryNumerator),
		})
	}
	if len(coefficients) != gaoA2BLUTDegree+1 {
		return gaoA2BLUTData{}, fmt.Errorf("homchain: Gao A2B %s LUT has %d coefficients, want %d", kind, len(coefficients), gaoA2BLUTDegree+1)
	}
	return gaoA2BLUTData{
		realNumerators:      realNumerators,
		imaginaryNumerators: imaginaryNumerators,
		polynomial:          bignum.NewPolynomial(bignum.Monomial, coefficients, nil),
	}, nil
}

func a2bExactDyadic(numerator *big.Int) *big.Float {
	denominator := new(big.Int).Lsh(big.NewInt(1), gaoA2BLUTDenominatorBits)
	return new(big.Float).SetPrec(gaoA2BLUTPrecision).Quo(
		new(big.Float).SetPrec(gaoA2BLUTPrecision).SetInt(numerator),
		new(big.Float).SetPrec(gaoA2BLUTPrecision).SetInt(denominator),
	)
}

func cloneA2BBigInts(values []*big.Int) []*big.Int {
	result := make([]*big.Int, len(values))
	for index, value := range values {
		result[index] = new(big.Int).Set(value)
	}
	return result
}
