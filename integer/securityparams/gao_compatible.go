// Package securityparams defines exact CKKS parameter candidates and their
// fail-closed evidence manifests. A manifest is parameter evidence only; it
// does not promote a circuit or a security claim.
package securityparams

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

const (
	GaoCompatibleTupleID       = "lattigo-gao-compatible-n16-v1"
	GaoCompatibleSchemaVersion = "ckks-security-parameter-manifest-v1"
	GaoCompatibleLogN          = 16
	GaoCompatibleMainWeight    = 192
	GaoCompatibleEphemeralH    = 32
	GaoCompatibleSigma         = 3.2
	GaoCompatibleBound         = 19.2
	GaoCompatibleDefaultScale  = 43
	GaoOpenFHEFullSigma        = 3.19
	GaoOpenFHEFullBound        = 39.0
	// GaoCompatibleManifestDigest authenticates the canonical parameter-only
	// manifest before runtime key evidence is attached.
	GaoCompatibleManifestDigest = "e2dc7b14f041589be98f27f0634dab1bc77b910babcc9a8c7775f81d498b3f3d"

	FunctionalA2BTupleID        = "lattigo-functional-a2b-n8-v1"
	FunctionalA2BSchemaVersion  = GaoCompatibleSchemaVersion
	FunctionalA2BManifestDigest = "d01835f4e15c2426d8f5c77667b93d30e7563ac37d4533f8b61685e412e463d5"
)

// These ordered RNS chains are the values emitted by the pinned OpenFHE
// 08f1eb87434e7be072cba889270a8400bbffc08e full-packed Gao benchmark.
// Keeping the values, rather than only their aggregate bit lengths, makes the
// Lattigo/OpenFHE performance comparison use the same numerical modulus tuple.
var gaoOpenFHEFullQ = []uint64{
	8796103114753, 8796120416257, 8796142305281, 8796131819521,
	8796137586689, 8796135227393, 8796142043137, 8796136144897,
	8796141649921, 8796137717761, 8796139159553, 8796122644481,
	8796134178817, 8796123824129, 8796130508801, 8796087386113,
	8796114124801, 8796110192641, 8796112814081, 8796090007553,
	8796105342977,
}

var gaoOpenFHEFullP = []uint64{
	1125899903827969, 1125899902124033, 1125899887312897,
	1125899886395393, 1125899885740033, 1125899884167169,
	1125899884036097,
}

// PrimeRecord is an ordered, lossless record of one RNS prime.
type PrimeRecord struct {
	Decimal string `json:"decimal"`
	Hex     string `json:"hex"`
	BitLen  int    `json:"bit_length"`
}

// ProductRecord authenticates an exact modulus product.
type ProductRecord struct {
	Decimal     string `json:"decimal"`
	Hex         string `json:"hex"`
	BitLen      int    `json:"bit_length"`
	SHA256ASCII string `json:"sha256_decimal_ascii"`
}

// DistributionRecord preserves the exact distribution declaration used by
// the candidate or planned bootstrapping secret.
type DistributionRecord struct {
	Type        string  `json:"type"`
	Weight      int     `json:"weight,omitempty"`
	Probability float64 `json:"nonzero_probability,omitempty"`
	Sigma       float64 `json:"sigma,omitempty"`
	Bound       float64 `json:"bound,omitempty"`
}

// ParameterManifest is deliberately ineligible for an estimator PASS until
// the actual evaluator-key inventory and sample exposures are attached.
type ParameterManifest struct {
	SchemaVersion       string             `json:"schema_version"`
	TupleID             string             `json:"tuple_id"`
	Status              string             `json:"status"`
	Provenance          string             `json:"provenance"`
	RingType            string             `json:"ring_type"`
	LogN                int                `json:"log_n"`
	N                   int                `json:"n"`
	MaxSlots            int                `json:"max_slots"`
	LogDefaultScale     int                `json:"log_default_scale"`
	Q                   []PrimeRecord      `json:"q"`
	P                   []PrimeRecord      `json:"p"`
	QProduct            ProductRecord      `json:"q_product"`
	PProduct            ProductRecord      `json:"p_product"`
	QPProduct           ProductRecord      `json:"qp_product"`
	MainSecret          DistributionRecord `json:"main_secret"`
	EphemeralSecret     DistributionRecord `json:"ephemeral_secret"`
	Error               DistributionRecord `json:"error"`
	EstimatorEligible   bool               `json:"estimator_eligible"`
	MissingEvidence     []string           `json:"missing_evidence"`
	CanonicalJSONSHA256 string             `json:"canonical_json_sha256"`
}

// GaoCompatibleN16Parameters returns a deterministic independent Lattigo
// candidate matching the Gao paper's aggregate ring/scale/depth/weight record.
// It does not claim prime-for-prime OpenFHE fidelity.
func GaoCompatibleN16Parameters() (ckks.Parameters, error) {
	logQ := make([]int, 21)
	for i := range logQ {
		logQ[i] = 43
	}
	logP := make([]int, 7)
	for i := range logP {
		logP[i] = 50
	}

	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            GaoCompatibleLogN,
		LogQ:            logQ,
		LogP:            logP,
		Xs:              ring.Ternary{H: GaoCompatibleMainWeight},
		Xe:              ring.DiscreteGaussian{Sigma: GaoCompatibleSigma, Bound: GaoCompatibleBound},
		RingType:        ring.Standard,
		LogDefaultScale: GaoCompatibleDefaultScale,
	})
}

// GaoOpenFHEFullN16Parameters returns the independent Lattigo parameter tuple
// used for the Gao/OpenFHE full-packed benchmark. It uses the exact ordered
// Q/P chains emitted by the pinned OpenFHE build, along with the matching
// H=192 secret and sigma=3.19/effective-bound=39 error profile.
func GaoOpenFHEFullN16Parameters() (ckks.Parameters, error) {
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            GaoCompatibleLogN,
		Q:               append([]uint64(nil), gaoOpenFHEFullQ...),
		P:               append([]uint64(nil), gaoOpenFHEFullP...),
		Xs:              ring.Ternary{H: GaoCompatibleMainWeight},
		Xe:              ring.DiscreteGaussian{Sigma: GaoOpenFHEFullSigma, Bound: GaoOpenFHEFullBound},
		RingType:        ring.Standard,
		LogDefaultScale: GaoCompatibleDefaultScale,
	})
}

// FunctionalA2BN8Parameters reproduces the parameter literal used by the
// accepted fixed n=8 A2B circuit. It is intentionally insecure.
func FunctionalA2BN8Parameters() (ckks.Parameters, error) {
	logQ := make([]int, 21)
	logQ[0] = 50
	for i := 1; i < len(logQ); i++ {
		logQ[i] = 35
	}
	return ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            5,
		LogQ:            logQ,
		LogP:            []int{50},
		Xs:              ring.Ternary{P: 2 / 3.0},
		Xe:              ring.DiscreteGaussian{Sigma: GaoCompatibleSigma, Bound: GaoCompatibleBound},
		RingType:        ring.Standard,
		LogDefaultScale: 35,
	})
}

// FunctionalA2BN8Manifest records the exact deliberately insecure diagnostic
// tuple used to test that estimator decisions do not default to PASS.
func FunctionalA2BN8Manifest() (ParameterManifest, error) {
	params, err := FunctionalA2BN8Parameters()
	if err != nil {
		return ParameterManifest{}, fmt.Errorf("securityparams: construct functional A2B parameters: %w", err)
	}
	manifest := ParameterManifest{
		SchemaVersion:   FunctionalA2BSchemaVersion,
		TupleID:         FunctionalA2BTupleID,
		Status:          "FUNCTIONAL-NOT-SECURE",
		Provenance:      "accepted-fixed-n8-functional-circuit-parameter-profile",
		RingType:        "Standard",
		LogN:            params.LogN(),
		N:               params.N(),
		MaxSlots:        params.MaxSlots(),
		LogDefaultScale: params.LogDefaultScale(),
		Q:               primeRecords(params.Q()),
		P:               primeRecords(params.P()),
		QProduct:        productRecord(params.QBigInt()),
		PProduct:        productRecord(params.PBigInt()),
		QPProduct:       productRecord(params.QPBigInt()),
		MainSecret: DistributionRecord{
			Type: "iid-ternary", Probability: 2 / 3.0,
		},
		EphemeralSecret: DistributionRecord{Type: "not-instantiated-in-dense-functional-profile"},
		Error: DistributionRecord{
			Type: "bounded-discrete-gaussian", Sigma: GaoCompatibleSigma, Bound: GaoCompatibleBound,
		},
		EstimatorEligible: false,
		MissingEvidence: []string{
			"secure-ring-dimension",
			"secure-circuit-profile",
			"evaluation-key-inventory",
			"finite-rlwe-sample-exposures",
		},
	}
	canonical, err := canonicalJSONWithoutDigest(manifest)
	if err != nil {
		return ParameterManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	manifest.CanonicalJSONSHA256 = hex.EncodeToString(digest[:])
	if manifest.CanonicalJSONSHA256 != FunctionalA2BManifestDigest {
		return ParameterManifest{}, fmt.Errorf("securityparams: functional A2B manifest drifted: got %s, want %s", manifest.CanonicalJSONSHA256, FunctionalA2BManifestDigest)
	}
	return manifest, nil
}

// GaoCompatibleN16Manifest returns the exact prime/product manifest for the
// candidate. It remains estimator-ineligible until runtime key evidence is
// attached by a later bundle layer.
func GaoCompatibleN16Manifest() (ParameterManifest, error) {
	params, err := GaoCompatibleN16Parameters()
	if err != nil {
		return ParameterManifest{}, fmt.Errorf("securityparams: construct Gao-compatible parameters: %w", err)
	}

	manifest := ParameterManifest{
		SchemaVersion:   GaoCompatibleSchemaVersion,
		TupleID:         GaoCompatibleTupleID,
		Status:          "PENDING-IMPLEMENTATION/PENDING-ESTIMATOR",
		Provenance:      "independent-lattigo-candidate;aggregate-compatible-not-openfhe-prime-identical",
		RingType:        "Standard",
		LogN:            params.LogN(),
		N:               params.N(),
		MaxSlots:        params.MaxSlots(),
		LogDefaultScale: params.LogDefaultScale(),
		Q:               primeRecords(params.Q()),
		P:               primeRecords(params.P()),
		QProduct:        productRecord(params.QBigInt()),
		PProduct:        productRecord(params.PBigInt()),
		QPProduct:       productRecord(params.QPBigInt()),
		MainSecret: DistributionRecord{
			Type: "balanced-sparse-ternary", Weight: GaoCompatibleMainWeight,
		},
		EphemeralSecret: DistributionRecord{
			Type: "balanced-sparse-ternary", Weight: GaoCompatibleEphemeralH,
		},
		Error: DistributionRecord{
			Type: "bounded-discrete-gaussian", Sigma: GaoCompatibleSigma, Bound: GaoCompatibleBound,
		},
		EstimatorEligible: false,
		MissingEvidence: []string{
			"accepted-secure-circuit-profile",
			"evaluation-key-inventory",
			"finite-rlwe-sample-exposures",
			"bootstrapping-secret-switch-profile",
			"classical-and-quantum-estimator-transcripts",
		},
	}

	canonical, err := canonicalJSONWithoutDigest(manifest)
	if err != nil {
		return ParameterManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	manifest.CanonicalJSONSHA256 = hex.EncodeToString(digest[:])
	if manifest.CanonicalJSONSHA256 != GaoCompatibleManifestDigest {
		return ParameterManifest{}, fmt.Errorf("securityparams: Gao-compatible manifest drifted: got %s, want %s", manifest.CanonicalJSONSHA256, GaoCompatibleManifestDigest)
	}
	return manifest, nil
}

// CanonicalJSON serializes a manifest with stable struct-field and array order.
func CanonicalJSON(manifest ParameterManifest) ([]byte, error) {
	if manifest.CanonicalJSONSHA256 == "" {
		return nil, fmt.Errorf("securityparams: manifest digest is empty")
	}
	withoutDigest, err := canonicalJSONWithoutDigest(manifest)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(withoutDigest)
	if got := hex.EncodeToString(digest[:]); got != manifest.CanonicalJSONSHA256 {
		return nil, fmt.Errorf("securityparams: manifest digest mismatch: got %s, want %s", got, manifest.CanonicalJSONSHA256)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("securityparams: marshal canonical manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func canonicalJSONWithoutDigest(manifest ParameterManifest) ([]byte, error) {
	manifest.CanonicalJSONSHA256 = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("securityparams: marshal manifest for digest: %w", err)
	}
	return encoded, nil
}

func primeRecords(primes []uint64) []PrimeRecord {
	records := make([]PrimeRecord, len(primes))
	for i, prime := range primes {
		records[i] = PrimeRecord{
			Decimal: new(big.Int).SetUint64(prime).String(),
			Hex:     fmt.Sprintf("0x%x", prime),
			BitLen:  bits.Len64(prime),
		}
	}
	return records
}

func productRecord(product *big.Int) ProductRecord {
	decimal := product.String()
	digest := sha256.Sum256([]byte(decimal))
	return ProductRecord{
		Decimal:     decimal,
		Hex:         fmt.Sprintf("0x%x", product),
		BitLen:      product.BitLen(),
		SHA256ASCII: hex.EncodeToString(digest[:]),
	}
}
