package secureeval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/nc26676027/LCPDTE/integer/securityparams"
)

const (
	routeBApplicationSecurityProfileSchema = "lcpdte-route-b-application-security-profile-v1"
	routeBApplicationSecurityProfileDigest = "49db539532bd31000918b8417bcd36a80412c9062e9435e6e3e0d0a125fadefb"

	routeBC75ArtifactSHA256 = "4a7fbd447dc8e127ff5392c3b3f22bf4a9f420edf4c30622445db76e965abbb2"
	routeBC75ReportDigest   = "93876cd488dc3b9b7d9e1535ceec34c82a80a537391a2240fd52b31ca5036d1d"

	routeBMainEstimatorTranscriptSHA256      = "690a66c23ddcdc778da4e2f5ce7b02b028db5e8bb26efa8e3d197c039956db02"
	routeBEphemeralEstimatorTranscriptSHA256 = "22c47027e866843fdedadbd59d5390d350cbefcc697340f4ab9e26495eee5bf6"
	routeBEstimatorCommit                    = "53da5982597709ba0fdf94ea37a84d822310fd84"
	routeBEstimatorTree                      = "7cb765baf3bb401580c08f678dcee8c6f35e66d1"
)

type RouteBApplicationSecurityStatus string

const (
	RouteBSecurityFail            RouteBApplicationSecurityStatus = "FAIL"
	RouteBSecurityInconclusive    RouteBApplicationSecurityStatus = "INCONCLUSIVE"
	RouteBSecurityConditionalPass RouteBApplicationSecurityStatus = "CONDITIONAL-PASS"
	// RouteBSecurityPass exists only so deserialization and mutation tests can
	// reject an unconditional promotion that this evidence cannot support.
	RouteBSecurityPass RouteBApplicationSecurityStatus = "PASS"
)

type RouteBSecurityBoundCircuit struct {
	CircuitID               string `json:"circuit_id"`
	ArtifactSHA256          string `json:"artifact_sha256"`
	ReportDigest            string `json:"report_digest"`
	ParameterTuple          string `json:"parameter_tuple"`
	ParameterManifestDigest string `json:"parameter_manifest_digest"`
	PreparedDigest          string `json:"prepared_parameter_digest"`
	InputCiphertexts        int    `json:"fresh_symmetric_input_ciphertexts"`
	PublicKeys              int    `json:"generated_public_keys"`
}

type RouteBSecurityModulusRecord struct {
	ID                  string `json:"id"`
	BitLength           int    `json:"bit_length"`
	DecimalASCII_SHA256 string `json:"sha256_decimal_ascii"`
}

type RouteBSecurityModuli struct {
	FullQ  RouteBSecurityModulusRecord `json:"full_q"`
	FullQP RouteBSecurityModulusRecord `json:"full_qp"`
	Q0P0   RouteBSecurityModulusRecord `json:"q0_p0"`
}

type RouteBEvaluationKeyExposure struct {
	Class             string `json:"class"`
	KeyCount          int    `json:"key_count"`
	InputSecret       string `json:"input_secret_or_message"`
	OutputSecret      string `json:"output_encryption_secret"`
	ModulusID         string `json:"modulus_id"`
	LevelQ            int    `json:"level_q"`
	LevelP            int    `json:"level_p"`
	BaseRNSRows       int    `json:"base_rns_rows"`
	BaseTwoColumns    []int  `json:"base_two_columns"`
	RingSamplesPerKey int    `json:"ring_rlwe_samples_per_key"`
	TotalRingSamples  int    `json:"total_ring_rlwe_samples"`
	AssumptionClass   string `json:"assumption_class"`
}

type RouteBSecurityExposureTotals struct {
	EvaluationKeys               int    `json:"evaluation_keys"`
	EvaluationKeyRingSamples     int    `json:"evaluation_key_ring_rlwe_samples"`
	InputCiphertextRingSamples   int    `json:"input_ciphertext_ring_rlwe_samples"`
	TotalFreshRingSamples        int    `json:"total_fresh_ring_rlwe_samples"`
	MainSecretRingSamples        int    `json:"main_secret_ring_rlwe_samples"`
	MainSecretFullQSamples       int    `json:"main_secret_full_q_samples"`
	MainSecretFullQPSamples      int    `json:"main_secret_full_qp_samples"`
	EphemeralSecretRingSamples   int    `json:"ephemeral_secret_ring_rlwe_samples"`
	EphemeralSecretQ0P0Samples   int    `json:"ephemeral_secret_q0p0_samples"`
	RingSampleCountingConvention string `json:"ring_sample_counting_convention"`
}

type RouteBSecurityEstimatorEvidence struct {
	EstimatorCommit                     string `json:"estimator_commit"`
	EstimatorTree                       string `json:"estimator_tree"`
	MainTranscriptSHA256                string `json:"main_transcript_sha256"`
	EphemeralTranscriptSHA256           string `json:"ephemeral_transcript_sha256"`
	MainClassicalMinimumBits            string `json:"main_classical_minimum_bits"`
	MainQuantumMinimumBits              string `json:"main_quantum_minimum_bits"`
	EphemeralClassicalMinimumBits       string `json:"ephemeral_classical_minimum_bits"`
	EphemeralQuantumMinimumBits         string `json:"ephemeral_quantum_minimum_bits"`
	NegativeControlClassicalMinimumBits string `json:"negative_control_classical_minimum_bits"`
	NegativeControlQuantumMinimumBits   string `json:"negative_control_quantum_minimum_bits"`
	SampleModel                         string `json:"sample_model"`
	Interpretation                      string `json:"interpretation"`
}

type RouteBSecuritySourceBindings struct {
	BootstrappingKeysGoSHA256 string `json:"bootstrapping_keys_go_sha256"`
	KeyGeneratorGoSHA256      string `json:"keygenerator_go_sha256"`
	GadgetCiphertextGoSHA256  string `json:"gadgetciphertext_go_sha256"`
	RLWEParametersGoSHA256    string `json:"rlwe_parameters_go_sha256"`
}

type RouteBSecurityDecision struct {
	Status                   RouteBApplicationSecurityStatus `json:"status"`
	ClassicalThresholdBits   int                             `json:"classical_threshold_bits"`
	Unconditional128BitClaim bool                            `json:"unconditional_128_bit_claim"`
	Reason                   string                          `json:"reason"`
}

type RouteBApplicationSecurityProfile struct {
	SchemaVersion       string                          `json:"schema_version"`
	BoundCircuit        RouteBSecurityBoundCircuit      `json:"bound_circuit"`
	Moduli              RouteBSecurityModuli            `json:"moduli"`
	GaloisElements      []uint64                        `json:"galois_elements"`
	KeyClasses          []RouteBEvaluationKeyExposure   `json:"evaluation_key_classes"`
	Totals              RouteBSecurityExposureTotals    `json:"exposure_totals"`
	Estimator           RouteBSecurityEstimatorEvidence `json:"estimator"`
	SourceBindings      RouteBSecuritySourceBindings    `json:"source_bindings"`
	Assumptions         []string                        `json:"required_assumptions"`
	OutOfScope          []string                        `json:"not_established"`
	Decision            RouteBSecurityDecision          `json:"decision"`
	CanonicalJSONSHA256 string                          `json:"canonical_json_sha256"`
}

func NewRouteBApplicationSecurityProfile() (RouteBApplicationSecurityProfile, error) {
	profile, err := newRouteBApplicationSecurityProfile()
	if err != nil {
		return RouteBApplicationSecurityProfile{}, err
	}
	if routeBApplicationSecurityProfileDigest != "" && profile.CanonicalJSONSHA256 != routeBApplicationSecurityProfileDigest {
		return RouteBApplicationSecurityProfile{}, lineagef(
			"Route-B application-security profile drifted: got %s, want %s",
			profile.CanonicalJSONSHA256, routeBApplicationSecurityProfileDigest,
		)
	}
	return profile, nil
}

func newRouteBApplicationSecurityProfile() (RouteBApplicationSecurityProfile, error) {
	prepared, _, err := prepareGaoN16RouteBTransportParameters()
	if err != nil {
		return RouteBApplicationSecurityProfile{}, err
	}
	parameters := prepared.EffectiveParameters().BootstrappingParameters
	manifest, err := securityparams.GaoCompatibleN16Manifest()
	if err != nil {
		return RouteBApplicationSecurityProfile{}, err
	}
	keys, err := routeBExpectedEvaluationGaloisKeys()
	if err != nil {
		return RouteBApplicationSecurityProfile{}, err
	}
	galois := append([]uint64(nil), keys[:]...)

	q0p0 := new(big.Int).SetUint64(parameters.Q()[0])
	q0p0.Mul(q0p0, new(big.Int).SetUint64(parameters.P()[0]))
	full := RouteBEvaluationKeyExposure{
		ModulusID: "QP", LevelQ: 20, LevelP: 6, BaseRNSRows: 3,
		BaseTwoColumns: []int{1, 1, 1}, RingSamplesPerKey: 3,
	}
	keyClasses := []RouteBEvaluationKeyExposure{
		{
			Class: "galois", KeyCount: 38, InputSecret: "automorphism(main-h192)", OutputSecret: "main-h192",
			ModulusID: full.ModulusID, LevelQ: full.LevelQ, LevelP: full.LevelP,
			BaseRNSRows: full.BaseRNSRows, BaseTwoColumns: append([]int(nil), full.BaseTwoColumns...),
			RingSamplesPerKey: full.RingSamplesPerKey, TotalRingSamples: 114,
			AssumptionClass: "RLWE plus key-dependent-message/circular security",
		},
		{
			Class: "relinearization", KeyCount: 1, InputSecret: "main-h192 squared", OutputSecret: "main-h192",
			ModulusID: full.ModulusID, LevelQ: full.LevelQ, LevelP: full.LevelP,
			BaseRNSRows: full.BaseRNSRows, BaseTwoColumns: append([]int(nil), full.BaseTwoColumns...),
			RingSamplesPerKey: full.RingSamplesPerKey, TotalRingSamples: 3,
			AssumptionClass: "RLWE plus key-dependent-message/circular security",
		},
		{
			Class: "dense-to-sparse", KeyCount: 1, InputSecret: "main-h192", OutputSecret: "ephemeral-h32",
			ModulusID: "Q[0]P[0]", LevelQ: 0, LevelP: 0, BaseRNSRows: 1,
			BaseTwoColumns: []int{1}, RingSamplesPerKey: 1, TotalRingSamples: 1,
			AssumptionClass: "RLWE plus cross-key key-dependent-message security",
		},
		{
			Class: "sparse-to-dense", KeyCount: 1, InputSecret: "ephemeral-h32", OutputSecret: "main-h192",
			ModulusID: full.ModulusID, LevelQ: full.LevelQ, LevelP: full.LevelP,
			BaseRNSRows: full.BaseRNSRows, BaseTwoColumns: append([]int(nil), full.BaseTwoColumns...),
			RingSamplesPerKey: full.RingSamplesPerKey, TotalRingSamples: 3,
			AssumptionClass: "RLWE plus cross-key key-dependent-message security",
		},
	}
	profile := RouteBApplicationSecurityProfile{
		SchemaVersion: routeBApplicationSecurityProfileSchema,
		BoundCircuit: RouteBSecurityBoundCircuit{
			CircuitID: "C75-route-b-signed8-depth2-selected-child", ArtifactSHA256: routeBC75ArtifactSHA256,
			ReportDigest: routeBC75ReportDigest, ParameterTuple: securityparams.GaoCompatibleTupleID,
			ParameterManifestDigest: manifest.CanonicalJSONSHA256,
			PreparedDigest:          gaoN16RouteBPreparedDigestHex, InputCiphertexts: 3, PublicKeys: 0,
		},
		Moduli: RouteBSecurityModuli{
			FullQ:  routeBSecurityModulusRecord("Q", parameters.QBigInt()),
			FullQP: routeBSecurityModulusRecord("QP", parameters.QPBigInt()),
			Q0P0:   routeBSecurityModulusRecord("Q[0]P[0]", q0p0),
		},
		GaloisElements: galois,
		KeyClasses:     keyClasses,
		Totals: RouteBSecurityExposureTotals{
			EvaluationKeys: 41, EvaluationKeyRingSamples: 121, InputCiphertextRingSamples: 3,
			TotalFreshRingSamples: 124, MainSecretRingSamples: 123, MainSecretFullQSamples: 3,
			MainSecretFullQPSamples: 120, EphemeralSecretRingSamples: 1, EphemeralSecretQ0P0Samples: 1,
			RingSampleCountingConvention: "one gadget matrix cell or fresh symmetric ciphertext equals one structured ring-RLWE sample; it is not silently multiplied by N",
		},
		Estimator: RouteBSecurityEstimatorEvidence{
			EstimatorCommit: routeBEstimatorCommit, EstimatorTree: routeBEstimatorTree,
			MainTranscriptSHA256:      routeBMainEstimatorTranscriptSHA256,
			EphemeralTranscriptSHA256: routeBEphemeralEstimatorTranscriptSHA256,
			MainClassicalMinimumBits:  "150.672", MainQuantumMinimumBits: "136.740",
			EphemeralClassicalMinimumBits: "+Infinity", EphemeralQuantumMinimumBits: "+Infinity",
			NegativeControlClassicalMinimumBits: "11.680", NegativeControlQuantumMinimumBits: "10.600",
			SampleModel:    "conservative unlimited-sample coefficient-embedding LWE sensitivity with n=N",
			Interpretation: "selected Core-SVP attack sensitivity, not a protocol or KDM/circular-security proof",
		},
		SourceBindings: RouteBSecuritySourceBindings{
			BootstrappingKeysGoSHA256: "e8062116044d9566bf51abb4411e39d1fb49d723d97f7e6f46ac2689fe439a1d",
			KeyGeneratorGoSHA256:      "1aae99164d242f18f578ab1c8ac28816940ba54a5e7f29a69dafb72fe59e7e68",
			GadgetCiphertextGoSHA256:  "de2ecb0ffff1bf310016f6ef0fafd0aa8cdc8cc5c967da95f97bf1cae84d0482",
			RLWEParametersGoSHA256:    "4728c5e616ab33a06cef7459f219a9e506695ef60fad45d3726f04549f26bfcd",
		},
		Assumptions: []string{
			"decisional sparse-secret RLWE for the exact main and ephemeral modulus/distribution roles",
			"key-dependent-message and circular security for Galois and relinearization keys",
			"cross-key key-dependent-message security for dense/sparse switching keys",
			"honest parameter, secret-key, error, and evaluation-key generation",
			"semi-honest public-model evaluation with no leakage outside the declared ciphertext interface",
		},
		OutOfScope: []string{
			"unconditional 128-bit protocol security",
			"a proof of key-dependent-message or circular security",
			"malicious security, side-channel resistance, and implementation leakage",
			"private-model security beyond the public-model C75 circuit",
			"a formal CKKS decryption-failure bound for the complete application",
		},
		Decision: RouteBSecurityDecision{
			Status: RouteBSecurityConditionalPass, ClassicalThresholdBits: 128, Unconditional128BitClaim: false,
			Reason: "both authenticated unlimited-sample secret-role sensitivities meet the classical threshold, the negative control fails, and the exact C75 key/sample inventory is bound; the promotion remains conditional on the enumerated RLWE/KDM/circular/cross-key assumptions",
		},
	}
	profile.CanonicalJSONSHA256, err = digestRouteBApplicationSecurityProfile(profile)
	if err != nil {
		return RouteBApplicationSecurityProfile{}, err
	}
	return profile, nil
}

func (profile RouteBApplicationSecurityProfile) Validate() error {
	expected, err := newRouteBApplicationSecurityProfile()
	if err != nil {
		return err
	}
	if routeBApplicationSecurityProfileDigest != "" && profile.CanonicalJSONSHA256 != routeBApplicationSecurityProfileDigest {
		return lineagef("Route-B application-security profile digest changed")
	}
	if !reflect.DeepEqual(profile, expected) {
		return lineagef("Route-B application-security profile differs from the exact C75 exposure and decision record")
	}
	return nil
}

func CanonicalRouteBApplicationSecurityProfileJSON(profile RouteBApplicationSecurityProfile) ([]byte, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("secureeval: marshal Route-B application-security profile: %w", err)
	}
	return append(payload, '\n'), nil
}

func routeBSecurityModulusRecord(id string, value *big.Int) RouteBSecurityModulusRecord {
	decimal := value.String()
	digest := sha256.Sum256([]byte(decimal))
	return RouteBSecurityModulusRecord{ID: id, BitLength: value.BitLen(), DecimalASCII_SHA256: hex.EncodeToString(digest[:])}
}

func digestRouteBApplicationSecurityProfile(profile RouteBApplicationSecurityProfile) (string, error) {
	profile.CanonicalJSONSHA256 = ""
	payload, err := json.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("secureeval: digest Route-B application-security profile: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
