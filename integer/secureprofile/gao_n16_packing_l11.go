package secureprofile

import (
	"errors"
	"math/bits"
	"sort"
)

const (
	gaoN16PackingL11ProfileSchema = "gao-n16-lattigo-packing-l11-profile-v1"
	gaoN16PackingL11ShapeSchema   = "gao-n16-lattigo-packing-l11-capacity-shape-v1"
	gaoN16PackingL11PlanSchema    = "gao-n16-lattigo-packing-l11-capacity-plan-v1"
	gaoN16PackingL11ProbeSchema   = "gao-n16-lattigo-packing-l11-capacity-probe-v1"
	gaoN16PackingL11ReportSchema  = "gao-n16-lattigo-packing-l11-capacity-report-v1"
	gaoN16PackingL11PermitSchema  = "gao-n16-lattigo-packing-l11-capacity-permit-v1"

	gaoN16PackingL11AdaptationLabel = "lattigo_packing_adaptation_r1"
	gaoN16PackingL11EvidenceScope   = "capacity_only"
)

// GaoN16PackingL11Profile binds the exact Gao-compatible N/Q/P/S/H/h tuple to
// the first reduced-packing admission gate. It is a capacity-only Lattigo
// adaptation and cannot claim the paper's full-packed execution result.
type GaoN16PackingL11Profile struct {
	schema                                  string
	adaptationLabel, evidenceScope          string
	maturity                                Maturity
	sourceFaithful, fullPacked              bool
	parameterDigest, baseProfileDigest      string
	logN, logSlots, slots                   uint64
	wordBits, wordCapacity, sparseDenseGap  uint64
	traceRotations                          []uint64
	traceGaloisElements                     []uint64
	qCount, pCount, logDefaultScale         uint64
	mainSecretWeight, ephemeralSecretWeight uint64
	digest                                  string
}

func NewGaoN16PackingL11Profile() (GaoN16PackingL11Profile, error) {
	profile := GaoN16PackingL11Profile{
		schema:                gaoN16PackingL11ProfileSchema,
		adaptationLabel:       gaoN16PackingL11AdaptationLabel,
		evidenceScope:         gaoN16PackingL11EvidenceScope,
		maturity:              ArtifactCapacityOnlyUnverified,
		sourceFaithful:        false,
		fullPacked:            false,
		parameterDigest:       gaoN16ExpectedParameterDigest,
		baseProfileDigest:     gaoN16ExpectedProfileDigest,
		logN:                  16,
		logSlots:              11,
		slots:                 2048,
		wordBits:              8,
		wordCapacity:          512,
		sparseDenseGap:        16,
		traceRotations:        []uint64{2048, 4096, 8192, 16384},
		qCount:                21,
		pCount:                7,
		logDefaultScale:       43,
		mainSecretWeight:      192,
		ephemeralSecretWeight: 32,
	}
	var err error
	profile.traceGaloisElements, err = gaoN16PackingL11GaloisElements(profile.traceRotations, 1<<profile.logN)
	if err != nil {
		return GaoN16PackingL11Profile{}, artifactCapacityBlocked("cannot derive L11 Trace Galois elements", err)
	}
	profile.digest, err = digestGaoN16PackingL11Profile(profile)
	if err != nil {
		return GaoN16PackingL11Profile{}, err
	}
	return profile, nil
}

func (p GaoN16PackingL11Profile) SchemaVersion() string     { return p.schema }
func (p GaoN16PackingL11Profile) AdaptationLabel() string   { return p.adaptationLabel }
func (p GaoN16PackingL11Profile) EvidenceScope() string     { return p.evidenceScope }
func (p GaoN16PackingL11Profile) Maturity() Maturity        { return p.maturity }
func (p GaoN16PackingL11Profile) IsSourceFaithful() bool    { return p.sourceFaithful }
func (p GaoN16PackingL11Profile) IsFullPacked() bool        { return p.fullPacked }
func (p GaoN16PackingL11Profile) ParameterDigest() string   { return p.parameterDigest }
func (p GaoN16PackingL11Profile) BaseProfileDigest() string { return p.baseProfileDigest }
func (p GaoN16PackingL11Profile) LogN() uint64              { return p.logN }
func (p GaoN16PackingL11Profile) LogSlots() uint64          { return p.logSlots }
func (p GaoN16PackingL11Profile) Slots() uint64             { return p.slots }
func (p GaoN16PackingL11Profile) WordBits() uint64          { return p.wordBits }
func (p GaoN16PackingL11Profile) WordCapacity() uint64      { return p.wordCapacity }
func (p GaoN16PackingL11Profile) SparseDenseGap() uint64    { return p.sparseDenseGap }
func (p GaoN16PackingL11Profile) QCount() uint64            { return p.qCount }
func (p GaoN16PackingL11Profile) PCount() uint64            { return p.pCount }
func (p GaoN16PackingL11Profile) LogDefaultScale() uint64   { return p.logDefaultScale }
func (p GaoN16PackingL11Profile) Digest() string            { return p.digest }
func (p GaoN16PackingL11Profile) TraceRotations() []uint64 {
	return append([]uint64(nil), p.traceRotations...)
}
func (p GaoN16PackingL11Profile) TraceGaloisElements() []uint64 {
	return append([]uint64(nil), p.traceGaloisElements...)
}

type gaoN16PackingL11ProfileDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope string
	Maturity                                      Maturity
	SourceFaithful, FullPacked                    bool
	ParameterDigest, BaseProfileDigest            string
	LogN, LogSlots, Slots, WordBits, WordCapacity uint64
	SparseDenseGap                                uint64
	TraceRotations                                []uint64
	TraceGaloisElements                           []uint64
	QCount, PCount, LogDefaultScale               uint64
	MainSecretWeight, EphemeralSecretWeight       uint64
}

func digestGaoN16PackingL11Profile(profile GaoN16PackingL11Profile) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11ProfileDigestRecord{
		SchemaVersion: profile.schema, AdaptationLabel: profile.adaptationLabel,
		EvidenceScope: profile.evidenceScope, Maturity: profile.maturity,
		SourceFaithful: profile.sourceFaithful, FullPacked: profile.fullPacked,
		ParameterDigest: profile.parameterDigest, BaseProfileDigest: profile.baseProfileDigest,
		LogN: profile.logN, LogSlots: profile.logSlots, Slots: profile.slots,
		WordBits: profile.wordBits, WordCapacity: profile.wordCapacity,
		SparseDenseGap: profile.sparseDenseGap, TraceRotations: profile.TraceRotations(),
		TraceGaloisElements: profile.TraceGaloisElements(),
		QCount:              profile.qCount, PCount: profile.pCount, LogDefaultScale: profile.logDefaultScale,
		MainSecretWeight: profile.mainSecretWeight, EphemeralSecretWeight: profile.ephemeralSecretWeight,
	}, "Gao N16 packing L11 profile")
}

func validateGaoN16PackingL11Profile(profile GaoN16PackingL11Profile) error {
	expected, err := NewGaoN16PackingL11Profile()
	if err != nil {
		return artifactCapacityBlocked("cannot construct expected L11 packing profile", err)
	}
	digest, err := digestGaoN16PackingL11Profile(profile)
	if err != nil {
		return artifactCapacityBlocked("cannot authenticate L11 packing profile", err)
	}
	if profile.digest == "" || profile.digest != digest || profile.digest != expected.digest ||
		profile.schema != expected.schema || profile.adaptationLabel != expected.adaptationLabel ||
		profile.evidenceScope != expected.evidenceScope || profile.maturity != expected.maturity ||
		profile.sourceFaithful || profile.fullPacked || profile.parameterDigest != expected.parameterDigest ||
		profile.baseProfileDigest != expected.baseProfileDigest || profile.logN != expected.logN ||
		profile.logSlots != expected.logSlots || profile.slots != expected.slots ||
		profile.wordBits != expected.wordBits || profile.wordCapacity != expected.wordCapacity ||
		profile.sparseDenseGap != expected.sparseDenseGap || !equalUint64s(profile.traceRotations, expected.traceRotations) ||
		!equalUint64s(profile.traceGaloisElements, expected.traceGaloisElements) ||
		profile.qCount != expected.qCount || profile.pCount != expected.pCount ||
		profile.logDefaultScale != expected.logDefaultScale || profile.mainSecretWeight != expected.mainSecretWeight ||
		profile.ephemeralSecretWeight != expected.ephemeralSecretWeight {
		return artifactCapacityBlocked("L11 profile drifted or was promoted beyond capacity-only packing evidence", nil)
	}
	return nil
}

// GaoN16PackingL11CapacityShape contains only checked-arithmetic inputs. It
// never contains an encoder, DFT matrix, key, evaluator or ciphertext.
type GaoN16PackingL11CapacityShape struct {
	formulaVersion                                     string
	adaptationLabel, evidenceScope                     string
	sourceFaithful, fullPacked                         bool
	logN, logSlots, ringDegree, slots                  uint64
	wordBits, wordCapacity, sparseDenseGap             uint64
	traceRotations                                     []uint64
	traceGaloisElements                                []uint64
	dftFormat, stcType, ctsType                        string
	stcLevels, ctsLevels                               []uint64
	logBSGSRatio                                       int
	stcRotationInputs, ctsRotationInputs               []uint64
	stcGaloisElements, ctsGaloisElements               []uint64
	conjugationGaloisElement                           uint64
	evaluationRotationExponents                        []int64
	evaluationGaloisElements                           []uint64
	qCount, pCount, coefficientBytes                   uint64
	complexEntryBoundBytes, textComplexBoundBytes      uint64
	textCopies                                         uint64
	specificationTransformCount                        uint64
	specificationVectorsPerTransform                   uint64
	compiledPairPolynomialCount                        uint64
	stcFactorDiagonalCounts, ctsFactorDiagonalCounts   []uint64
	stcLevelQ, stcLevelP, ctsLevelQ, ctsLevelP         int
	maskCount, maskLevelQ                              uint64
	polynomialMappingCount, polynomialCoefficientCount uint64
	dftTraceConjugationKeyCount, keyBytesPerKey        uint64
	fixedEvaluationKeys                                []string
	evaluatorFixedBufferBytes                          uint64
	babyStepCiphertextCount, ciphertextComponents      uint64
	babyStepLevelQ, babyStepLevelP                     int
	scratchCoefficientCount                            uint64
	digest                                             string
}

func DefaultGaoN16PackingL11CapacityShape() GaoN16PackingL11CapacityShape {
	shape := GaoN16PackingL11CapacityShape{
		formulaVersion:  gaoN16PackingL11ShapeSchema,
		adaptationLabel: gaoN16PackingL11AdaptationLabel, evidenceScope: gaoN16PackingL11EvidenceScope,
		sourceFaithful: false, fullPacked: false,
		logN: 16, logSlots: 11, ringDegree: 65536, slots: 2048,
		wordBits: 8, wordCapacity: 512, sparseDenseGap: 16,
		traceRotations: []uint64{2048, 4096, 8192, 16384},
		dftFormat:      "split_real_and_imag", stcType: "homomorphic_decode", ctsType: "homomorphic_encode",
		stcLevels: []uint64{1, 1}, ctsLevels: []uint64{1, 1, 1}, logBSGSRatio: 0,
		stcRotationInputs:        []uint64{1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 64, 96, 128, 160, 192, 224, 256, 512, 768, 1024, 1280, 1536, 1792, 2016, 2024, 2032, 2040},
		ctsRotationInputs:        []uint64{1, 2, 3, 4, 8, 16, 24, 32, 64, 96, 128, 256, 384, 512, 1024, 1536, 1920, 1952, 1984, 2016, 2040, 2044},
		conjugationGaloisElement: 131071,
		qCount:                   21, pCount: 7, coefficientBytes: 8,
		complexEntryBoundBytes: 256, textComplexBoundBytes: 192, textCopies: 2,
		specificationTransformCount: 9, specificationVectorsPerTransform: 4,
		compiledPairPolynomialCount: 14,
		stcFactorDiagonalCounts:     []uint64{63, 64}, ctsFactorDiagonalCounts: []uint64{16, 31, 15},
		stcLevelQ: 18, stcLevelP: 6, ctsLevelQ: 20, ctsLevelP: 6,
		maskCount: 2, maskLevelQ: 19,
		polynomialMappingCount: 3, polynomialCoefficientCount: 79,
		keyBytesPerKey:            88080384,
		fixedEvaluationKeys:       []string{"relinearization", "dense_to_sparse", "sparse_to_dense"},
		evaluatorFixedBufferBytes: 440926208,
		babyStepCiphertextCount:   4, ciphertextComponents: 2,
		babyStepLevelQ: 18, babyStepLevelP: 6,
		scratchCoefficientCount: 65536,
	}
	shape.traceGaloisElements = defaultGaoN16PackingL11GaloisElements(shape.traceRotations, shape.ringDegree)
	shape.stcGaloisElements = defaultGaoN16PackingL11GaloisElements(shape.stcRotationInputs, shape.ringDegree)
	shape.ctsGaloisElements = defaultGaoN16PackingL11GaloisElements(shape.ctsRotationInputs, shape.ringDegree)
	shape.evaluationRotationExponents = uniqueSortedInt64(append(
		append(append([]int64{-1}, uint64sToInt64s(shape.stcRotationInputs)...), uint64sToInt64s(shape.ctsRotationInputs)...),
		uint64sToInt64s(shape.traceRotations)...,
	))
	shape.evaluationGaloisElements = uniqueSortedUint64(append(
		append(append(append([]uint64(nil), shape.stcGaloisElements...), shape.ctsGaloisElements...), shape.traceGaloisElements...),
		shape.conjugationGaloisElement,
	))
	shape.dftTraceConjugationKeyCount = uint64(len(shape.evaluationGaloisElements))
	shape.digest, _ = digestGaoN16PackingL11Shape(shape)
	return shape
}

func (s GaoN16PackingL11CapacityShape) SchemaVersion() string  { return s.formulaVersion }
func (s GaoN16PackingL11CapacityShape) LogN() uint64           { return s.logN }
func (s GaoN16PackingL11CapacityShape) LogSlots() uint64       { return s.logSlots }
func (s GaoN16PackingL11CapacityShape) RingDegree() uint64     { return s.ringDegree }
func (s GaoN16PackingL11CapacityShape) Slots() uint64          { return s.slots }
func (s GaoN16PackingL11CapacityShape) WordCapacity() uint64   { return s.wordCapacity }
func (s GaoN16PackingL11CapacityShape) SparseDenseGap() uint64 { return s.sparseDenseGap }
func (s GaoN16PackingL11CapacityShape) TraceRotationCount() uint64 {
	return uint64(len(s.traceRotations))
}
func (s GaoN16PackingL11CapacityShape) DFTFormat() string { return s.dftFormat }
func (s GaoN16PackingL11CapacityShape) STCType() string   { return s.stcType }
func (s GaoN16PackingL11CapacityShape) CTSType() string   { return s.ctsType }
func (s GaoN16PackingL11CapacityShape) LogBSGSRatio() int { return s.logBSGSRatio }
func (s GaoN16PackingL11CapacityShape) STCLevels() []uint64 {
	return append([]uint64(nil), s.stcLevels...)
}
func (s GaoN16PackingL11CapacityShape) CTSLevels() []uint64 {
	return append([]uint64(nil), s.ctsLevels...)
}
func (s GaoN16PackingL11CapacityShape) TraceGaloisElements() []uint64 {
	return append([]uint64(nil), s.traceGaloisElements...)
}
func (s GaoN16PackingL11CapacityShape) STCGaloisElements() []uint64 {
	return append([]uint64(nil), s.stcGaloisElements...)
}
func (s GaoN16PackingL11CapacityShape) CTSGaloisElements() []uint64 {
	return append([]uint64(nil), s.ctsGaloisElements...)
}
func (s GaoN16PackingL11CapacityShape) EvaluationRotationExponents() []int64 {
	return append([]int64(nil), s.evaluationRotationExponents...)
}
func (s GaoN16PackingL11CapacityShape) EvaluationGaloisElements() []uint64 {
	return append([]uint64(nil), s.evaluationGaloisElements...)
}
func (s GaoN16PackingL11CapacityShape) ConjugationGaloisElement() uint64 {
	return s.conjugationGaloisElement
}
func (s GaoN16PackingL11CapacityShape) STCFactorDiagonalCounts() []uint64 {
	return append([]uint64(nil), s.stcFactorDiagonalCounts...)
}
func (s GaoN16PackingL11CapacityShape) CTSFactorDiagonalCounts() []uint64 {
	return append([]uint64(nil), s.ctsFactorDiagonalCounts...)
}
func (s GaoN16PackingL11CapacityShape) FixedEvaluationKeys() []string {
	return append([]string(nil), s.fixedEvaluationKeys...)
}
func (s GaoN16PackingL11CapacityShape) Digest() string { return s.digest }

func cloneGaoN16PackingL11CapacityShape(s GaoN16PackingL11CapacityShape) GaoN16PackingL11CapacityShape {
	s.traceRotations = append([]uint64(nil), s.traceRotations...)
	s.traceGaloisElements = append([]uint64(nil), s.traceGaloisElements...)
	s.stcLevels = append([]uint64(nil), s.stcLevels...)
	s.ctsLevels = append([]uint64(nil), s.ctsLevels...)
	s.stcRotationInputs = append([]uint64(nil), s.stcRotationInputs...)
	s.ctsRotationInputs = append([]uint64(nil), s.ctsRotationInputs...)
	s.stcGaloisElements = append([]uint64(nil), s.stcGaloisElements...)
	s.ctsGaloisElements = append([]uint64(nil), s.ctsGaloisElements...)
	s.evaluationRotationExponents = append([]int64(nil), s.evaluationRotationExponents...)
	s.evaluationGaloisElements = append([]uint64(nil), s.evaluationGaloisElements...)
	s.stcFactorDiagonalCounts = append([]uint64(nil), s.stcFactorDiagonalCounts...)
	s.ctsFactorDiagonalCounts = append([]uint64(nil), s.ctsFactorDiagonalCounts...)
	s.fixedEvaluationKeys = append([]string(nil), s.fixedEvaluationKeys...)
	return s
}

type gaoN16PackingL11ShapeDigestRecord struct {
	SchemaVersion, FormulaVersion, AdaptationLabel, EvidenceScope string
	SourceFaithful, FullPacked                                    bool
	LogN, LogSlots, RingDegree, Slots                             uint64
	WordBits, WordCapacity, SparseDenseGap                        uint64
	TraceRotations                                                []uint64
	TraceGaloisElements                                           []uint64
	DFTFormat, STCType, CTSType                                   string
	STCLevels, CTSLevels                                          []uint64
	LogBSGSRatio                                                  int
	STCRotationInputs, CTSRotationInputs                          []uint64
	STCGaloisElements, CTSGaloisElements                          []uint64
	ConjugationGaloisElement                                      uint64
	EvaluationRotationExponents                                   []int64
	EvaluationGaloisElements                                      []uint64
	QCount, PCount, CoefficientBytes                              uint64
	ComplexEntryBoundBytes, TextComplexBoundBytes, TextCopies     uint64
	SpecificationTransformCount, SpecificationVectorsPerTransform uint64
	CompiledPairPolynomialCount                                   uint64
	STCFactorDiagonalCounts, CTSFactorDiagonalCounts              []uint64
	STCLevelQ, STCLevelP, CTSLevelQ, CTSLevelP                    int
	MaskCount, MaskLevelQ                                         uint64
	PolynomialMappingCount, PolynomialCoefficientCount            uint64
	DFTTraceConjugationKeyCount, KeyBytesPerKey                   uint64
	FixedEvaluationKeys                                           []string
	EvaluatorFixedBufferBytes                                     uint64
	BabyStepCiphertextCount, CiphertextComponents                 uint64
	BabyStepLevelQ, BabyStepLevelP                                int
	ScratchCoefficientCount                                       uint64
}

func digestGaoN16PackingL11Shape(shape GaoN16PackingL11CapacityShape) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11ShapeDigestRecord{
		SchemaVersion: gaoN16PackingL11ShapeSchema, FormulaVersion: shape.formulaVersion,
		AdaptationLabel: shape.adaptationLabel, EvidenceScope: shape.evidenceScope,
		SourceFaithful: shape.sourceFaithful, FullPacked: shape.fullPacked,
		LogN: shape.logN, LogSlots: shape.logSlots, RingDegree: shape.ringDegree, Slots: shape.slots,
		WordBits: shape.wordBits, WordCapacity: shape.wordCapacity, SparseDenseGap: shape.sparseDenseGap,
		TraceRotations:      append([]uint64(nil), shape.traceRotations...),
		TraceGaloisElements: shape.TraceGaloisElements(),
		DFTFormat:           shape.dftFormat, STCType: shape.stcType, CTSType: shape.ctsType,
		STCLevels: shape.STCLevels(), CTSLevels: shape.CTSLevels(), LogBSGSRatio: shape.logBSGSRatio,
		STCRotationInputs:           append([]uint64(nil), shape.stcRotationInputs...),
		CTSRotationInputs:           append([]uint64(nil), shape.ctsRotationInputs...),
		STCGaloisElements:           append([]uint64(nil), shape.stcGaloisElements...),
		CTSGaloisElements:           append([]uint64(nil), shape.ctsGaloisElements...),
		ConjugationGaloisElement:    shape.conjugationGaloisElement,
		EvaluationRotationExponents: shape.EvaluationRotationExponents(),
		EvaluationGaloisElements:    shape.EvaluationGaloisElements(),
		QCount:                      shape.qCount, PCount: shape.pCount, CoefficientBytes: shape.coefficientBytes,
		ComplexEntryBoundBytes: shape.complexEntryBoundBytes,
		TextComplexBoundBytes:  shape.textComplexBoundBytes, TextCopies: shape.textCopies,
		SpecificationTransformCount:      shape.specificationTransformCount,
		SpecificationVectorsPerTransform: shape.specificationVectorsPerTransform,
		CompiledPairPolynomialCount:      shape.compiledPairPolynomialCount,
		STCFactorDiagonalCounts:          shape.STCFactorDiagonalCounts(), CTSFactorDiagonalCounts: shape.CTSFactorDiagonalCounts(),
		STCLevelQ: shape.stcLevelQ, STCLevelP: shape.stcLevelP,
		CTSLevelQ: shape.ctsLevelQ, CTSLevelP: shape.ctsLevelP,
		MaskCount: shape.maskCount, MaskLevelQ: shape.maskLevelQ,
		PolynomialMappingCount:      shape.polynomialMappingCount,
		PolynomialCoefficientCount:  shape.polynomialCoefficientCount,
		DFTTraceConjugationKeyCount: shape.dftTraceConjugationKeyCount, KeyBytesPerKey: shape.keyBytesPerKey,
		FixedEvaluationKeys: shape.FixedEvaluationKeys(), EvaluatorFixedBufferBytes: shape.evaluatorFixedBufferBytes,
		BabyStepCiphertextCount: shape.babyStepCiphertextCount, CiphertextComponents: shape.ciphertextComponents,
		BabyStepLevelQ: shape.babyStepLevelQ, BabyStepLevelP: shape.babyStepLevelP,
		ScratchCoefficientCount: shape.scratchCoefficientCount,
	}, "Gao N16 packing L11 capacity shape")
}

func validateGaoN16PackingL11ShapeSeal(shape GaoN16PackingL11CapacityShape) error {
	if err := validateGaoN16PackingL11KeySchedule(shape); err != nil {
		return err
	}
	digest, err := digestGaoN16PackingL11Shape(shape)
	if err != nil {
		return err
	}
	if shape.digest == "" || shape.digest != digest || shape.adaptationLabel != gaoN16PackingL11AdaptationLabel ||
		shape.evidenceScope != gaoN16PackingL11EvidenceScope || shape.sourceFaithful || shape.fullPacked {
		return artifactCapacityBlocked("L11 capacity shape drifted or was promoted beyond packing-adaptation evidence", nil)
	}
	return nil
}

// GaoN16PackingL11CapacityEstimate is one versioned named arithmetic term in
// the combined artifact-and-runtime capacity plan.
type GaoN16PackingL11CapacityEstimate struct {
	name, formula string
	bytes         uint64
}

func (e GaoN16PackingL11CapacityEstimate) Name() string    { return e.name }
func (e GaoN16PackingL11CapacityEstimate) Formula() string { return e.formula }
func (e GaoN16PackingL11CapacityEstimate) Bytes() uint64   { return e.bytes }

type gaoN16PackingL11Derived struct {
	estimates                                      []GaoN16PackingL11CapacityEstimate
	residentArtifactBytes, maxEncodedFactorBytes   uint64
	fullArtifactPeakBytes                          uint64
	dftKeyBytes, fixedKeyBytes, evaluationKeyBytes uint64
	projectedIncrementalPeakBytes                  uint64
}

func deriveGaoN16PackingL11Capacity(shape GaoN16PackingL11CapacityShape) (gaoN16PackingL11Derived, error) {
	blocked := func(reason string, err error) (gaoN16PackingL11Derived, error) {
		return gaoN16PackingL11Derived{}, artifactCapacityBlocked(reason, err)
	}
	stcDiagonals, err := checkedUint64Sum(shape.stcFactorDiagonalCounts...)
	if err != nil {
		return blocked("L11 STC diagonal count overflow", err)
	}
	ctsDiagonals, err := checkedUint64Sum(shape.ctsFactorDiagonalCounts...)
	if err != nil {
		return blocked("L11 CTS diagonal count overflow", err)
	}
	stcQ, err := checkedLevelCount(shape.stcLevelQ)
	if err != nil {
		return blocked("invalid L11 STC Q level", err)
	}
	stcP, err := checkedLevelCount(shape.stcLevelP)
	if err != nil {
		return blocked("invalid L11 STC P level", err)
	}
	stcLimbs, err := checkedUint64Sum(stcQ, stcP)
	if err != nil {
		return blocked("L11 STC limb count overflow", err)
	}
	ctsQ, err := checkedLevelCount(shape.ctsLevelQ)
	if err != nil {
		return blocked("invalid L11 CTS Q level", err)
	}
	ctsP, err := checkedLevelCount(shape.ctsLevelP)
	if err != nil {
		return blocked("invalid L11 CTS P level", err)
	}
	ctsLimbs, err := checkedUint64Sum(ctsQ, ctsP)
	if err != nil {
		return blocked("L11 CTS limb count overflow", err)
	}
	compiledLimbs, err := checkedUint64Sum(shape.qCount, shape.pCount)
	if err != nil {
		return blocked("L11 compiled-pair limb count overflow", err)
	}

	specifications, err := checkedUint64Product(shape.specificationTransformCount, shape.specificationVectorsPerTransform, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return blocked("L11 transform specification estimate overflow", err)
	}
	compiledPair, err := checkedUint64Product(shape.compiledPairPolynomialCount, shape.ringDegree, shape.coefficientBytes, compiledLimbs)
	if err != nil {
		return blocked("L11 compiled transform-pair estimate overflow", err)
	}
	stcEncoded, err := checkedUint64Product(stcDiagonals, shape.ringDegree, shape.coefficientBytes, stcLimbs)
	if err != nil {
		return blocked("L11 encoded STC estimate overflow", err)
	}
	ctsEncoded, err := checkedUint64Product(ctsDiagonals, shape.ringDegree, shape.coefficientBytes, ctsLimbs)
	if err != nil {
		return blocked("L11 encoded CTS estimate overflow", err)
	}
	maskQ, err := checkedUint64Sum(shape.maskLevelQ, 1)
	if err != nil {
		return blocked("L11 mask level count overflow", err)
	}
	masks, err := checkedUint64Product(shape.maskCount, shape.ringDegree, shape.coefficientBytes, maskQ)
	if err != nil {
		return blocked("L11 mask estimate overflow", err)
	}
	polyMappings, err := checkedUint64Product(shape.polynomialMappingCount, shape.slots, shape.coefficientBytes)
	if err != nil {
		return blocked("L11 polynomial mapping estimate overflow", err)
	}
	polyCoefficients, err := checkedUint64Product(shape.polynomialCoefficientCount, shape.complexEntryBoundBytes)
	if err != nil {
		return blocked("L11 polynomial coefficient estimate overflow", err)
	}
	polynomials, err := checkedUint64Sum(polyMappings, polyCoefficients)
	if err != nil {
		return blocked("L11 polynomial operand estimate overflow", err)
	}
	resident, err := checkedUint64Sum(specifications, compiledPair, stcEncoded, ctsEncoded, masks, polynomials)
	if err != nil {
		return blocked("L11 resident artifact estimate overflow", err)
	}
	base, err := checkedUint64Sum(specifications, compiledPair, masks, polynomials)
	if err != nil {
		return blocked("L11 base artifact estimate overflow", err)
	}
	stcHighPrecision, err := checkedUint64Product(stcDiagonals, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return blocked("L11 STC high-precision estimate overflow", err)
	}
	ctsHighPrecision, err := checkedUint64Product(ctsDiagonals, shape.slots, shape.complexEntryBoundBytes)
	if err != nil {
		return blocked("L11 CTS high-precision estimate overflow", err)
	}
	stcText, err := checkedUint64Product(stcDiagonals, shape.slots, shape.textComplexBoundBytes, shape.textCopies)
	if err != nil {
		return blocked("L11 STC digest estimate overflow", err)
	}
	ctsText, err := checkedUint64Product(ctsDiagonals, shape.slots, shape.textComplexBoundBytes, shape.textCopies)
	if err != nil {
		return blocked("L11 CTS digest estimate overflow", err)
	}
	stcStage, err := checkedUint64Sum(base, stcEncoded, stcHighPrecision, stcText)
	if err != nil {
		return blocked("L11 STC construction peak overflow", err)
	}
	ctsStage, err := checkedUint64Sum(base, stcEncoded, ctsEncoded, ctsHighPrecision, ctsText)
	if err != nil {
		return blocked("L11 CTS construction peak overflow", err)
	}
	polyStage, err := checkedUint64Sum(resident, polynomials)
	if err != nil {
		return blocked("L11 polynomial clone peak overflow", err)
	}
	artifactPeak := stcStage
	if ctsStage > artifactPeak {
		artifactPeak = ctsStage
	}
	if polyStage > artifactPeak {
		artifactPeak = polyStage
	}

	maxFactor := uint64(0)
	for _, diagonals := range shape.stcFactorDiagonalCounts {
		value, productErr := checkedUint64Product(diagonals, shape.ringDegree, shape.coefficientBytes, stcLimbs)
		if productErr != nil {
			return blocked("L11 STC factor estimate overflow", productErr)
		}
		if value > maxFactor {
			maxFactor = value
		}
	}
	for _, diagonals := range shape.ctsFactorDiagonalCounts {
		value, productErr := checkedUint64Product(diagonals, shape.ringDegree, shape.coefficientBytes, ctsLimbs)
		if productErr != nil {
			return blocked("L11 CTS factor estimate overflow", productErr)
		}
		if value > maxFactor {
			maxFactor = value
		}
	}

	actualKeyCount := uint64(len(shape.evaluationGaloisElements))
	if actualKeyCount != shape.dftTraceConjugationKeyCount {
		return blocked("L11 DFT/Trace/conjugation key count differs from the deduplicated Galois union", nil)
	}
	dftKeyBytes, err := checkedUint64Product(actualKeyCount, shape.keyBytesPerKey)
	if err != nil {
		return blocked("L11 DFT/Trace/conjugation key estimate overflow", err)
	}
	fixedCount := uint64(len(shape.fixedEvaluationKeys))
	fixedKeyBytes, err := checkedUint64Product(fixedCount, shape.keyBytesPerKey)
	if err != nil {
		return blocked("L11 fixed evaluation-key estimate overflow", err)
	}
	evaluationKeyBytes, err := checkedUint64Sum(dftKeyBytes, fixedKeyBytes)
	if err != nil {
		return blocked("L11 evaluation-key total overflow", err)
	}
	babyQ, err := checkedLevelCount(shape.babyStepLevelQ)
	if err != nil {
		return blocked("invalid L11 baby-step Q level", err)
	}
	babyP, err := checkedLevelCount(shape.babyStepLevelP)
	if err != nil {
		return blocked("invalid L11 baby-step P level", err)
	}
	babyLimbs, err := checkedUint64Sum(babyQ, babyP)
	if err != nil {
		return blocked("L11 baby-step limb count overflow", err)
	}
	preRotated, err := checkedUint64Product(shape.babyStepCiphertextCount, shape.ciphertextComponents, shape.ringDegree, shape.coefficientBytes, babyLimbs)
	if err != nil {
		return blocked("L11 baby-step ciphertext estimate overflow", err)
	}
	scratch, err := checkedUint64Product(shape.scratchCoefficientCount, shape.coefficientBytes)
	if err != nil {
		return blocked("L11 coefficient scratch estimate overflow", err)
	}
	combinedPeak, err := checkedUint64Sum(artifactPeak, evaluationKeyBytes, shape.evaluatorFixedBufferBytes, preRotated, scratch)
	if err != nil {
		return blocked("L11 combined runtime capacity estimate overflow", err)
	}

	estimates := []GaoN16PackingL11CapacityEstimate{
		{name: "transform_specifications_bound", formula: "9*4*slots*256B", bytes: specifications},
		{name: "compiled_transform_pair_bound", formula: "14*N*8B*(Q21+P7)", bytes: compiledPair},
		{name: "encoded_stc_qp_exact", formula: "sum(63,64)*N*8B*((LQ18+1)+(LP6+1))", bytes: stcEncoded},
		{name: "encoded_cts_qp_exact", formula: "sum(16,31,15)*N*8B*((LQ20+1)+(LP6+1))", bytes: ctsEncoded},
		{name: "q_only_masks_bound", formula: "2*N*8B*(LQ19+1)", bytes: masks},
		{name: "polynomial_operands_bound", formula: "3*slots*8B+79*256B", bytes: polynomials},
		{name: "full_artifact_construction_peak", formula: "max(STC-construction,CTS-construction,polynomial-clone)", bytes: artifactPeak},
		{name: "dft_trace_conjugation_evaluation_keys_bound", formula: "38*88080384B", bytes: dftKeyBytes},
		{name: "fixed_evaluation_keys_bound", formula: "3*88080384B(relinearization+dense-to-sparse+sparse-to-dense)", bytes: fixedKeyBytes},
		{name: "evaluator_fixed_buffers_bound", formula: "accepted-evaluator-fixed-buffer-bound=440926208B", bytes: shape.evaluatorFixedBufferBytes},
		{name: "max_factor_baby_step_prerotated_ciphertexts_bound", formula: "4*2*N*8B*((LQ18+1)+(LP6+1))", bytes: preRotated},
		{name: "n_coefficient_scratch_bound", formula: "N*8B", bytes: scratch},
	}
	return gaoN16PackingL11Derived{
		estimates: estimates, residentArtifactBytes: resident, maxEncodedFactorBytes: maxFactor,
		fullArtifactPeakBytes: artifactPeak, dftKeyBytes: dftKeyBytes, fixedKeyBytes: fixedKeyBytes,
		evaluationKeyBytes: evaluationKeyBytes, projectedIncrementalPeakBytes: combinedPeak,
	}, nil
}

// GaoN16PackingL11CapacityPlan seals the exact reduced-packing profile, every
// arithmetic input and each named artifact/runtime estimate.
type GaoN16PackingL11CapacityPlan struct {
	schema, adaptationLabel, evidenceScope                    string
	maturity                                                  Maturity
	sourceFaithful, fullPacked                                bool
	parameterDigest, profileDigest, shapeDigest, policyDigest string
	digest                                                    string
	profile                                                   GaoN16PackingL11Profile
	shape                                                     GaoN16PackingL11CapacityShape
	policy                                                    CapacityPolicy
	estimates                                                 []GaoN16PackingL11CapacityEstimate
	residentArtifactBytes, maxEncodedFactorBytes              uint64
	fullArtifactPeakBytes                                     uint64
	dftKeyBytes, fixedKeyBytes, evaluationKeyBytes            uint64
	projectedIncrementalPeakBytes                             uint64
}

func NewGaoN16PackingL11CapacityPlan(profile GaoN16PackingL11Profile, shape GaoN16PackingL11CapacityShape, policy CapacityPolicy) (GaoN16PackingL11CapacityPlan, error) {
	if err := validateGaoN16PackingL11Profile(profile); err != nil {
		return GaoN16PackingL11CapacityPlan{}, err
	}
	shape = cloneGaoN16PackingL11CapacityShape(shape)
	if err := validateGaoN16PackingL11ShapeSeal(shape); err != nil {
		return GaoN16PackingL11CapacityPlan{}, err
	}
	if err := validateArtifactCapacityPolicy(policy); err != nil {
		return GaoN16PackingL11CapacityPlan{}, err
	}
	derived, err := deriveGaoN16PackingL11Capacity(shape)
	if err != nil {
		return GaoN16PackingL11CapacityPlan{}, err
	}
	expectedShape := DefaultGaoN16PackingL11CapacityShape()
	if shape.digest != expectedShape.digest || shape.logN != profile.logN || shape.logSlots != profile.logSlots ||
		shape.slots != profile.slots || shape.wordBits != profile.wordBits || shape.wordCapacity != profile.wordCapacity ||
		shape.sparseDenseGap != profile.sparseDenseGap || !equalUint64s(shape.traceRotations, profile.traceRotations) ||
		shape.qCount != profile.qCount || shape.pCount != profile.pCount {
		return GaoN16PackingL11CapacityPlan{}, artifactCapacityBlocked("L11 capacity shape or profile drifted", nil)
	}
	plan := GaoN16PackingL11CapacityPlan{
		schema: gaoN16PackingL11PlanSchema, adaptationLabel: profile.adaptationLabel,
		evidenceScope: profile.evidenceScope, maturity: ArtifactCapacityOnlyUnverified,
		sourceFaithful: false, fullPacked: false,
		parameterDigest: profile.parameterDigest, profileDigest: profile.digest,
		shapeDigest: shape.digest, policyDigest: policy.digest,
		profile: profile, shape: shape, policy: policy,
		estimates:             append([]GaoN16PackingL11CapacityEstimate(nil), derived.estimates...),
		residentArtifactBytes: derived.residentArtifactBytes, maxEncodedFactorBytes: derived.maxEncodedFactorBytes,
		fullArtifactPeakBytes: derived.fullArtifactPeakBytes, dftKeyBytes: derived.dftKeyBytes,
		fixedKeyBytes: derived.fixedKeyBytes, evaluationKeyBytes: derived.evaluationKeyBytes,
		projectedIncrementalPeakBytes: derived.projectedIncrementalPeakBytes,
	}
	plan.digest, err = digestGaoN16PackingL11Plan(plan)
	if err != nil {
		return GaoN16PackingL11CapacityPlan{}, err
	}
	return plan, nil
}

func (p GaoN16PackingL11CapacityPlan) SchemaVersion() string         { return p.schema }
func (p GaoN16PackingL11CapacityPlan) Maturity() Maturity            { return p.maturity }
func (p GaoN16PackingL11CapacityPlan) AdaptationLabel() string       { return p.adaptationLabel }
func (p GaoN16PackingL11CapacityPlan) EvidenceScope() string         { return p.evidenceScope }
func (p GaoN16PackingL11CapacityPlan) IsSourceFaithful() bool        { return p.sourceFaithful }
func (p GaoN16PackingL11CapacityPlan) IsFullPacked() bool            { return p.fullPacked }
func (p GaoN16PackingL11CapacityPlan) ParameterDigest() string       { return p.parameterDigest }
func (p GaoN16PackingL11CapacityPlan) ProfileDigest() string         { return p.profileDigest }
func (p GaoN16PackingL11CapacityPlan) ShapeDigest() string           { return p.shapeDigest }
func (p GaoN16PackingL11CapacityPlan) PolicyDigest() string          { return p.policyDigest }
func (p GaoN16PackingL11CapacityPlan) Digest() string                { return p.digest }
func (p GaoN16PackingL11CapacityPlan) ResidentArtifactBytes() uint64 { return p.residentArtifactBytes }
func (p GaoN16PackingL11CapacityPlan) MaxEncodedFactorBytes() uint64 { return p.maxEncodedFactorBytes }
func (p GaoN16PackingL11CapacityPlan) FullArtifactPeakBytes() uint64 { return p.fullArtifactPeakBytes }
func (p GaoN16PackingL11CapacityPlan) DFTRotationTraceConjugationKeyCount() uint64 {
	return uint64(len(p.shape.evaluationGaloisElements))
}
func (p GaoN16PackingL11CapacityPlan) EvaluationRotationExponents() []int64 {
	return p.shape.EvaluationRotationExponents()
}
func (p GaoN16PackingL11CapacityPlan) EvaluationGaloisElements() []uint64 {
	return p.shape.EvaluationGaloisElements()
}
func (p GaoN16PackingL11CapacityPlan) TraceGaloisElements() []uint64 {
	return p.shape.TraceGaloisElements()
}
func (p GaoN16PackingL11CapacityPlan) STCGaloisElements() []uint64 {
	return p.shape.STCGaloisElements()
}
func (p GaoN16PackingL11CapacityPlan) CTSGaloisElements() []uint64 {
	return p.shape.CTSGaloisElements()
}
func (p GaoN16PackingL11CapacityPlan) ConjugationGaloisElement() uint64 {
	return p.shape.ConjugationGaloisElement()
}
func (p GaoN16PackingL11CapacityPlan) FixedEvaluationKeyCount() uint64 {
	return uint64(len(p.shape.fixedEvaluationKeys))
}
func (p GaoN16PackingL11CapacityPlan) TotalEvaluationKeyCount() uint64 {
	return p.DFTRotationTraceConjugationKeyCount() + p.FixedEvaluationKeyCount()
}
func (p GaoN16PackingL11CapacityPlan) EvaluationKeyBytes() uint64 { return p.evaluationKeyBytes }
func (p GaoN16PackingL11CapacityPlan) ProjectedIncrementalPeakBytes() uint64 {
	return p.projectedIncrementalPeakBytes
}
func (p GaoN16PackingL11CapacityPlan) Estimates() []GaoN16PackingL11CapacityEstimate {
	return append([]GaoN16PackingL11CapacityEstimate(nil), p.estimates...)
}
func (p GaoN16PackingL11CapacityPlan) Shape() GaoN16PackingL11CapacityShape {
	return cloneGaoN16PackingL11CapacityShape(p.shape)
}
func (p GaoN16PackingL11CapacityPlan) Policy() CapacityPolicy { return p.policy }

type gaoN16PackingL11EstimateDigestRecord struct {
	Name, Formula string
	Bytes         uint64
}
type gaoN16PackingL11PlanDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope             string
	Maturity                                                  Maturity
	SourceFaithful, FullPacked                                bool
	ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest string
	Estimates                                                 []gaoN16PackingL11EstimateDigestRecord
	ResidentArtifactBytes, MaxEncodedFactorBytes              uint64
	FullArtifactPeakBytes, DFTKeyBytes, FixedKeyBytes         uint64
	EvaluationKeyBytes, ProjectedIncrementalPeakBytes         uint64
}

func digestGaoN16PackingL11Plan(plan GaoN16PackingL11CapacityPlan) (string, error) {
	estimates := make([]gaoN16PackingL11EstimateDigestRecord, len(plan.estimates))
	for i, estimate := range plan.estimates {
		estimates[i] = gaoN16PackingL11EstimateDigestRecord{Name: estimate.name, Formula: estimate.formula, Bytes: estimate.bytes}
	}
	return digestCapacityRecord(gaoN16PackingL11PlanDigestRecord{
		SchemaVersion: plan.schema, AdaptationLabel: plan.adaptationLabel, EvidenceScope: plan.evidenceScope,
		Maturity: plan.maturity, SourceFaithful: plan.sourceFaithful, FullPacked: plan.fullPacked,
		ParameterDigest: plan.parameterDigest, ProfileDigest: plan.profileDigest,
		ShapeDigest: plan.shapeDigest, PolicyDigest: plan.policyDigest, Estimates: estimates,
		ResidentArtifactBytes: plan.residentArtifactBytes, MaxEncodedFactorBytes: plan.maxEncodedFactorBytes,
		FullArtifactPeakBytes: plan.fullArtifactPeakBytes, DFTKeyBytes: plan.dftKeyBytes,
		FixedKeyBytes: plan.fixedKeyBytes, EvaluationKeyBytes: plan.evaluationKeyBytes,
		ProjectedIncrementalPeakBytes: plan.projectedIncrementalPeakBytes,
	}, "Gao N16 packing L11 capacity plan")
}

func (p GaoN16PackingL11CapacityPlan) validate() error {
	if err := validateGaoN16PackingL11Profile(p.profile); err != nil {
		return err
	}
	if err := validateGaoN16PackingL11ShapeSeal(p.shape); err != nil {
		return err
	}
	if err := validateArtifactCapacityPolicy(p.policy); err != nil {
		return err
	}
	expected, err := NewGaoN16PackingL11CapacityPlan(p.profile, p.shape, p.policy)
	if err != nil {
		return err
	}
	digest, err := digestGaoN16PackingL11Plan(p)
	if err != nil {
		return err
	}
	if p.digest == "" || p.digest != digest || p.digest != expected.digest ||
		p.schema != expected.schema || p.adaptationLabel != expected.adaptationLabel ||
		p.evidenceScope != expected.evidenceScope || p.maturity != expected.maturity ||
		p.sourceFaithful || p.fullPacked || p.parameterDigest != expected.parameterDigest ||
		p.profileDigest != expected.profileDigest || p.shapeDigest != expected.shapeDigest ||
		p.policyDigest != expected.policyDigest || p.residentArtifactBytes != expected.residentArtifactBytes ||
		p.maxEncodedFactorBytes != expected.maxEncodedFactorBytes || p.fullArtifactPeakBytes != expected.fullArtifactPeakBytes ||
		p.dftKeyBytes != expected.dftKeyBytes || p.fixedKeyBytes != expected.fixedKeyBytes ||
		p.evaluationKeyBytes != expected.evaluationKeyBytes ||
		p.projectedIncrementalPeakBytes != expected.projectedIncrementalPeakBytes ||
		!equalGaoN16PackingL11Estimates(p.estimates, expected.estimates) {
		return artifactCapacityBlocked("L11 combined capacity plan drifted or was promoted", nil)
	}
	return nil
}

// GaoN16PackingL11CapacityReport is the sealed arithmetic result for one
// explicit caller-provided snapshot.
type GaoN16PackingL11CapacityReport struct {
	schema, adaptationLabel, evidenceScope                  string
	maturity                                                Maturity
	decision                                                CapacityDecision
	sourceFaithful, fullPacked                              bool
	planDigest, parameterDigest, profileDigest, shapeDigest string
	policyDigest, probeDigest, digest                       string
	snapshot                                                PhysicalMemorySnapshot
	currentSystemUsedBytes, capacityLimitBytes              uint64
	projectedIncrementalPeakBytes, guardBytes               uint64
	guardedRequirementBytes, projectedSystemUsedBytes       uint64
	remainingBytes                                          uint64
}

func (r GaoN16PackingL11CapacityReport) SchemaVersion() string            { return r.schema }
func (r GaoN16PackingL11CapacityReport) Maturity() Maturity               { return r.maturity }
func (r GaoN16PackingL11CapacityReport) Decision() CapacityDecision       { return r.decision }
func (r GaoN16PackingL11CapacityReport) AdaptationLabel() string          { return r.adaptationLabel }
func (r GaoN16PackingL11CapacityReport) EvidenceScope() string            { return r.evidenceScope }
func (r GaoN16PackingL11CapacityReport) IsSourceFaithful() bool           { return r.sourceFaithful }
func (r GaoN16PackingL11CapacityReport) IsFullPacked() bool               { return r.fullPacked }
func (r GaoN16PackingL11CapacityReport) PlanDigest() string               { return r.planDigest }
func (r GaoN16PackingL11CapacityReport) ParameterDigest() string          { return r.parameterDigest }
func (r GaoN16PackingL11CapacityReport) ProfileDigest() string            { return r.profileDigest }
func (r GaoN16PackingL11CapacityReport) ShapeDigest() string              { return r.shapeDigest }
func (r GaoN16PackingL11CapacityReport) PolicyDigest() string             { return r.policyDigest }
func (r GaoN16PackingL11CapacityReport) ProbeDigest() string              { return r.probeDigest }
func (r GaoN16PackingL11CapacityReport) Digest() string                   { return r.digest }
func (r GaoN16PackingL11CapacityReport) Snapshot() PhysicalMemorySnapshot { return r.snapshot }
func (r GaoN16PackingL11CapacityReport) CurrentSystemUsedBytes() uint64 {
	return r.currentSystemUsedBytes
}
func (r GaoN16PackingL11CapacityReport) CapacityLimitBytes() uint64 { return r.capacityLimitBytes }
func (r GaoN16PackingL11CapacityReport) ProjectedIncrementalPeakBytes() uint64 {
	return r.projectedIncrementalPeakBytes
}
func (r GaoN16PackingL11CapacityReport) GuardBytes() uint64 { return r.guardBytes }
func (r GaoN16PackingL11CapacityReport) GuardedRequirementBytes() uint64 {
	return r.guardedRequirementBytes
}
func (r GaoN16PackingL11CapacityReport) ProjectedSystemUsedBytes() uint64 {
	return r.projectedSystemUsedBytes
}
func (r GaoN16PackingL11CapacityReport) RemainingBelowLimitBytes() uint64 { return r.remainingBytes }

// GaoN16PackingL11CapacityPermit is opaque to external callers. A permit is
// valid only when it exactly matches the unique report independently rebuilt
// from the current plan and snapshot.
type GaoN16PackingL11CapacityPermit struct {
	schema, adaptationLabel, evidenceScope                  string
	maturity                                                Maturity
	decision                                                CapacityDecision
	sourceFaithful, fullPacked                              bool
	planDigest, parameterDigest, profileDigest, shapeDigest string
	policyDigest, probeDigest, reportDigest, sealDigest     string
}

func (p GaoN16PackingL11CapacityPermit) IsZero() bool {
	return p == (GaoN16PackingL11CapacityPermit{})
}
func (p GaoN16PackingL11CapacityPermit) SchemaVersion() string      { return p.schema }
func (p GaoN16PackingL11CapacityPermit) Maturity() Maturity         { return p.maturity }
func (p GaoN16PackingL11CapacityPermit) Decision() CapacityDecision { return p.decision }
func (p GaoN16PackingL11CapacityPermit) AdaptationLabel() string    { return p.adaptationLabel }
func (p GaoN16PackingL11CapacityPermit) EvidenceScope() string      { return p.evidenceScope }
func (p GaoN16PackingL11CapacityPermit) IsSourceFaithful() bool     { return p.sourceFaithful }
func (p GaoN16PackingL11CapacityPermit) IsFullPacked() bool         { return p.fullPacked }
func (p GaoN16PackingL11CapacityPermit) PlanDigest() string         { return p.planDigest }
func (p GaoN16PackingL11CapacityPermit) ParameterDigest() string    { return p.parameterDigest }
func (p GaoN16PackingL11CapacityPermit) ProfileDigest() string      { return p.profileDigest }
func (p GaoN16PackingL11CapacityPermit) ShapeDigest() string        { return p.shapeDigest }
func (p GaoN16PackingL11CapacityPermit) PolicyDigest() string       { return p.policyDigest }
func (p GaoN16PackingL11CapacityPermit) ProbeDigest() string        { return p.probeDigest }
func (p GaoN16PackingL11CapacityPermit) ReportDigest() string       { return p.reportDigest }
func (p GaoN16PackingL11CapacityPermit) Digest() string             { return p.sealDigest }

func (p GaoN16PackingL11CapacityPlan) Evaluate(snapshot PhysicalMemorySnapshot) (GaoN16PackingL11CapacityReport, GaoN16PackingL11CapacityPermit, error) {
	report, err := p.evaluateReport(snapshot)
	if err != nil {
		return report, GaoN16PackingL11CapacityPermit{}, err
	}
	permit := GaoN16PackingL11CapacityPermit{
		schema: gaoN16PackingL11PermitSchema, adaptationLabel: report.adaptationLabel,
		evidenceScope: report.evidenceScope, maturity: report.maturity, decision: report.decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: report.planDigest, parameterDigest: report.parameterDigest,
		profileDigest: report.profileDigest, shapeDigest: report.shapeDigest,
		policyDigest: report.policyDigest, probeDigest: report.probeDigest, reportDigest: report.digest,
	}
	permit.sealDigest, err = digestGaoN16PackingL11Permit(permit)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, GaoN16PackingL11CapacityPermit{}, err
	}
	return report, permit, nil
}

func (p GaoN16PackingL11CapacityPlan) evaluateReport(snapshot PhysicalMemorySnapshot) (GaoN16PackingL11CapacityReport, error) {
	if err := p.validate(); err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	if err := validatePhysicalMemorySnapshot(snapshot); err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	probe, err := digestGaoN16PackingL11Probe(p, snapshot)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	currentUsed := snapshot.TotalPhysicalBytes - snapshot.AvailablePhysicalBytes
	limitProduct, err := checkedUint64Product(snapshot.TotalPhysicalBytes, p.policy.limitNumerator)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 capacity limit overflow", err)
	}
	limit := limitProduct / p.policy.limitDenominator
	guardProduct, err := checkedUint64Product(p.projectedIncrementalPeakBytes, p.policy.relativeGuardNumerator)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 relative guard overflow", err)
	}
	guard := guardProduct / p.policy.relativeGuardDenominator
	if guard < p.policy.minimumGuardBytes {
		guard = p.policy.minimumGuardBytes
	}
	guarded, err := checkedUint64Sum(p.projectedIncrementalPeakBytes, guard)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 guarded requirement overflow", err)
	}
	projected, err := checkedUint64Sum(currentUsed, guarded)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, artifactCapacityBlocked("L11 projected system use overflow", err)
	}
	decision := Admitted
	remaining := uint64(0)
	if projected >= limit {
		decision = ResourceBlocked
	} else {
		remaining = limit - projected
	}
	report := GaoN16PackingL11CapacityReport{
		schema: gaoN16PackingL11ReportSchema, adaptationLabel: p.adaptationLabel,
		evidenceScope: p.evidenceScope, maturity: ArtifactCapacityOnlyUnverified, decision: decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: p.digest, parameterDigest: p.parameterDigest, profileDigest: p.profileDigest,
		shapeDigest: p.shapeDigest, policyDigest: p.policyDigest, probeDigest: probe, snapshot: snapshot,
		currentSystemUsedBytes: currentUsed, capacityLimitBytes: limit,
		projectedIncrementalPeakBytes: p.projectedIncrementalPeakBytes, guardBytes: guard,
		guardedRequirementBytes: guarded, projectedSystemUsedBytes: projected, remainingBytes: remaining,
	}
	report.digest, err = digestGaoN16PackingL11Report(report)
	if err != nil {
		return GaoN16PackingL11CapacityReport{}, err
	}
	if decision == ResourceBlocked {
		return report, artifactCapacityBlocked("L11 projected use is at or over the strict 80% boundary", nil)
	}
	return report, nil
}

func (p GaoN16PackingL11CapacityPlan) ValidateReport(snapshot PhysicalMemorySnapshot, report GaoN16PackingL11CapacityReport) error {
	expected, evaluationErr := p.evaluateReport(snapshot)
	if report != expected || report.digest == "" {
		return artifactCapacityBlocked("L11 capacity report is zero, stale, foreign, tampered, or promoted", nil)
	}
	digest, err := digestGaoN16PackingL11Report(report)
	if err != nil {
		return err
	}
	if digest != report.digest {
		return artifactCapacityBlocked("L11 capacity report seal changed", nil)
	}
	if evaluationErr != nil {
		var blocked *ErrArtifactCapacityBlocked
		if !errors.As(evaluationErr, &blocked) {
			return evaluationErr
		}
	}
	return nil
}

func (p GaoN16PackingL11CapacityPlan) ValidatePermit(snapshot PhysicalMemorySnapshot, permit GaoN16PackingL11CapacityPermit) error {
	report, err := p.evaluateReport(snapshot)
	if err != nil {
		return err
	}
	if report.decision != Admitted {
		return artifactCapacityBlocked("L11 capacity report is not admitted", nil)
	}
	expected := GaoN16PackingL11CapacityPermit{
		schema: gaoN16PackingL11PermitSchema, adaptationLabel: report.adaptationLabel,
		evidenceScope: report.evidenceScope, maturity: report.maturity, decision: report.decision,
		sourceFaithful: false, fullPacked: false,
		planDigest: report.planDigest, parameterDigest: report.parameterDigest,
		profileDigest: report.profileDigest, shapeDigest: report.shapeDigest,
		policyDigest: report.policyDigest, probeDigest: report.probeDigest, reportDigest: report.digest,
	}
	expected.sealDigest, err = digestGaoN16PackingL11Permit(expected)
	if err != nil {
		return err
	}
	if permit != expected || !isArtifactCapacityDigest(permit.reportDigest) || !isArtifactCapacityDigest(permit.sealDigest) {
		return artifactCapacityBlocked("L11 capacity permit is zero, blocked, stale, foreign, tampered, or promoted", nil)
	}
	return nil
}

type gaoN16PackingL11ProbeDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope, PlanDigest, PolicyDigest string
	SnapshotID                                                              string
	TotalPhysicalBytes, AvailablePhysicalBytes                              uint64
}

func digestGaoN16PackingL11Probe(plan GaoN16PackingL11CapacityPlan, snapshot PhysicalMemorySnapshot) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11ProbeDigestRecord{
		SchemaVersion: gaoN16PackingL11ProbeSchema, AdaptationLabel: plan.adaptationLabel,
		EvidenceScope: plan.evidenceScope, PlanDigest: plan.digest, PolicyDigest: plan.policyDigest,
		SnapshotID: snapshot.SnapshotID, TotalPhysicalBytes: snapshot.TotalPhysicalBytes,
		AvailablePhysicalBytes: snapshot.AvailablePhysicalBytes,
	}, "Gao N16 packing L11 capacity probe")
}

type gaoN16PackingL11ReportDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope                                      string
	Maturity                                                                           Maturity
	Decision                                                                           CapacityDecision
	SourceFaithful, FullPacked                                                         bool
	PlanDigest, ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest, ProbeDigest string
	Snapshot                                                                           PhysicalMemorySnapshot
	CurrentSystemUsedBytes, CapacityLimitBytes                                         uint64
	ProjectedIncrementalPeakBytes, GuardBytes, GuardedRequirementBytes                 uint64
	ProjectedSystemUsedBytes, RemainingBytes                                           uint64
}

func digestGaoN16PackingL11Report(report GaoN16PackingL11CapacityReport) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11ReportDigestRecord{
		SchemaVersion: report.schema, AdaptationLabel: report.adaptationLabel, EvidenceScope: report.evidenceScope,
		Maturity: report.maturity, Decision: report.decision,
		SourceFaithful: report.sourceFaithful, FullPacked: report.fullPacked,
		PlanDigest: report.planDigest, ParameterDigest: report.parameterDigest,
		ProfileDigest: report.profileDigest, ShapeDigest: report.shapeDigest,
		PolicyDigest: report.policyDigest, ProbeDigest: report.probeDigest, Snapshot: report.snapshot,
		CurrentSystemUsedBytes: report.currentSystemUsedBytes, CapacityLimitBytes: report.capacityLimitBytes,
		ProjectedIncrementalPeakBytes: report.projectedIncrementalPeakBytes, GuardBytes: report.guardBytes,
		GuardedRequirementBytes:  report.guardedRequirementBytes,
		ProjectedSystemUsedBytes: report.projectedSystemUsedBytes, RemainingBytes: report.remainingBytes,
	}, "Gao N16 packing L11 capacity report")
}

type gaoN16PackingL11PermitDigestRecord struct {
	SchemaVersion, AdaptationLabel, EvidenceScope                         string
	Maturity                                                              Maturity
	Decision                                                              CapacityDecision
	SourceFaithful, FullPacked                                            bool
	PlanDigest, ParameterDigest, ProfileDigest, ShapeDigest, PolicyDigest string
	ProbeDigest, ReportDigest                                             string
}

func digestGaoN16PackingL11Permit(permit GaoN16PackingL11CapacityPermit) (string, error) {
	return digestCapacityRecord(gaoN16PackingL11PermitDigestRecord{
		SchemaVersion: permit.schema, AdaptationLabel: permit.adaptationLabel, EvidenceScope: permit.evidenceScope,
		Maturity: permit.maturity, Decision: permit.decision,
		SourceFaithful: permit.sourceFaithful, FullPacked: permit.fullPacked,
		PlanDigest: permit.planDigest, ParameterDigest: permit.parameterDigest,
		ProfileDigest: permit.profileDigest, ShapeDigest: permit.shapeDigest, PolicyDigest: permit.policyDigest,
		ProbeDigest: permit.probeDigest, ReportDigest: permit.reportDigest,
	}, "Gao N16 packing L11 capacity permit")
}

func validateGaoN16PackingL11KeySchedule(shape GaoN16PackingL11CapacityShape) error {
	stc, err := gaoN16PackingL11GaloisElements(shape.stcRotationInputs, shape.ringDegree)
	if err != nil {
		return artifactCapacityBlocked("cannot derive L11 STC Galois elements", err)
	}
	cts, err := gaoN16PackingL11GaloisElements(shape.ctsRotationInputs, shape.ringDegree)
	if err != nil {
		return artifactCapacityBlocked("cannot derive L11 CTS Galois elements", err)
	}
	trace, err := gaoN16PackingL11GaloisElements(shape.traceRotations, shape.ringDegree)
	if err != nil {
		return artifactCapacityBlocked("cannot derive L11 Trace Galois elements", err)
	}
	nthRoot, err := checkedUint64Product(shape.ringDegree, 2)
	if err != nil || nthRoot == 0 || nthRoot&(nthRoot-1) != 0 {
		return artifactCapacityBlocked("invalid L11 Galois modulus", err)
	}
	if shape.conjugationGaloisElement != nthRoot-1 || !equalUint64s(shape.stcGaloisElements, stc) ||
		!equalUint64s(shape.ctsGaloisElements, cts) || !equalUint64s(shape.traceGaloisElements, trace) {
		return artifactCapacityBlocked("L11 grouped Galois schedule drifted", nil)
	}
	exponents := uniqueSortedInt64(append(
		append(append([]int64{-1}, uint64sToInt64s(shape.stcRotationInputs)...), uint64sToInt64s(shape.ctsRotationInputs)...),
		uint64sToInt64s(shape.traceRotations)...,
	))
	union := uniqueSortedUint64(append(
		append(append(append([]uint64(nil), stc...), cts...), trace...),
		shape.conjugationGaloisElement,
	))
	if !equalInt64s(shape.evaluationRotationExponents, exponents) ||
		!equalUint64s(shape.evaluationGaloisElements, union) ||
		uint64(len(union)) != shape.dftTraceConjugationKeyCount || len(union) != 38 {
		return artifactCapacityBlocked("L11 evaluation-key union is not the exact deduplicated 38-key schedule", nil)
	}
	return nil
}

func defaultGaoN16PackingL11GaloisElements(rotations []uint64, ringDegree uint64) []uint64 {
	values, err := gaoN16PackingL11GaloisElements(rotations, ringDegree)
	if err != nil {
		return nil
	}
	return values
}

// gaoN16PackingL11GaloisElements is the arithmetic equivalent of Lattigo's
// GaloisElement(k)=5^k mod 2N for the power-of-two CKKS ring. It creates no
// parameter object or cryptographic artifact.
func gaoN16PackingL11GaloisElements(rotations []uint64, ringDegree uint64) ([]uint64, error) {
	nthRoot, err := checkedUint64Product(ringDegree, 2)
	if err != nil {
		return nil, err
	}
	if nthRoot == 0 || nthRoot&(nthRoot-1) != 0 {
		return nil, errors.New("2N is not a positive power of two")
	}
	result := make([]uint64, len(rotations))
	for i, rotation := range rotations {
		result[i] = gaoN16PackingL11ModExpPow2(5, rotation&(nthRoot-1), nthRoot)
	}
	return uniqueSortedUint64(result), nil
}

func gaoN16PackingL11ModExpPow2(base, exponent, modulus uint64) uint64 {
	mask := modulus - 1
	result := uint64(1)
	base &= mask
	for exponent != 0 {
		if exponent&1 != 0 {
			_, result = bits.Mul64(result, base)
			result &= mask
		}
		_, base = bits.Mul64(base, base)
		base &= mask
		exponent >>= 1
	}
	return result
}

func uniqueSortedUint64(values []uint64) []uint64 {
	result := append([]uint64(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func uniqueSortedInt64(values []int64) []int64 {
	result := append([]int64(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func uint64sToInt64s(values []uint64) []int64 {
	result := make([]int64, len(values))
	for i, value := range values {
		result[i] = int64(value)
	}
	return result
}

func equalUint64s(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalInt64s(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalGaoN16PackingL11Estimates(left, right []GaoN16PackingL11CapacityEstimate) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
