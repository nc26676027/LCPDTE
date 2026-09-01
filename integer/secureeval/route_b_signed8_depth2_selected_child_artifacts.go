package secureeval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"sort"

	"dt_go/integer/homchain"
	"dt_go/integer/z2n"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/lintrans"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type routeBSigned8Depth2SelectedChildRootArtifacts struct {
	threshold       *rlwe.Plaintext
	parameterDigest string
	thresholdDigest string
}

type routeBSigned8Depth2SelectedChildArtifacts struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	scalePlan routeBSigned8Depth2SelectedChildScalePlan

	phaseBroadcast lintrans.LinearTransformation
	childBroadcast lintrans.LinearTransformation
	conditioner    *rlwe.Plaintext
	rootOne        *rlwe.Plaintext
	thresholdDelta *rlwe.Plaintext
	leftThreshold  *rlwe.Plaintext
	childOne       *rlwe.Plaintext
	baseLeaf       *rlwe.Plaintext
	alphaLeaf      *rlwe.Plaintext
	betaLeaf       *rlwe.Plaintext
	gammaLeaf      *rlwe.Plaintext

	periodic *homchain.GaoPeriodicBooleanN16L11Circuit
	a2sign   *routeBSigned8Depth2SelectedChildA2SignCircuit

	phaseBroadcastSourceDigest    string
	phaseBroadcastCompiledDigest  string
	phaseBroadcastEncodedBytes    uint64
	phaseBroadcastRotationIndexes []int
	phaseBroadcastGaloisElements  []uint64
	childBroadcastSourceDigest    string
	childBroadcastCompiledDigest  string
	childBroadcastEncodedBytes    uint64
	conditionerDigest             string
	rootOneDigest                 string
	thresholdDeltaDigest          string
	leftThresholdDigest           string
	childOneDigest                string
	terminalOperandDigests        [4]string
}

func newRouteBSigned8Depth2SelectedChildRootArtifacts(
	params ckks.Parameters,
	model RouteBSigned8Depth2SelectedChildModel,
) (routeBSigned8Depth2SelectedChildRootArtifacts, error) {
	canonical, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, err
	}
	if !params.Equal(&canonical) {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, lineagef("selected-child root artifacts require the canonical Route-B parameters")
	}
	if err = validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, err
	}
	encoder := ckks.NewEncoder(params, routeBSigned8RootTreeEncoderPrecision)
	values, err := routeBSigned8ThresholdSlots(model.thresholds[0])
	if err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, err
	}
	threshold, err := encodeRouteBSigned8Plaintext(params, encoder, values, routeBSigned8Depth2SelectedChildInputLevel, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, fmt.Errorf("secureeval: encode selected-child root threshold: %w", err)
	}
	parameterPayload, err := params.MarshalBinary()
	if err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, err
	}
	thresholdDigest, err := routeBSigned8RootTreePlaintextDigest(threshold)
	if err != nil {
		return routeBSigned8Depth2SelectedChildRootArtifacts{}, err
	}
	return routeBSigned8Depth2SelectedChildRootArtifacts{
		threshold: threshold, parameterDigest: routeBSigned8DigestBytes(parameterPayload), thresholdDigest: thresholdDigest,
	}, nil
}

func newRouteBSigned8Depth2SelectedChildArtifacts(
	evaluator *bootstrapping.Evaluator,
	model RouteBSigned8Depth2SelectedChildModel,
) (routeBSigned8Depth2SelectedChildArtifacts, error) {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil || evaluator.MemEvaluationKeySet == nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, lineagef("selected-child supplemental evaluator graph is incomplete")
	}
	params := evaluator.BootstrappingParameters
	canonical, err := canonicalRouteBSigned8RootTreeParameters()
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	if !params.Equal(&canonical) || !params.Equal(&evaluator.ResidualParameters) {
		return routeBSigned8Depth2SelectedChildArtifacts{}, lineagef("selected-child supplemental artifacts require the canonical N16/L11 Route-B parameters")
	}
	if err = validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	plan, err := newRouteBSigned8Depth2SelectedChildScalePlan(params)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	encoder := ckks.NewEncoder(params, routeBSigned8RootTreeEncoderPrecision)
	phaseBroadcast, phaseSource, phaseCompiled, phaseBytes, phaseRotations, phaseGalois, err :=
		newRouteBSigned8Depth2SelectedChildPhaseBroadcast(params, encoder)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	childBroadcast, childSource, childCompiled, childBytes, _, _, err := newRouteBSigned8Broadcast(params, encoder)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	encodeConstant := func(name string, value float64, level int, scale rlwe.Scale) (*rlwe.Plaintext, string, error) {
		plaintext, encodeErr := encodeRouteBSigned8Plaintext(params, encoder, routeBSigned8ConstantSlots(value), level, scale)
		if encodeErr != nil {
			return nil, "", fmt.Errorf("secureeval: encode selected-child %s: %w", name, encodeErr)
		}
		digest, digestErr := routeBSigned8RootTreePlaintextDigest(plaintext)
		return plaintext, digest, digestErr
	}
	conditioner, conditionerDigest, err := encodeConstant("selector conditioner", 1, 8, plan.conditionerScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	rootOne, rootOneDigest, err := encodeConstant("conditioned root one", 1, 7, plan.conditionedRootScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	leftSlots, err := routeBSigned8ThresholdSlots(model.thresholds[1])
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	rightSlots, err := routeBSigned8ThresholdSlots(model.thresholds[2])
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	deltaSlots, err := routeBSigned8ComplexVectorDifference(rightSlots, leftSlots)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	thresholdDelta, err := encodeRouteBSigned8Plaintext(params, encoder, deltaSlots, 7, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, fmt.Errorf("secureeval: encode selected-child threshold delta: %w", err)
	}
	leftThreshold, err := encodeRouteBSigned8Plaintext(params, encoder, leftSlots, 6, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, fmt.Errorf("secureeval: encode selected-child left threshold: %w", err)
	}
	thresholdDeltaDigest, err := routeBSigned8RootTreePlaintextDigest(thresholdDelta)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	leftThresholdDigest, err := routeBSigned8RootTreePlaintextDigest(leftThreshold)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	childOne, childOneDigest, err := encodeConstant("child Boolean one", 1, 3, params.DefaultScale())
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	leaves := model.leaves
	alpha, beta, gamma := routeBSigned8Depth2SelectedChildLeafCoefficients(leaves)
	baseLeaf, baseDigest, err := encodeConstant("base leaf", leaves[0], 1, plan.terminalOutputScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	alphaLeaf, alphaDigest, err := encodeConstant("alpha leaf", alpha, 3, plan.alphaOperandScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	betaLeaf, betaDigest, err := encodeConstant("beta leaf", beta, 3, plan.betaOperandScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	gammaLeaf, gammaDigest, err := encodeConstant("gamma leaf", gamma, 3, plan.gammaOperandScale)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	periodic, err := homchain.NewGaoPeriodicBooleanN16L11Circuit(params, encoder)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	a2sign, err := newRouteBSigned8Depth2SelectedChildA2SignCircuit(evaluator, encoder)
	if err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	artifacts := routeBSigned8Depth2SelectedChildArtifacts{
		params: params, encoder: encoder, scalePlan: plan,
		phaseBroadcast: phaseBroadcast, childBroadcast: childBroadcast,
		conditioner: conditioner, rootOne: rootOne, thresholdDelta: thresholdDelta, leftThreshold: leftThreshold,
		childOne: childOne, baseLeaf: baseLeaf, alphaLeaf: alphaLeaf, betaLeaf: betaLeaf, gammaLeaf: gammaLeaf,
		periodic: periodic, a2sign: a2sign,
		phaseBroadcastSourceDigest: phaseSource, phaseBroadcastCompiledDigest: phaseCompiled,
		phaseBroadcastEncodedBytes: phaseBytes, phaseBroadcastRotationIndexes: phaseRotations,
		phaseBroadcastGaloisElements: phaseGalois,
		childBroadcastSourceDigest:   childSource, childBroadcastCompiledDigest: childCompiled,
		childBroadcastEncodedBytes: childBytes, conditionerDigest: conditionerDigest, rootOneDigest: rootOneDigest,
		thresholdDeltaDigest: thresholdDeltaDigest, leftThresholdDigest: leftThresholdDigest,
		childOneDigest:         childOneDigest,
		terminalOperandDigests: [4]string{baseDigest, alphaDigest, betaDigest, gammaDigest},
	}
	if err = preflightRouteBSigned8Depth2SelectedChildKeys(evaluator, artifacts); err != nil {
		return routeBSigned8Depth2SelectedChildArtifacts{}, err
	}
	return artifacts, nil
}

func newRouteBSigned8Depth2SelectedChildPhaseBroadcast(
	params ckks.Parameters,
	encoder *ckks.Encoder,
) (
	transformation lintrans.LinearTransformation,
	sourceDigest, compiledDigest string,
	encodedBytes uint64,
	rotations []int,
	galois []uint64,
	err error,
) {
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return transformation, "", "", 0, nil, nil, err
	}
	coefficients := ringZ.TauInverse().Coefficients()
	if len(coefficients) != 8 {
		return transformation, "", "", 0, nil, nil, lineagef("selected-child tau inverse coefficient count changed")
	}
	diagonals := make(lintrans.Diagonals[*bignum.Complex], 4)
	for offset := 0; offset < 4; offset++ {
		values := make([]*bignum.Complex, routeBSigned8RootTreeSlots)
		for index := range values {
			values[index] = bignum.NewComplex().SetPrec(routeBSigned8RootTreeEncoderPrecision)
		}
		outputColumn := routeBSigned8RootTreeBroadcastColumn - offset
		for word := 0; word < routeBSigned8RootTreeWords; word++ {
			values[4*word+outputColumn].Real().Set(coefficients[outputColumn])
		}
		diagonals[offset] = values
	}
	parameters := lintrans.Parameters{
		DiagonalsIndexList: []int{0, 1, 2, 3},
		LevelQ:             routeBSigned8Depth2SelectedChildPhaseBroadcastLevel, LevelP: routeBSigned8RootTreeBroadcastLevelP,
		Scale:         rlwe.NewScale(params.Q()[routeBSigned8Depth2SelectedChildPhaseBroadcastLevel]),
		LogDimensions: ring.Dimensions{Rows: 0, Cols: 11}, LogBabyStepGiantStepRatio: 0,
	}
	transformation = lintrans.NewTransformation(params, parameters)
	if err = lintrans.Encode(encoder, diagonals, transformation); err != nil {
		return transformation, "", "", 0, nil, nil, fmt.Errorf("secureeval: encode selected-child phase broadcast: %w", err)
	}
	sourceDigest = routeBSigned8Depth2SelectedChildPhaseBroadcastSourceDigest(coefficients)
	compiledDigest, encodedBytes, err = routeBSigned8Depth2SelectedChildTransformationDigest(
		"phase-broadcast-v1", transformation,
	)
	if err != nil {
		return transformation, "", "", 0, nil, nil, err
	}
	rotations = routeBSigned8BroadcastRotations(transformation)
	galois = transformation.GaloisElements(params)
	slices.Sort(galois)
	galois = slices.Compact(galois)
	galois = slices.DeleteFunc(galois, func(element uint64) bool { return element == 1 })
	if !slices.Equal(rotations, routeBSigned8RootTreeExpectedBroadcastRotations()) ||
		!slices.Equal(galois, routeBSigned8RootTreeExpectedBroadcastGalois()) || len(transformation.Vec) != 4 || encodedBytes == 0 {
		return transformation, "", "", 0, nil, nil, lineagef("selected-child phase broadcast topology changed")
	}
	return transformation, sourceDigest, compiledDigest, encodedBytes, rotations, galois, nil
}

func routeBSigned8Depth2SelectedChildPhaseBroadcastSourceDigest(coefficients []*big.Float) string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "lcpdte-route-b-selected-child-phase-broadcast-v1|words=%d|slots=%d|source-column=3|precision=%d",
		routeBSigned8RootTreeWords, routeBSigned8RootTreeSlots, routeBSigned8RootTreeEncoderPrecision)
	for column := 0; column < 4; column++ {
		_, _ = fmt.Fprintf(hasher, "|column=%d,coefficient=%s", column, coefficients[column].Text('x', -1))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func routeBSigned8Depth2SelectedChildTransformationDigest(
	name string,
	transformation lintrans.LinearTransformation,
) (string, uint64, error) {
	if transformation.MetaData == nil || transformation.Vec == nil {
		return "", 0, lineagef("selected-child %s transformation is empty", name)
	}
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "lcpdte-route-b-selected-child-%s|Q=%d|P=%d|N1=%d|bsgs=%d|dims=%d,%d|",
		name, transformation.LevelQ, transformation.LevelP, transformation.N1,
		transformation.LogBabyStepGiantStepRatio, transformation.LogDimensions.Rows, transformation.LogDimensions.Cols)
	keys := make([]int, 0, len(transformation.Vec))
	for key := range transformation.Vec {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	var bytes uint64
	for _, key := range keys {
		var keyBytes [8]byte
		binary.LittleEndian.PutUint64(keyBytes[:], uint64(key))
		_, _ = hasher.Write(keyBytes[:])
		poly := transformation.Vec[key]
		written, err := poly.WriteTo(hasher)
		if err != nil || written != int64(poly.BinarySize()) {
			return "", 0, lineagef("selected-child %s transformation serialization changed", name)
		}
		bytes += uint64(written)
	}
	return hex.EncodeToString(hasher.Sum(nil)), bytes, nil
}

func routeBSigned8Depth2SelectedChildCompiledPairDigest(pair homchain.CompiledPair) (string, uint64, error) {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("lcpdte-route-b-selected-child-low-ingress-special-b0-v1\x00"))
	var total uint64
	for index, transformation := range []lintrans.LinearTransformation{pair.Low, pair.High} {
		digest, bytes, err := routeBSigned8Depth2SelectedChildTransformationDigest(fmt.Sprintf("special-b0-half-%d", index), transformation)
		if err != nil {
			return "", 0, err
		}
		_, _ = hasher.Write([]byte(digest))
		total += bytes
	}
	return hex.EncodeToString(hasher.Sum(nil)), total, nil
}

func routeBSigned8ComplexVectorDifference(a, b []*bignum.Complex) ([]*bignum.Complex, error) {
	if len(a) != routeBSigned8RootTreeSlots || len(b) != len(a) {
		return nil, lineagef("selected-child threshold vector shape changed")
	}
	result := make([]*bignum.Complex, len(a))
	for index := range result {
		result[index] = bignum.NewComplex().SetPrec(routeBSigned8RootTreeEncoderPrecision)
		result[index].Real().Sub(a[index].Real(), b[index].Real())
		result[index].Imag().Sub(a[index].Imag(), b[index].Imag())
	}
	return result, nil
}

func preflightRouteBSigned8Depth2SelectedChildKeys(
	evaluator *bootstrapping.Evaluator,
	artifacts routeBSigned8Depth2SelectedChildArtifacts,
) error {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.MemEvaluationKeySet == nil || artifacts.a2sign == nil {
		return lineagef("selected-child key preflight graph is incomplete")
	}
	required := append([]uint64(nil), artifacts.phaseBroadcastGaloisElements...)
	required = append(required, artifacts.a2sign.galoisElements...)
	required = append(required, artifacts.a2sign.secondSTCReport.GaloisElements...)
	slices.Sort(required)
	required = slices.Compact(required)
	installed := evaluator.MemEvaluationKeySet.GetGaloisKeysList()
	slices.Sort(installed)
	for _, element := range required {
		if _, present := slices.BinarySearch(installed, element); !present {
			return lineagef("selected-child Galois element %d is outside the installed key union", element)
		}
		key, err := evaluator.MemEvaluationKeySet.GetGaloisKey(element)
		if err != nil || key == nil || key.GaloisElement != element || key.LevelP() < 6 {
			return lineagef("selected-child Galois key %d is absent or incomplete", element)
		}
	}
	relinearizationKey, err := evaluator.MemEvaluationKeySet.GetRelinearizationKey()
	if err != nil || relinearizationKey == nil || relinearizationKey.LevelQ() < 3 || relinearizationKey.LevelP() < 6 {
		return lineagef("selected-child relinearization key is absent or incomplete")
	}
	return nil
}

type routeBSigned8Depth2SelectedChildA2SignCircuit struct {
	triangle                                       *homchain.Evaluator
	specialB0                                      homchain.CompiledPair
	secondSTC                                      dft.Matrix
	secondSTCReport                                RouteBA2BFullSecondSTCReport
	iter1Mask, idScale                             *rlwe.Plaintext
	kernel                                         *homchain.GaoA2BKernelN16L11Circuit
	transformSourceDigest, transformCompiledDigest string
	transformEncodedBytes                          uint64
	iter1MaskDigest, idScaleDigest                 string
	rotationIndexes                                []int
	galoisElements                                 []uint64
}

func newRouteBSigned8Depth2SelectedChildA2SignCircuit(
	evaluator *bootstrapping.Evaluator,
	encoder *ckks.Encoder,
) (*routeBSigned8Depth2SelectedChildA2SignCircuit, error) {
	if evaluator == nil || evaluator.Evaluator == nil || evaluator.DFTEvaluator == nil ||
		evaluator.MemEvaluationKeySet == nil || encoder == nil {
		return nil, lineagef("selected-child A2Sign circuit graph is incomplete")
	}
	params := evaluator.BootstrappingParameters
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return nil, err
	}
	specifications, err := homchain.NewSpecificationsFromRing(ringZ, routeBA2BFirstRoundWords)
	if err != nil {
		return nil, err
	}
	source := specifications.VSpecialB0Pair()
	options := homchain.CompileOptions{
		LevelQ: 5, LevelP: 6, Scale: rlwe.NewScale(params.Q()[5]),
		LogBabyStepGiantStepRatio: routeBA2BFirstRoundBSGSRatio,
	}
	specialB0, err := homchain.CompilePair(params, encoder, source, options)
	if err != nil {
		return nil, fmt.Errorf("secureeval: compile selected-child low-ingress special-b0: %w", err)
	}
	rotations := specialB0.RotationIndexes()
	galois := homchain.GaloisElementsForZToC(params, specialB0)
	transformSourceDigest, err := digestRouteBA2BTransformSource(source, options, rotations, galois)
	if err != nil {
		return nil, err
	}
	transformCompiledDigest, transformEncodedBytes, err := routeBSigned8Depth2SelectedChildCompiledPairDigest(specialB0)
	if err != nil {
		return nil, err
	}
	secondSTC, secondSTCReport, err := buildRouteBA2BFullSecondSTC(evaluator)
	if err != nil {
		return nil, err
	}
	iter1Mask, idScale, iter1MaskDigest, idScaleDigest, err := newRouteBA2BFullOperands(params)
	if err != nil {
		return nil, err
	}
	kernel, err := homchain.NewGaoA2BKernelN16L11Circuit(params, encoder)
	if err != nil {
		return nil, err
	}
	if specialB0.Low.LevelQ != 5 || specialB0.High.LevelQ != 5 ||
		specialB0.Low.N1 != 4 || specialB0.High.N1 != 4 || secondSTC.LevelQ != 3 ||
		iter1Mask.Level() != 4 || idScale.Level() != 5 {
		return nil, lineagef("selected-child A2Sign schedule changed")
	}
	return &routeBSigned8Depth2SelectedChildA2SignCircuit{
		triangle: homchain.NewEvaluator(evaluator.Evaluator), specialB0: specialB0,
		secondSTC: secondSTC, secondSTCReport: secondSTCReport,
		iter1Mask: iter1Mask, idScale: idScale, kernel: kernel,
		transformSourceDigest: transformSourceDigest, transformCompiledDigest: transformCompiledDigest,
		transformEncodedBytes: transformEncodedBytes, iter1MaskDigest: iter1MaskDigest, idScaleDigest: idScaleDigest,
		rotationIndexes: rotations, galoisElements: galois,
	}, nil
}
