package secureeval

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"slices"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/dft"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

const (
	gaoFullPackedSpecialB0BSGSRatio = 2
	gaoFullPackedZ2CInputLevel      = 4
	gaoFullPackedCoreLevel          = 3
	gaoFullPackedMaskedLevel        = 2
	gaoFullPackedScaleDriftBound    = 0x1p-40
)

// gaoFullPackedA2BEvaluator owns the complete Gao-compatible N=65536
// evaluation graph. Construction is intentionally separate from EvaluateNew:
// bootstrapping keys, operands and two key-bound polynomial evaluators are
// reused, while the shared STC and CTS factors are resident and prevalidated.
//
// The object is not safe for concurrent use because Lattigo evaluators reuse
// scratch buffers. Callers that need concurrency must construct one evaluator
// per worker. Close removes both factor stores and releases the evaluator
// graph.
type gaoFullPackedA2BEvaluator struct {
	params ckks.Parameters

	source    *bootstrapping.Evaluator
	triangle  *homchain.Evaluator
	specialB0 homchain.CompiledPair

	ctsFactors *gaoFullPackedFactorStore
	stcFactors *gaoFullPackedFactorStore

	kernel0 *homchain.GaoA2BKernelN16FullPackedEvaluator
	kernel1 *homchain.GaoA2BKernelN16FullPackedEvaluator
	closed  bool
}

// newGaoFullPackedA2BEvaluator constructs the reusable server-side evaluator
// for exactly 8,192 uint8 words represented by all 32,768 complex CKKS slots.
// The caller's secret key must use the canonical N=65536 Gao parameter set.
func newGaoFullPackedA2BEvaluator(secretKey *rlwe.SecretKey) (result *gaoFullPackedA2BEvaluator, err error) {
	if secretKey == nil {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B secret key is nil")
	}

	raw, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		return nil, err
	}
	prepared, err := bootstrapping.PrepareParameters(raw)
	if err != nil {
		return nil, fmt.Errorf("secureeval: prepare Gao full-packed A2B parameters: %w", err)
	}
	if err = prepared.Verify(); err != nil {
		return nil, fmt.Errorf("secureeval: verify Gao full-packed A2B parameters: %w", err)
	}
	effective := prepared.EffectiveParameters()
	params := effective.BootstrappingParameters
	if params.LogN() != 16 || params.LogMaxSlots() != gaoFullPackedLogSlots ||
		params.MaxLevel() != 20 || params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B parameter shape changed")
	}
	if secretKey.Value.Q.N() != params.N() {
		return nil, fmt.Errorf(
			"secureeval: Gao full-packed A2B secret-key degree %d, want %d",
			secretKey.Value.Q.N(), params.N(),
		)
	}

	// Encode each DFT factor before generating evaluation keys. A private
	// temporary store separates the large encoding workspace from keygen; once
	// the evaluator graph is complete, the factors are loaded and validated
	// exactly once for resident prepared-online evaluation.
	encoder := ckks.NewEncoder(params)
	var stores []*gaoFullPackedFactorStore
	defer func() {
		if result != nil {
			return
		}
		for _, store := range stores {
			_ = store.Close()
		}
	}()
	ctsFactors, err := newGaoFullPackedFactorStore(
		params, effective.CoeffsToSlotsParameters, encoder, "", "primary-cts",
	)
	if err != nil {
		return nil, err
	}
	stores = append(stores, ctsFactors)
	stcFactors, err := newGaoFullPackedFactorStore(
		params, effective.SlotsToCoeffsParameters, encoder, "", "primary-stc",
	)
	if err != nil {
		return nil, err
	}
	stores = append(stores, stcFactors)
	// Ensure the last multi-gigabyte encoded donor is reclaimed before keygen.
	runtime.GC()

	specialB0, err := newGaoFullPackedSpecialB0(params, encoder)
	if err != nil {
		return nil, err
	}
	requiredSpecialGalois := homchain.GaloisElementsForZToC(params, specialB0)

	evaluationKeys, bootstrappingSecretKey, err := effective.GenEvaluationKeys(secretKey)
	if err != nil {
		return nil, fmt.Errorf("secureeval: generate Gao full-packed A2B evaluation keys: %w", err)
	}
	if err = addGaoFullPackedSpecialB0Keys(params, evaluationKeys, bootstrappingSecretKey, requiredSpecialGalois); err != nil {
		return nil, err
	}
	// Only the bootstrap stages used by Gao's MR0 prefix are assembled here;
	// factor-backed DFT evaluation replaces the resident matrix fields.
	heEvaluator := ckks.NewEvaluator(params, evaluationKeys)
	source := &bootstrapping.Evaluator{
		Parameters: effective, EvaluationKeys: evaluationKeys,
		Evaluator: heEvaluator, Mod1Parameters: prepared.Mod1Parameters(),
	}
	source.DFTEvaluator = dft.NewEvaluator(params, heEvaluator)
	if source == nil || source.Evaluator == nil || source.DFTEvaluator == nil ||
		source.EvaluationKeys == nil || source.MemEvaluationKeySet == nil {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B evaluator graph is incomplete")
	}
	for _, element := range requiredSpecialGalois {
		if key, keyErr := source.MemEvaluationKeySet.GetGaloisKey(element); keyErr != nil || key == nil {
			return nil, fmt.Errorf("secureeval: Gao full-packed A2B special-b0 key %d is missing", element)
		}
	}

	kernelEncoder := ckks.NewEncoder(params, z2n.DefaultPrecision)
	kernelCircuit, err := homchain.NewGaoA2BKernelN16FullPackedCircuit(params, kernelEncoder)
	if err != nil {
		return nil, fmt.Errorf("secureeval: construct Gao full-packed A2B kernel: %w", err)
	}
	memKeyView := source.Evaluator.WithKey(source.MemEvaluationKeySet)
	if memKeyView == nil || memKeyView.EvaluationKeySet != source.MemEvaluationKeySet {
		return nil, fmt.Errorf("secureeval: bind Gao full-packed A2B in-memory key view")
	}
	kernel0, err := kernelCircuit.BindEvaluator(memKeyView)
	if err != nil {
		return nil, fmt.Errorf("secureeval: bind Gao full-packed A2B iter0 kernel: %w", err)
	}
	kernel1, err := kernelCircuit.BindEvaluator(memKeyView)
	if err != nil {
		return nil, fmt.Errorf("secureeval: bind Gao full-packed A2B iter1 kernel: %w", err)
	}
	if kernel0 == kernel1 || kernel0.CoefficientSlots() != gaoFullPackedSlots ||
		kernel1.CoefficientSlots() != gaoFullPackedSlots {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B kernel reuse shape changed")
	}
	// Release key-generation scratch before admitting the resident DFT payload.
	// Timed Evaluate calls must not perform factor I/O or deserialization.
	runtime.GC()
	for _, preparedStore := range []struct {
		name  string
		store *gaoFullPackedFactorStore
	}{
		{name: "CTS", store: ctsFactors},
		{name: "STC", store: stcFactors},
	} {
		if err = preparedStore.store.PrepareResident(); err != nil {
			return nil, fmt.Errorf("secureeval: prepare resident Gao full-packed %s factors: %w", preparedStore.name, err)
		}
	}

	result = &gaoFullPackedA2BEvaluator{
		params: params, source: source,
		triangle: homchain.NewEvaluator(source.Evaluator), specialB0: specialB0,
		ctsFactors: ctsFactors, stcFactors: stcFactors,
		kernel0: kernel0, kernel1: kernel1,
	}
	return result, nil
}

func newGaoFullPackedSpecialB0(
	params ckks.Parameters,
	encoder *ckks.Encoder,
) (homchain.CompiledPair, error) {
	// Gao's source constants carry 128 fractional bits. That precision is
	// retained while the final CKKS encoding uses the profile's native encoder.
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, 128)
	if err != nil {
		return homchain.CompiledPair{}, err
	}
	specifications, err := homchain.NewSpecificationsFromRing(ringZ, gaoFullPackedWords)
	if err != nil {
		return homchain.CompiledPair{}, fmt.Errorf("secureeval: construct Gao full-packed special-b0: %w", err)
	}
	compiled, err := homchain.CompilePair(
		params,
		encoder,
		specifications.VSpecialB0Pair(),
		homchain.CompileOptions{
			LevelQ: gaoFullPackedZ2CInputLevel, LevelP: params.MaxLevelP(),
			Scale:                     rlwe.NewScale(params.Q()[gaoFullPackedZ2CInputLevel]),
			LogBabyStepGiantStepRatio: gaoFullPackedSpecialB0BSGSRatio,
		},
	)
	if err != nil {
		return homchain.CompiledPair{}, fmt.Errorf("secureeval: compile Gao full-packed special-b0: %w", err)
	}
	if compiled.Low.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}) ||
		compiled.High.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}) ||
		compiled.Low.LevelQ != gaoFullPackedZ2CInputLevel ||
		compiled.High.LevelQ != gaoFullPackedZ2CInputLevel {
		return homchain.CompiledPair{}, fmt.Errorf("secureeval: Gao full-packed special-b0 shape changed")
	}
	return compiled, nil
}

func addGaoFullPackedSpecialB0Keys(
	params ckks.Parameters,
	evaluationKeys *bootstrapping.EvaluationKeys,
	secretKey *rlwe.SecretKey,
	required []uint64,
) error {
	if evaluationKeys == nil || evaluationKeys.MemEvaluationKeySet == nil || secretKey == nil {
		return fmt.Errorf("secureeval: Gao full-packed A2B evaluation-key graph is incomplete")
	}
	present := make(map[uint64]struct{}, len(evaluationKeys.GetGaloisKeysList()))
	for _, element := range evaluationKeys.GetGaloisKeysList() {
		present[element] = struct{}{}
	}
	missing := make([]uint64, 0, len(required))
	for _, element := range required {
		if _, ok := present[element]; !ok {
			missing = append(missing, element)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	missing = slices.Compact(missing)
	generated := rlwe.NewKeyGenerator(params).GenGaloisKeysNew(missing, secretKey)
	for _, key := range generated {
		if key == nil {
			return fmt.Errorf("secureeval: generated nil Gao full-packed A2B special-b0 key")
		}
		evaluationKeys.GaloisKeys[key.GaloisElement] = key
	}
	return nil
}

// Parameters returns the canonical full-packed CKKS parameters used by the
// evaluator. The value is suitable for session-side encoding and encryption.
func (e *gaoFullPackedA2BEvaluator) Parameters() ckks.Parameters {
	if e == nil {
		return ckks.Parameters{}
	}
	return e.params
}

// adjustGaoFullPackedToLevel implements Gao/OpenFHE's
// AdjustCiphertextToLevel for the fixed S43 scale. OpenFHE levels count the
// moduli already consumed, whereas Lattigo levels name the highest remaining
// Q limb. The operation first keeps Q[0:target+2], then multiplies by the last
// retained modulus and rescales once, yielding Q[0:target+1] without changing
// the encoded value or target scale.
func adjustGaoFullPackedToLevel(
	evaluator *ckks.Evaluator,
	input *rlwe.Ciphertext,
	targetLevel int,
	targetScale rlwe.Scale,
) (*rlwe.Ciphertext, error) {
	return adjustGaoFullPackedScaledToLevel(evaluator, input, targetLevel, targetScale, 1, 1)
}

func adjustGaoFullPackedScaledToLevel(
	evaluator *ckks.Evaluator,
	input *rlwe.Ciphertext,
	targetLevel int,
	targetScale rlwe.Scale,
	numerator, denominator uint64,
) (*rlwe.Ciphertext, error) {
	if evaluator == nil || evaluator.GetParameters() == nil || input == nil || input.MetaData == nil {
		return nil, fmt.Errorf("secureeval: Gao full-packed level adjustment input is nil")
	}
	params := evaluator.GetParameters()
	if targetLevel < 0 || targetLevel >= input.Level() || targetLevel+1 > params.MaxLevel() ||
		input.Degree() != 1 || !input.Scale.Equal(targetScale) || numerator == 0 || denominator == 0 {
		return nil, fmt.Errorf(
			"secureeval: cannot adjust Gao full-packed ciphertext from L%d to L%d at the requested scale",
			input.Level(), targetLevel,
		)
	}
	preRescaleLevel := targetLevel + 1
	adjusted := ckks.NewCiphertext(*params, input.Degree(), preRescaleLevel)
	*adjusted.MetaData = *input.MetaData
	for index := range adjusted.Value {
		adjusted.Value[index].CopyLvl(preRescaleLevel, input.Value[index])
	}
	modulus := params.Q()[preRescaleLevel]
	factor := new(big.Int).Mul(new(big.Int).SetUint64(modulus), new(big.Int).SetUint64(numerator))
	divisor := new(big.Int).SetUint64(denominator)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(factor, divisor, remainder)
	if remainder.Lsh(remainder, 1).Cmp(divisor) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if err := evaluator.Mul(adjusted, quotient, adjusted); err != nil {
		return nil, fmt.Errorf("secureeval: multiply Gao full-packed level-adjustment factor: %w", err)
	}
	adjusted.Scale = adjusted.Scale.Mul(rlwe.NewScale(modulus))
	if err := evaluator.Rescale(adjusted, adjusted); err != nil {
		return nil, fmt.Errorf("secureeval: rescale Gao full-packed level adjustment: %w", err)
	}
	adjusted.Scale = targetScale
	return adjusted, nil
}

// dropGaoFullPackedIdentityMaskLevel implements the level transition caused
// by Gao/OpenFHE's full-packed A2B mask. For zN=8 and w=4, each of the two
// masks selects all 32,768 complex slots and is therefore the constant one.
// Dropping the unused top modulus preserves the value and scale while avoiding
// an identity plaintext multiplication and rescale.
func dropGaoFullPackedIdentityMaskLevel(
	evaluator *ckks.Evaluator,
	input *rlwe.Ciphertext,
) (*rlwe.Ciphertext, error) {
	if evaluator == nil || evaluator.GetParameters() == nil || input == nil || input.MetaData == nil ||
		input.Level() != gaoFullPackedCoreLevel || input.Degree() != 1 ||
		input.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}) {
		return nil, fmt.Errorf("secureeval: Gao full-packed identity-mask input state changed")
	}
	evaluator.DropLevel(input, gaoFullPackedCoreLevel-gaoFullPackedMaskedLevel)
	return input, nil
}

// EvaluateNew executes Gao's complete two-round 8-bit A2B graph. Preparation,
// encryption, decryption, verification, and evidence generation are outside
// the returned duration; it measures only the online homomorphic operations.
func (e *gaoFullPackedA2BEvaluator) EvaluateNew(
	input *rlwe.Ciphertext,
) (lowMSB, highMSB *rlwe.Ciphertext, online time.Duration, err error) {
	if e == nil || e.source == nil || e.source.Evaluator == nil || e.source.DFTEvaluator == nil ||
		e.triangle == nil || e.kernel0 == nil || e.kernel1 == nil ||
		e.ctsFactors == nil || e.stcFactors == nil ||
		e.closed || input == nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B evaluator or input is nil")
	}
	defaultScale := e.params.DefaultScale()
	if err = requireGaoFullPackedCiphertext("arithmetic input", input, 20, defaultScale); err != nil {
		return nil, nil, 0, err
	}

	started := time.Now()
	z2cInput, err := adjustGaoFullPackedToLevel(
		e.source.Evaluator, input, gaoFullPackedZ2CInputLevel, defaultScale,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B adjust input for Z2C: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("Z2C input", z2cInput, gaoFullPackedZ2CInputLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	halves, err := e.triangle.ZToCNew(z2cInput, e.specialB0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B special-b0: %w", err)
	}
	if len(halves) != 2 {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B special-b0 output count changed")
	}
	if err = requireGaoFullPackedCiphertext("special-b0 low", halves[0], gaoFullPackedCoreLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	if err = requireGaoFullPackedCiphertext("special-b0 high", halves[1], gaoFullPackedCoreLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}

	iter0Masked, err := dropGaoFullPackedIdentityMaskLevel(e.source.Evaluator, halves[0])
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter0 identity mask: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter0 mask", iter0Masked, gaoFullPackedMaskedLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	iter0STC, err := e.source.DFTEvaluator.SlotsToCoeffsFromFactorsNew(iter0Masked, nil, e.stcFactors)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter0 STC: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter0 STC", iter0STC, 0, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	iter0Refreshed, err := e.refreshRealNew(iter0STC)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter0 refresh: %w", err)
	}
	if err = normalizeGaoFullPackedScale(iter0Refreshed, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	id0, lowMSB, err := e.kernel0.EvaluatePreparedOutputsNew(iter0Refreshed)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter0 kernel: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter0 ID", id0, 5, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	if err = requireGaoFullPackedCiphertext("iter0 MSB", lowMSB, 5, defaultScale); err != nil {
		return nil, nil, 0, err
	}

	highCore := halves[1]
	id0Over16Adjusted, err := adjustGaoFullPackedScaledToLevel(
		e.source.Evaluator, id0, gaoFullPackedCoreLevel, defaultScale, 1, 16,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B adjust ID0/16: %w", err)
	}
	if err = e.source.Evaluator.Sub(highCore, id0Over16Adjusted, highCore); err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B high-core update: %w", err)
	}
	highUpdated := highCore
	if err = requireGaoFullPackedCiphertext("high core updated", highUpdated, gaoFullPackedCoreLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}

	iter1Masked, err := dropGaoFullPackedIdentityMaskLevel(e.source.Evaluator, highUpdated)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter1 identity mask: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter1 mask", iter1Masked, gaoFullPackedMaskedLevel, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	iter1STC, err := e.source.DFTEvaluator.SlotsToCoeffsFromFactorsNew(iter1Masked, nil, e.stcFactors)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter1 STC: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter1 STC", iter1STC, 0, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	iter1Refreshed, err := e.refreshRealNew(iter1STC)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter1 refresh: %w", err)
	}
	if err = normalizeGaoFullPackedScale(iter1Refreshed, defaultScale); err != nil {
		return nil, nil, 0, err
	}
	highMSB, err = e.kernel1.EvaluatePreparedMSBNew(iter1Refreshed)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("secureeval: Gao full-packed A2B iter1 MSB kernel: %w", err)
	}
	if err = requireGaoFullPackedCiphertext("iter1 MSB", highMSB, 5, defaultScale); err != nil {
		return nil, nil, 0, err
	}

	online = time.Since(started)
	if online <= 0 {
		online = time.Nanosecond
	}
	return lowMSB, highMSB, online, nil
}

// refreshRealNew implements the full-packed MR0 prefix. ModUp invokes no
// sparse trace rotations when LogSlots=LogN-1. Gao's masked path consumes only
// C2R's real output, so the unused dense imaginary ciphertext is not built.
func (e *gaoFullPackedA2BEvaluator) refreshRealNew(input *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if input == nil || input.Degree() != 1 || input.Level() != 0 ||
		input.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}) {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B refresh input shape changed")
	}
	scaled, _, err := e.source.ScaleDown(input)
	if err != nil {
		return nil, err
	}
	if scaled != input || scaled.Level() != 0 {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B ScaleDown output changed")
	}
	raised, err := e.source.ModUp(scaled)
	if err != nil {
		return nil, err
	}
	if raised != input || raised.Level() != e.params.MaxLevel() || raised.LogSlots() != gaoFullPackedLogSlots {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B ModUp output changed")
	}
	realOutput, err := e.source.DFTEvaluator.CoeffsToSlotsRealFromFactorsConsumeNew(raised, e.ctsFactors)
	if err != nil {
		return nil, err
	}
	if realOutput == nil {
		return nil, fmt.Errorf("secureeval: Gao full-packed A2B dense C2S did not return its real output")
	}
	if err = requireGaoFullPackedCiphertext("refresh real output", realOutput, 17, realOutput.Scale); err != nil {
		return nil, err
	}
	return realOutput, nil
}

// Close releases the evaluator graph and removes every private on-disk DFT
// factor store. It is safe to call more than once.
func (e *gaoFullPackedA2BEvaluator) Close() error {
	if e == nil || e.closed {
		return nil
	}
	e.closed = true
	err := errors.Join(
		e.ctsFactors.Close(),
		e.stcFactors.Close(),
	)
	e.ctsFactors = nil
	e.stcFactors = nil
	e.source = nil
	e.triangle = nil
	e.specialB0 = homchain.CompiledPair{}
	e.kernel0 = nil
	e.kernel1 = nil
	return err
}

func normalizeGaoFullPackedScale(ciphertext *rlwe.Ciphertext, target rlwe.Scale) error {
	if ciphertext == nil || ciphertext.MetaData == nil {
		return fmt.Errorf("secureeval: Gao full-packed A2B scale-normalization input is nil")
	}
	drift := math.Abs(ciphertext.Scale.Div(target).Log2())
	if math.IsNaN(drift) || math.IsInf(drift, 0) || drift > gaoFullPackedScaleDriftBound {
		return fmt.Errorf(
			"secureeval: Gao full-packed A2B |log2(scale/target)|=%g exceeds 2^-40", drift,
		)
	}
	ciphertext.Scale = target
	return nil
}

func requireGaoFullPackedCiphertext(name string, ciphertext *rlwe.Ciphertext, level int, scale rlwe.Scale) error {
	if ciphertext == nil || ciphertext.MetaData == nil || ciphertext.Level() != level ||
		ciphertext.Degree() != 1 || ciphertext.LogN() != 16 ||
		ciphertext.LogDimensions != (ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}) ||
		!ciphertext.Scale.Equal(scale) {
		return fmt.Errorf("secureeval: Gao full-packed A2B %s state changed", name)
	}
	return nil
}
