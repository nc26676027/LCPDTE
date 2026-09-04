package secureeval

import (
	"fmt"
	"math"
	"math/bits"
	"sync"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

const (
	// GaoFullPackedA2BMaxWords is Gao et al.'s canonical zSlots=8192
	// capacity for one N=65536, logSlots=15 ciphertext.
	GaoFullPackedA2BMaxWords = gaoFullPackedWords

	gaoFullPackedA2BTraceSchema = "gao-full-packed-a2b-v2|public-key|8192-words|adjust-l20-l4|special-b0|mask0|stc|modup|cts-real-only|exp46-r2-id-msb|fused-id0-over16-adjust|mask1|stc|modup|cts-real-only|exp46-r2-msb-only|outputs-low4-high4|resident-prevalidated|bsgs-ratio2"
	gaoFullPackedA2BTraceDigest = "3640dc3e5a7c6e61b8a941476898d0d52dad42630f0f7aeef0489cdaf9bd3ebf"
)

// GaoFullPackedA2BSetupReport records construction that is excluded from the
// prepared-online interval. ServerConstructionWallTime includes all DFT,
// polynomial, evaluation-key, and reusable evaluator preparation.
type GaoFullPackedA2BSetupReport struct {
	ParameterWallTime          time.Duration
	KeyGenerationWallTime      time.Duration
	ServerConstructionWallTime time.Duration
	Parameters                 GaoFullPackedA2BParameterReport
}

// GaoFullPackedA2BParameterReport is derived from the live session parameters
// and records the full-packing and backend execution profile.
type GaoFullPackedA2BParameterReport struct {
	RingDimension                  int
	PackingSlots                   int
	UsefulWords                    int
	QModuliCount                   int
	QLog2Aggregate                 int
	PModuliCount                   int
	PLog2Aggregate                 int
	ScalingModulusBits             int
	FirstModulusBits               int
	MultiplicativeDepth            int
	LargeDigits                    int
	EphemeralSecretHammingWeight   int
	LevelBudget                    [2]int
	OpenFHERequestedBSGSDimensions [2]int
	ChunkWidth                     int
	CutoffBits                     int
	STCLogBSGSRatio                int
	CTSLogBSGSRatio                int
	SpecialB0LogBSGSRatio          int
	EncryptionMode                 string
	FactorStorageMode              string
	ScaleSchedule                  string
}

// GaoFullPackedA2BPhaseReport records one client or server operation.
// PreparationWallTime is always zero: the server is fully prepared before the
// constructor returns. OnlineWallTime is populated only by EvaluateA2B.
type GaoFullPackedA2BPhaseReport struct {
	Phase               string
	WordCount           int
	WallTime            time.Duration
	PreparationWallTime time.Duration
	OnlineWallTime      time.Duration
	TraceDigest         string
}

type gaoFullPackedA2BSessionToken struct{ marker byte }

// GaoFullPackedA2BClient owns the canonical encoder, public-key encryptor, and
// secret-key decryptor. Its methods serialize access to Lattigo scratch state.
type GaoFullPackedA2BClient struct {
	mu sync.Mutex

	params    ckks.Parameters
	ringZ     *z2n.Ring
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	secretKey *rlwe.SecretKey
	publicKey *rlwe.PublicKey
	session   *gaoFullPackedA2BSessionToken
}

// GaoFullPackedA2BServer owns Gao's fully prepared two-round A2B evaluator.
// Calls are serialized because the underlying Lattigo evaluator reuses
// scratch buffers.
type GaoFullPackedA2BServer struct {
	mu sync.Mutex

	evaluator *gaoFullPackedA2BEvaluator
	session   *gaoFullPackedA2BSessionToken
	closed    bool
}

// GaoFullPackedA2BEncryptedInput is an opaque, session-bound arithmetic
// ciphertext.
type GaoFullPackedA2BEncryptedInput struct {
	ciphertext *rlwe.Ciphertext
	wordCount  int
	session    *gaoFullPackedA2BSessionToken
}

// GaoFullPackedA2BEncryptedOutput is an opaque, session-bound pair of Boolean
// ciphertexts: low bits 0..3 and high bits 4..7.
type GaoFullPackedA2BEncryptedOutput struct {
	lowMSB    *rlwe.Ciphertext
	highMSB   *rlwe.Ciphertext
	wordCount int
	session   *gaoFullPackedA2BSessionToken
}

// NewGaoFullPackedA2BSession constructs the canonical Gao-compatible
// N=65536, logSlots=15 client/server session. When it returns, the server is
// ready for prepared-online evaluation; the first call performs no lazy
// circuit construction.
func NewGaoFullPackedA2BSession() (
	client *GaoFullPackedA2BClient,
	server *GaoFullPackedA2BServer,
	report GaoFullPackedA2BSetupReport,
	err error,
) {
	parameterStarted := time.Now()
	raw, err := newGaoN16FullPackedTransportParameters()
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: construct Gao full-packed A2B parameters: %w", err)
	}
	params := raw.BootstrappingParameters
	if params.LogN() != 16 || params.LogMaxSlots() != gaoFullPackedLogSlots ||
		params.MaxLevel() != 20 || params.MaxLevelP() != 6 || params.LogDefaultScale() != 43 {
		return nil, nil, report, fmt.Errorf("secureeval: Gao full-packed A2B session parameter shape changed")
	}
	report.Parameters, err = newGaoFullPackedA2BParameterReport(raw)
	if err != nil {
		return nil, nil, report, err
	}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, z2n.DefaultPrecision)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: construct Gao full-packed A2B integer encoder: %w", err)
	}
	report.ParameterWallTime = gaoFullPackedPositiveDuration(parameterStarted)

	keyStarted := time.Now()
	secretKey, publicKey, encryptor, decryptor, err := newGaoFullPackedClientCryptography(params)
	if err != nil {
		return nil, nil, report, err
	}
	report.KeyGenerationWallTime = gaoFullPackedPositiveDuration(keyStarted)

	serverStarted := time.Now()
	evaluator, err := newGaoFullPackedA2BEvaluator(secretKey)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: construct Gao full-packed A2B server: %w", err)
	}
	evaluatorParams := evaluator.Parameters()
	if !params.Equal(&evaluatorParams) {
		return nil, nil, report, fmt.Errorf("secureeval: Gao full-packed A2B client/server parameters differ")
	}
	report.ServerConstructionWallTime = gaoFullPackedPositiveDuration(serverStarted)

	session := &gaoFullPackedA2BSessionToken{marker: 1}
	client = &GaoFullPackedA2BClient{
		params: params, ringZ: ringZ,
		encoder:   ckks.NewEncoder(params, z2n.DefaultPrecision),
		encryptor: encryptor,
		decryptor: decryptor,
		secretKey: secretKey,
		publicKey: publicKey,
		session:   session,
	}
	server = &GaoFullPackedA2BServer{evaluator: evaluator, session: session}
	return client, server, report, nil
}

func newGaoFullPackedA2BParameterReport(parameters bootstrapping.Parameters) (GaoFullPackedA2BParameterReport, error) {
	params := parameters.BootstrappingParameters
	if params.N() != 65_536 || params.MaxSlots() != gaoFullPackedSlots ||
		len(params.Q()) == 0 || len(params.P()) == 0 {
		return GaoFullPackedA2BParameterReport{}, fmt.Errorf("secureeval: Gao full-packed A2B live parameter profile is incomplete")
	}
	return GaoFullPackedA2BParameterReport{
		RingDimension:                  params.N(),
		PackingSlots:                   params.MaxSlots(),
		UsefulWords:                    gaoFullPackedWords,
		QModuliCount:                   len(params.Q()),
		QLog2Aggregate:                 params.QBigInt().BitLen(),
		PModuliCount:                   len(params.P()),
		PLog2Aggregate:                 params.PBigInt().BitLen(),
		ScalingModulusBits:             params.LogDefaultScale(),
		FirstModulusBits:               bits.Len64(params.Q()[0]),
		MultiplicativeDepth:            params.MaxLevel(),
		LargeDigits:                    3,
		EphemeralSecretHammingWeight:   parameters.EphemeralSecretWeight,
		LevelBudget:                    [2]int{len(parameters.CoeffsToSlotsParameters.Levels), len(parameters.SlotsToCoeffsParameters.Levels)},
		OpenFHERequestedBSGSDimensions: [2]int{0, 0},
		ChunkWidth:                     params.MaxSlots() / gaoFullPackedWords,
		CutoffBits:                     -24,
		STCLogBSGSRatio:                parameters.SlotsToCoeffsParameters.LogBSGSRatio,
		CTSLogBSGSRatio:                parameters.CoeffsToSlotsParameters.LogBSGSRatio,
		SpecialB0LogBSGSRatio:          gaoFullPackedSpecialB0BSGSRatio,
		EncryptionMode:                 "public-key",
		FactorStorageMode:              "resident-prevalidated",
		ScaleSchedule:                  "lattigo-explicit-level-scale-native",
	}, nil
}

func newGaoFullPackedClientCryptography(params ckks.Parameters) (
	secretKey *rlwe.SecretKey,
	publicKey *rlwe.PublicKey,
	encryptor *rlwe.Encryptor,
	decryptor *rlwe.Decryptor,
	err error,
) {
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey, publicKey = keyGenerator.GenKeyPairNew()
	if secretKey == nil || publicKey == nil {
		return nil, nil, nil, nil, fmt.Errorf("secureeval: Gao full-packed A2B key-pair generation returned nil")
	}
	return secretKey, publicKey,
		ckks.NewEncryptor(params, publicKey),
		ckks.NewDecryptor(params, secretKey), nil
}

// EncryptA2B encrypts 1..8192 uint8 words. Every word occupies four adjacent
// complex slots; unused word positions are encoded as zero and are never
// filled by repeating caller data.
func (client *GaoFullPackedA2BClient) EncryptA2B(
	words []uint8,
) (*GaoFullPackedA2BEncryptedInput, GaoFullPackedA2BPhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.ringZ == nil || client.encoder == nil || client.encryptor == nil || client.session == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B client is incomplete")
	}
	padded, err := padGaoFullPackedA2BWords(words)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, err
	}

	slots := make([]*bignum.Complex, 0, gaoFullPackedSlots)
	for index, word := range padded {
		block, encodeErr := client.ringZ.ToRootSlots(client.ringZ.ArithmeticEncode(uint64(word)))
		if encodeErr != nil {
			return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf(
				"secureeval: encode Gao full-packed A2B word %d: %w", index, encodeErr,
			)
		}
		slots = append(slots, block...)
	}
	if len(slots) != gaoFullPackedSlots {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf(
			"secureeval: Gao full-packed A2B encoded %d slots, want %d", len(slots), gaoFullPackedSlots,
		)
	}
	plaintext := ckks.NewPlaintext(client.params, client.params.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: gaoFullPackedLogSlots}
	if err = client.encoder.Encode(slots, plaintext); err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: encode Gao full-packed A2B plaintext: %w", err)
	}
	ciphertext, err := client.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: encrypt Gao full-packed A2B input: %w", err)
	}
	return &GaoFullPackedA2BEncryptedInput{
			ciphertext: ciphertext, wordCount: len(words), session: client.session,
		}, GaoFullPackedA2BPhaseReport{
			Phase: "encrypt", WordCount: len(words), WallTime: gaoFullPackedPositiveDuration(started),
		}, nil
}

// EvaluateA2B executes Gao's complete two-round A2B graph and returns the two
// ciphertext output container used by the OpenFHE implementation. All
// preparation belongs to NewGaoFullPackedA2BSession, so
// PreparationWallTime is zero for every call.
func (server *GaoFullPackedA2BServer) EvaluateA2B(
	input *GaoFullPackedA2BEncryptedInput,
) (*GaoFullPackedA2BEncryptedOutput, GaoFullPackedA2BPhaseReport, error) {
	started := time.Now()
	if server == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B server is nil")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if input == nil || input.ciphertext == nil || input.session == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B encrypted input is empty")
	}
	if server.session == nil || input.session != server.session {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B input belongs to a different session")
	}
	if server.closed || server.evaluator == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B server is closed or incomplete")
	}

	low, high, online, err := server.evaluator.EvaluateNew(input.ciphertext)
	if err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: evaluate Gao full-packed A2B request: %w", err)
	}
	if low == nil || high == nil || online <= 0 {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B evaluation returned an incomplete result")
	}
	return &GaoFullPackedA2BEncryptedOutput{
			lowMSB: low, highMSB: high, wordCount: input.wordCount, session: server.session,
		}, GaoFullPackedA2BPhaseReport{
			Phase: "evaluate", WordCount: input.wordCount,
			WallTime:       gaoFullPackedPositiveDuration(started),
			OnlineWallTime: online,
			TraceDigest:    gaoFullPackedA2BTraceDigest,
		}, nil
}

// DecryptA2B returns one LSB-first eight-bit vector for each original input
// word. Slots belonging to internal zero padding are not returned.
func (client *GaoFullPackedA2BClient) DecryptA2B(
	output *GaoFullPackedA2BEncryptedOutput,
) ([][8]uint8, GaoFullPackedA2BPhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if output == nil || output.lowMSB == nil || output.highMSB == nil || output.session == nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B encrypted output is empty")
	}
	if client.session == nil || output.session != client.session {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B output belongs to a different session")
	}
	if client.encoder == nil || client.decryptor == nil || client.secretKey == nil ||
		output.wordCount < 1 || output.wordCount > GaoFullPackedA2BMaxWords {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: Gao full-packed A2B client or output shape is invalid")
	}

	lowValues := make([]complex128, gaoFullPackedSlots)
	if err := client.encoder.Decode(client.decryptor.DecryptNew(output.lowMSB), lowValues); err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: decode Gao full-packed A2B low bits: %w", err)
	}
	highValues := make([]complex128, gaoFullPackedSlots)
	if err := client.encoder.Decode(client.decryptor.DecryptNew(output.highMSB), highValues); err != nil {
		return nil, GaoFullPackedA2BPhaseReport{}, fmt.Errorf("secureeval: decode Gao full-packed A2B high bits: %w", err)
	}

	bits := make([][8]uint8, output.wordCount)
	for word := range bits {
		for bit := 0; bit < 4; bit++ {
			low, err := decodeGaoFullPackedA2BBit(lowValues[4*word+bit], word, bit)
			if err != nil {
				return nil, GaoFullPackedA2BPhaseReport{}, err
			}
			high, err := decodeGaoFullPackedA2BBit(highValues[4*word+bit], word, bit+4)
			if err != nil {
				return nil, GaoFullPackedA2BPhaseReport{}, err
			}
			bits[word][bit] = low
			bits[word][bit+4] = high
		}
	}
	return bits, GaoFullPackedA2BPhaseReport{
		Phase: "decrypt/decode", WordCount: output.wordCount,
		WallTime: gaoFullPackedPositiveDuration(started),
	}, nil
}

func padGaoFullPackedA2BWords(words []uint8) ([]uint8, error) {
	if len(words) < 1 || len(words) > GaoFullPackedA2BMaxWords {
		return nil, fmt.Errorf(
			"secureeval: Gao full-packed A2B word count %d is outside 1..%d",
			len(words), GaoFullPackedA2BMaxWords,
		)
	}
	padded := make([]uint8, GaoFullPackedA2BMaxWords)
	copy(padded, words)
	return padded, nil
}

func decodeGaoFullPackedA2BBit(value complex128, word, bit int) (uint8, error) {
	if math.IsNaN(real(value)) || math.IsInf(real(value), 0) ||
		math.IsNaN(imag(value)) || math.IsInf(imag(value), 0) {
		return 0, fmt.Errorf("secureeval: Gao full-packed A2B word %d bit %d is non-finite", word, bit)
	}
	rounded := math.Round(real(value))
	if (rounded != 0 && rounded != 1) ||
		math.Abs(real(value)-rounded) > RouteBA2BFullAccuracyTolerance ||
		math.Abs(imag(value)) > RouteBA2BFullAccuracyTolerance {
		return 0, fmt.Errorf("secureeval: Gao full-packed A2B word %d bit %d failed Boolean decoding", word, bit)
	}
	return uint8(rounded), nil
}

func gaoFullPackedPositiveDuration(started time.Time) time.Duration {
	elapsed := time.Since(started)
	if elapsed <= 0 {
		return time.Nanosecond
	}
	return elapsed
}

// Close releases the reusable server evaluator. It is idempotent.
func (server *GaoFullPackedA2BServer) Close() {
	if server == nil {
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return
	}
	server.closed = true
	if server.evaluator != nil {
		_ = server.evaluator.Close()
	}
	server.evaluator = nil
	server.session = nil
}
