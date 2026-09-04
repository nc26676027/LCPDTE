package secureeval

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
	"github.com/nc26676027/LCPDTE/lattigo/utils/bignum"
)

// CanonicalRouteBA2BMaxWords is the number of packed 8-bit words processed by
// one canonical N=2^16, logSlots=11 Route-B ciphertext.
const CanonicalRouteBA2BMaxWords = routeBA2BFirstRoundWords

// RouteBA2BSetupReport records the externally meaningful setup phases.
type RouteBA2BSetupReport struct {
	ParameterArtifactWallTime time.Duration
	KeyGenerationWallTime     time.Duration
	ServerInstallWallTime     time.Duration
}

// RouteBA2BPhaseReport records one client or server phase.
type RouteBA2BPhaseReport struct {
	Phase               string
	WordCount           int
	WallTime            time.Duration
	PreparationWallTime time.Duration
	OnlineWallTime      time.Duration
	TraceDigest         string
}

type routeBA2BSessionToken struct{ marker byte }

// RouteBA2BClient owns the canonical parameters and client-only key material.
type RouteBA2BClient struct {
	mu sync.Mutex

	params    ckks.Parameters
	ringZ     *z2n.Ring
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	secretKey *rlwe.SecretKey
	session   *routeBA2BSessionToken
}

// RouteBA2BServer owns the installed evaluator and its prepared A2B circuit.
type RouteBA2BServer struct {
	mu sync.Mutex

	installed *RouteBInstalledEvaluator
	session   *routeBA2BSessionToken
	calls     uint64
	closed    bool
}

// RouteBA2BEncryptedInput is an opaque, session-bound arithmetic ciphertext.
type RouteBA2BEncryptedInput struct {
	ciphertext *rlwe.Ciphertext
	wordCount  int
	session    *routeBA2BSessionToken
}

// RouteBA2BEncryptedOutput is an opaque, session-bound Boolean result.
type RouteBA2BEncryptedOutput struct {
	lowMSB    *rlwe.Ciphertext
	highMSB   *rlwe.Ciphertext
	wordCount int
	session   *routeBA2BSessionToken
}

// NewCanonicalRouteBA2BSession constructs a split client/server Route-B A2B
// session through Authority -> Build -> Ready -> Install.
func NewCanonicalRouteBA2BSession() (
	client *RouteBA2BClient,
	server *RouteBA2BServer,
	report RouteBA2BSetupReport,
	err error,
) {
	parameterArtifactStarted := time.Now()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: create canonical Route-B A2B Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	_, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: authorize canonical Route-B A2B build: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: build canonical Route-B A2B artifact: %w", err)
	}
	installedPublished := false
	defer func() {
		if err == nil {
			return
		}
		if installedPublished && server != nil {
			server.Close()
			return
		}
		if artifact.cell != nil {
			clearRouteBArtifactCell(artifact.cell)
		}
	}()
	releaseRouteBTransientHeap()
	_, readyPermit, err := authority.AuthorizeReady(buildPermit, receipt, artifact)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: ready canonical Route-B A2B artifact: %w", err)
	}
	releaseRouteBTransientHeap()
	raw, err := newGaoN16RouteBTransportParameters()
	if err != nil {
		return nil, nil, report, err
	}
	prepared, _, err := prepareGaoN16RouteBTransportParametersFromRaw(raw)
	raw = bootstrapping.Parameters{}
	if err != nil {
		return nil, nil, report, err
	}
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return nil, nil, report, err
	}
	params := prepared.EffectiveParameters().BootstrappingParameters
	prepared = bootstrapping.PreparedParameters{}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: create canonical Route-B A2B integer encoder: %w", err)
	}
	report.ParameterArtifactWallTime = routeBDepth2NonzeroDuration(parameterArtifactStarted)

	keyGenerationStarted := time.Now()
	secretKey := rlwe.NewKeyGenerator(params).GenSecretKeyNew()
	if secretKey == nil {
		return nil, nil, report, lineagef("canonical Route-B A2B key generation returned nil")
	}
	report.KeyGenerationWallTime = routeBDepth2NonzeroDuration(keyGenerationStarted)

	serverInstallStarted := time.Now()
	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: install canonical Route-B A2B evaluator: %w", err)
	}
	report.ServerInstallWallTime = routeBDepth2NonzeroDuration(serverInstallStarted)

	session := &routeBA2BSessionToken{marker: 1}
	client = &RouteBA2BClient{
		params: params, ringZ: ringZ,
		encoder:   ckks.NewEncoder(params, routeBSigned8RootTreeEncoderPrecision),
		encryptor: ckks.NewEncryptor(params, secretKey),
		decryptor: ckks.NewDecryptor(params, secretKey),
		secretKey: secretKey, session: session,
	}
	server = &RouteBA2BServer{installed: installed, session: session}
	installedPublished = true
	return client, server, report, nil
}

// EncryptA2B encodes and encrypts 1..512 bytes, padding the physical packing
// by repeating the caller's batch.
func (client *RouteBA2BClient) EncryptA2B(
	words []uint8,
) (*RouteBA2BEncryptedInput, RouteBA2BPhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(words) < 1 || len(words) > CanonicalRouteBA2BMaxWords {
		return nil, RouteBA2BPhaseReport{}, lineagef(
			"canonical Route-B A2B word count %d is outside 1..%d", len(words), CanonicalRouteBA2BMaxWords,
		)
	}
	if client.ringZ == nil || client.encoder == nil || client.encryptor == nil || client.session == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B client is incomplete")
	}

	slots := make([]*bignum.Complex, 0, routeBA2BFirstRoundSlots)
	for index := 0; index < CanonicalRouteBA2BMaxWords; index++ {
		word := words[index%len(words)]
		block, err := client.ringZ.ToRootSlots(client.ringZ.ArithmeticEncode(uint64(word)))
		if err != nil {
			return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: encode canonical Route-B A2B word %d: %w", index, err)
		}
		slots = append(slots, block...)
	}
	if len(slots) != routeBA2BFirstRoundSlots {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B input slot count changed")
	}
	plaintext := ckks.NewPlaintext(client.params, client.params.MaxLevel())
	plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
	if err := client.encoder.Encode(slots, plaintext); err != nil {
		return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: encode canonical Route-B A2B input: %w", err)
	}
	ciphertext, err := client.encryptor.EncryptNew(plaintext)
	if err != nil {
		return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: encrypt canonical Route-B A2B input: %w", err)
	}
	return &RouteBA2BEncryptedInput{
			ciphertext: ciphertext, wordCount: len(words), session: client.session,
		}, RouteBA2BPhaseReport{
			Phase: "encrypt", WordCount: len(words), WallTime: routeBDepth2NonzeroDuration(started),
		}, nil
}

// EvaluateA2B runs complete 8-bit A2B. The first call performs preparation and
// becomes the warmup; later calls reuse the prepared circuit.
func (server *RouteBA2BServer) EvaluateA2B(
	input *RouteBA2BEncryptedInput,
) (*RouteBA2BEncryptedOutput, RouteBA2BPhaseReport, error) {
	started := time.Now()
	if server == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B server is nil")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if input == nil || input.ciphertext == nil || input.session == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B encrypted input is empty")
	}
	if server.session == nil || input.session != server.session {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B input belongs to a different session")
	}
	if server.closed || server.installed == nil || server.installed.IsZero() {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B server is closed or incomplete")
	}

	var (
		result      RouteBA2BFullResult
		fullReport  RouteBA2BFullReport
		err         error
		preparation time.Duration
	)
	if server.calls == 0 {
		result, _, fullReport, err = server.installed.RunFirstSparseA2BFull(input.ciphertext)
		if server.installed.cell != nil {
			preparation = time.Duration(server.installed.cell.preparedA2BFullWallNanos)
		}
	} else {
		result, _, fullReport, err = server.installed.RunSparseA2BFull(input.ciphertext)
	}
	if err != nil {
		return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: evaluate canonical Route-B A2B request: %w", err)
	}
	low, high := result.LowMSB(), result.HighMSB()
	if low == nil || high == nil || fullReport.Digest == "" {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B evaluation returned an incomplete result")
	}
	server.calls++
	return &RouteBA2BEncryptedOutput{
			lowMSB: low, highMSB: high, wordCount: input.wordCount, session: server.session,
		}, RouteBA2BPhaseReport{
			Phase: "evaluate", WordCount: input.wordCount,
			WallTime:            routeBDepth2NonzeroDuration(started),
			PreparationWallTime: preparation,
			OnlineWallTime:      time.Duration(fullReport.WallNanoseconds),
			TraceDigest:         fullReport.Digest,
		}, nil
}

// DecryptA2B decodes one LSB-first bit vector per original input byte.
func (client *RouteBA2BClient) DecryptA2B(
	output *RouteBA2BEncryptedOutput,
) ([][8]uint8, RouteBA2BPhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if output == nil || output.lowMSB == nil || output.highMSB == nil || output.session == nil {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B encrypted output is empty")
	}
	if client.session == nil || output.session != client.session {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B output belongs to a different session")
	}
	if client.encoder == nil || client.decryptor == nil || client.secretKey == nil ||
		output.wordCount < 1 || output.wordCount > CanonicalRouteBA2BMaxWords {
		return nil, RouteBA2BPhaseReport{}, lineagef("canonical Route-B A2B client or output shape is invalid")
	}

	lowValues := make([]complex128, routeBA2BFirstRoundSlots)
	if err := client.encoder.Decode(client.decryptor.DecryptNew(output.lowMSB), lowValues); err != nil {
		return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: decode canonical Route-B A2B low bits: %w", err)
	}
	highValues := make([]complex128, routeBA2BFirstRoundSlots)
	if err := client.encoder.Decode(client.decryptor.DecryptNew(output.highMSB), highValues); err != nil {
		return nil, RouteBA2BPhaseReport{}, fmt.Errorf("secureeval: decode canonical Route-B A2B high bits: %w", err)
	}

	bits := make([][8]uint8, output.wordCount)
	for word := range bits {
		for bit := 0; bit < 4; bit++ {
			low, err := decodeRouteBA2BBit(lowValues[4*word+bit], word, bit)
			if err != nil {
				return nil, RouteBA2BPhaseReport{}, err
			}
			high, err := decodeRouteBA2BBit(highValues[4*word+bit], word, bit+4)
			if err != nil {
				return nil, RouteBA2BPhaseReport{}, err
			}
			bits[word][bit] = low
			bits[word][bit+4] = high
		}
	}
	return bits, RouteBA2BPhaseReport{
		Phase: "decrypt/decode", WordCount: output.wordCount, WallTime: routeBDepth2NonzeroDuration(started),
	}, nil
}

func decodeRouteBA2BBit(value complex128, word, bit int) (uint8, error) {
	if math.IsNaN(real(value)) || math.IsInf(real(value), 0) ||
		math.IsNaN(imag(value)) || math.IsInf(imag(value), 0) {
		return 0, lineagef("canonical Route-B A2B word %d bit %d is non-finite", word, bit)
	}
	rounded := math.Round(real(value))
	if (rounded != 0 && rounded != 1) ||
		math.Abs(real(value)-rounded) > RouteBA2BFullAccuracyTolerance ||
		math.Abs(imag(value)) > RouteBA2BFullAccuracyTolerance {
		return 0, lineagef("canonical Route-B A2B word %d bit %d failed Boolean decoding", word, bit)
	}
	return uint8(rounded), nil
}

// Close releases the installed evaluator. It is idempotent.
func (server *RouteBA2BServer) Close() {
	if server == nil {
		return
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.closed {
		return
	}
	server.closed = true
	retireRouteBInstalledEvaluator(server.installed)
	server.installed = nil
}
