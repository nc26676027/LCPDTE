package secureeval

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nc26676027/LCPDTE/integer/homchain"
	"github.com/nc26676027/LCPDTE/integer/z2n"
	"github.com/nc26676027/LCPDTE/lattigo/circuits/ckks/bootstrapping"
	"github.com/nc26676027/LCPDTE/lattigo/core/rlwe"
	"github.com/nc26676027/LCPDTE/lattigo/ring"
	"github.com/nc26676027/LCPDTE/lattigo/schemes/ckks"
)

// CanonicalRouteBDepth2MaxQueries is the fixed signed-int8 capacity of the
// Gao-compatible N=2^16, logSlots=11 Route-B circuit.
const CanonicalRouteBDepth2MaxQueries = routeBSigned8RootTreeWords

// RouteBDepth2RequestInfo is the shape accepted by the canonical circuit.
type RouteBDepth2RequestInfo struct {
	QueryCount       int
	PaddedQueryCount int
	FeatureCount     int
}

// RouteBDepth2SetupReport records the three externally meaningful setup
// phases without exposing the underlying evaluator or key types.
type RouteBDepth2SetupReport struct {
	ParameterArtifactWallTime time.Duration
	KeyGenerationWallTime     time.Duration
	ServerInstallWallTime     time.Duration
}

// RouteBDepth2PhaseReport records one online phase.
type RouteBDepth2PhaseReport struct {
	Phase       string
	QueryCount  int
	WallTime    time.Duration
	TraceDigest string
}

type routeBDepth2SessionToken struct{ marker byte }

// RouteBDepth2Client owns the canonical parameters and all client-only
// encryption and decryption material.
type RouteBDepth2Client struct {
	mu sync.Mutex

	params    ckks.Parameters
	ringZ     *z2n.Ring
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	secretKey *rlwe.SecretKey
	session   *routeBDepth2SessionToken
}

// RouteBDepth2Server owns only the installed evaluator and its session token.
type RouteBDepth2Server struct {
	mu sync.Mutex

	installed *RouteBInstalledEvaluator
	session   *routeBDepth2SessionToken
	used      bool
	closed    bool
}

// RouteBDepth2EncryptedInput is an opaque, session-bound depth-2 request.
type RouteBDepth2EncryptedInput struct {
	bound      RouteBSigned8Depth2SelectedChildFeatures
	ranges     [3]homchain.Signed8NoOverflowRange
	model      RouteBSigned8Depth2SelectedChildModel
	queryCount int
	session    *routeBDepth2SessionToken
}

// RouteBDepth2EncryptedOutput is an opaque, session-bound depth-2 result.
type RouteBDepth2EncryptedOutput struct {
	ciphertext *rlwe.Ciphertext
	queryCount int
	session    *routeBDepth2SessionToken
}

// NewCanonicalRouteBDepth2Session constructs the fixed Gao-compatible Route-B
// client/server pair through Authority -> Build -> Ready -> Install.
func NewCanonicalRouteBDepth2Session() (
	client *RouteBDepth2Client,
	server *RouteBDepth2Server,
	report RouteBDepth2SetupReport,
	err error,
) {
	parameterArtifactStarted := time.Now()
	authority, err := NewRouteBAuthority()
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: create canonical Route-B depth2 Authority: %w", err)
	}
	releaseRouteBTransientHeap()
	_, buildPermit, err := authority.AuthorizeBuild()
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: authorize canonical Route-B depth2 build: %w", err)
	}
	releaseRouteBTransientHeap()
	receipt, artifact, err := authority.BeginBuild(buildPermit)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: build canonical Route-B depth2 artifact: %w", err)
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
		return nil, nil, report, fmt.Errorf("secureeval: ready canonical Route-B depth2 artifact: %w", err)
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
	params := prepared.EffectiveParameters().BootstrappingParameters
	if err = validateGaoN16RouteBPreparedIdentity(prepared); err != nil {
		return nil, nil, report, err
	}
	prepared = bootstrapping.PreparedParameters{}
	ringZ, err := z2n.NewWithPrecision(z2n.Word8, routeBSigned8RootTreeEncoderPrecision)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: create canonical Route-B depth2 integer encoder: %w", err)
	}
	report.ParameterArtifactWallTime = routeBDepth2NonzeroDuration(parameterArtifactStarted)

	keyGenerationStarted := time.Now()
	keyGenerator := rlwe.NewKeyGenerator(params)
	secretKey := keyGenerator.GenSecretKeyNew()
	if secretKey == nil {
		return nil, nil, report, lineagef("canonical Route-B depth2 key generation returned nil")
	}
	report.KeyGenerationWallTime = routeBDepth2NonzeroDuration(keyGenerationStarted)

	serverInstallStarted := time.Now()
	installed, err := authority.Install(readyPermit, receipt, artifact, secretKey)
	if err != nil {
		return nil, nil, report, fmt.Errorf("secureeval: install canonical Route-B depth2 evaluator: %w", err)
	}
	report.ServerInstallWallTime = routeBDepth2NonzeroDuration(serverInstallStarted)

	session := new(routeBDepth2SessionToken)
	client = &RouteBDepth2Client{
		params: params, ringZ: ringZ,
		encoder:   ckks.NewEncoder(params, routeBSigned8RootTreeEncoderPrecision),
		encryptor: ckks.NewEncryptor(params, secretKey),
		decryptor: ckks.NewDecryptor(params, secretKey),
		secretKey: secretKey, session: session,
	}
	server = &RouteBDepth2Server{installed: installed, session: session}
	installedPublished = true
	return client, server, report, nil
}

// ValidateCanonicalRouteBDepth2Request validates the complete public request
// without constructing Route-B artifacts or evaluation keys.
func ValidateCanonicalRouteBDepth2Request(
	features [][]int8,
	model RouteBSigned8Depth2SelectedChildModel,
) (RouteBDepth2RequestInfo, error) {
	info, _, err := validateCanonicalRouteBDepth2Request(features, model)
	return info, err
}

func validateCanonicalRouteBDepth2Request(
	features [][]int8,
	model RouteBSigned8Depth2SelectedChildModel,
) (RouteBDepth2RequestInfo, [3]homchain.Signed8NoOverflowRange, error) {
	var ranges [3]homchain.Signed8NoOverflowRange
	if err := validateRouteBSigned8Depth2SelectedChildModel(model); err != nil {
		return RouteBDepth2RequestInfo{}, ranges, err
	}
	if len(features) == 0 {
		return RouteBDepth2RequestInfo{}, ranges, lineagef("canonical Route-B depth2 requires 1..512 queries")
	}
	queryCount := len(features[0])
	if queryCount < 1 || queryCount > CanonicalRouteBDepth2MaxQueries {
		return RouteBDepth2RequestInfo{}, ranges, lineagef(
			"canonical Route-B depth2 requires 1..512 queries, got %d", queryCount,
		)
	}
	for featureID, values := range features {
		if len(values) != queryCount {
			return RouteBDepth2RequestInfo{}, ranges, lineagef(
				"canonical Route-B depth2 features must have the same query count: feature 0 has %d, feature %d has %d",
				queryCount, featureID, len(values),
			)
		}
	}
	for node, featureID := range model.featureIDs {
		if uint64(featureID) >= uint64(len(features)) {
			return RouteBDepth2RequestInfo{}, ranges, lineagef(
				"canonical Route-B depth2 node %d requires feature %d, got %d features",
				node, featureID, len(features),
			)
		}
		values := features[int(featureID)]
		minimum, maximum := int64(values[0]), int64(values[0])
		for _, value := range values[1:] {
			candidate := int64(value)
			if candidate < minimum {
				minimum = candidate
			}
			if candidate > maximum {
				maximum = candidate
			}
		}
		var err error
		ranges[node], err = homchain.NewSigned8NoOverflowRange(
			minimum, maximum, model.thresholds[node], model.thresholds[node],
		)
		if err != nil {
			return RouteBDepth2RequestInfo{}, [3]homchain.Signed8NoOverflowRange{}, fmt.Errorf(
				"secureeval: canonical Route-B depth2 node %d no-overflow range: %w", node, err,
			)
		}
	}
	return RouteBDepth2RequestInfo{
		QueryCount: queryCount, PaddedQueryCount: CanonicalRouteBDepth2MaxQueries, FeatureCount: len(features),
	}, ranges, nil
}

// EncryptDepth2 validates, pads, encodes and encrypts one depth-2 request.
func (client *RouteBDepth2Client) EncryptDepth2(
	features [][]int8,
	model RouteBSigned8Depth2SelectedChildModel,
) (*RouteBDepth2EncryptedInput, RouteBDepth2PhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.session == nil || client.ringZ == nil || client.encoder == nil || client.encryptor == nil ||
		client.decryptor == nil || client.secretKey == nil || client.params.LogN() != 16 {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 client is incomplete")
	}
	info, ranges, err := validateCanonicalRouteBDepth2Request(features, model)
	if err != nil {
		return nil, RouteBDepth2PhaseReport{}, err
	}

	featureVector := make(map[uint32]*rlwe.Ciphertext, 3)
	for _, featureID := range model.featureIDs {
		if _, present := featureVector[featureID]; present {
			continue
		}
		words := make([]int64, CanonicalRouteBDepth2MaxQueries)
		values := features[int(featureID)]
		for query := range words {
			if query < info.QueryCount {
				words[query] = int64(values[query])
			} else {
				words[query] = int64(values[0])
			}
		}
		slots, slotErr := routeBSigned8Depth2SelectedChildFeatureSlots(client.ringZ, words)
		if slotErr != nil {
			return nil, RouteBDepth2PhaseReport{}, slotErr
		}
		plaintext := ckks.NewPlaintext(client.params, client.params.MaxLevel())
		plaintext.LogDimensions = ring.Dimensions{Rows: 0, Cols: 11}
		if slotErr = client.encoder.Encode(slots, plaintext); slotErr != nil {
			return nil, RouteBDepth2PhaseReport{}, fmt.Errorf(
				"secureeval: encode canonical Route-B depth2 feature %d: %w", featureID, slotErr,
			)
		}
		featureVector[featureID], slotErr = client.encryptor.EncryptNew(plaintext)
		if slotErr != nil {
			return nil, RouteBDepth2PhaseReport{}, fmt.Errorf(
				"secureeval: encrypt canonical Route-B depth2 feature %d: %w", featureID, slotErr,
			)
		}
	}
	bound, err := BindRouteBSigned8Depth2SelectedChildFeatures(model, featureVector)
	if err != nil {
		return nil, RouteBDepth2PhaseReport{}, err
	}
	return &RouteBDepth2EncryptedInput{
			bound: bound, ranges: ranges, model: model, queryCount: info.QueryCount, session: client.session,
		}, RouteBDepth2PhaseReport{
			Phase: "encrypt", QueryCount: info.QueryCount, WallTime: routeBDepth2NonzeroDuration(started),
		}, nil
}

// EvaluateDepth2 evaluates exactly one request for this server session.
func (server *RouteBDepth2Server) EvaluateDepth2(
	input *RouteBDepth2EncryptedInput,
) (*RouteBDepth2EncryptedOutput, RouteBDepth2PhaseReport, error) {
	started := time.Now()
	if server == nil {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 server is nil")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if input == nil || input.session == nil {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 encrypted input is empty")
	}
	if server.session == nil || input.session != server.session {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 encrypted input belongs to a different session")
	}
	if server.closed || server.installed == nil || server.installed.IsZero() {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 server is closed or incomplete")
	}
	if server.used {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 server already evaluated its request")
	}
	server.used = true
	result, _, evaluationReport, err := server.installed.RunSigned8Depth2SelectedChildPublic(
		input.bound, input.ranges, input.model,
	)
	if err != nil {
		return nil, RouteBDepth2PhaseReport{}, fmt.Errorf("secureeval: evaluate canonical Route-B depth2 request: %w", err)
	}
	ciphertext := result.Ciphertext()
	if ciphertext == nil || result.ReportDigest() == "" || result.ReportDigest() != evaluationReport.Digest {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 evaluation returned an incomplete result")
	}
	return &RouteBDepth2EncryptedOutput{
			ciphertext: ciphertext, queryCount: input.queryCount, session: server.session,
		}, RouteBDepth2PhaseReport{
			Phase: "evaluate", QueryCount: input.queryCount,
			WallTime: routeBDepth2NonzeroDuration(started), TraceDigest: evaluationReport.Digest,
		}, nil
}

// DecryptDepth2 decrypts and decodes only the caller's original query count.
func (client *RouteBDepth2Client) DecryptDepth2(
	output *RouteBDepth2EncryptedOutput,
) ([]float64, RouteBDepth2PhaseReport, error) {
	started := time.Now()
	if client == nil {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 client is nil")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if output == nil || output.ciphertext == nil || output.session == nil {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 encrypted output is empty")
	}
	if client.session == nil || output.session != client.session {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 encrypted output belongs to a different session")
	}
	if client.decoderUnavailable() {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 client decryptor is incomplete")
	}
	if output.queryCount < 1 || output.queryCount > CanonicalRouteBDepth2MaxQueries {
		return nil, RouteBDepth2PhaseReport{}, lineagef("canonical Route-B depth2 output query count is invalid")
	}
	plaintext := client.decryptor.DecryptNew(output.ciphertext)
	values := make([]complex128, routeBSigned8RootTreeSlots)
	if err := client.encoder.Decode(plaintext, values); err != nil {
		return nil, RouteBDepth2PhaseReport{}, fmt.Errorf("secureeval: decode canonical Route-B depth2 output: %w", err)
	}
	decoded, err := decodeCanonicalRouteBDepth2Blocks(values, output.queryCount)
	if err != nil {
		return nil, RouteBDepth2PhaseReport{}, err
	}
	return decoded, RouteBDepth2PhaseReport{
		Phase: "decrypt/decode", QueryCount: output.queryCount, WallTime: routeBDepth2NonzeroDuration(started),
	}, nil
}

func decodeCanonicalRouteBDepth2Blocks(values []complex128, queryCount int) ([]float64, error) {
	if queryCount < 1 || queryCount > CanonicalRouteBDepth2MaxQueries {
		return nil, lineagef("canonical Route-B depth2 decoded query count %d is outside 1..512", queryCount)
	}
	requiredSlots := 4 * queryCount
	if len(values) < requiredSlots {
		return nil, lineagef(
			"canonical Route-B depth2 decode has %d slots, need at least %d for %d queries",
			len(values), requiredSlots, queryCount,
		)
	}
	tolerance := RouteBSigned8Depth2SelectedChildAccuracyTolerance
	decoded := make([]float64, queryCount)
	for query := range decoded {
		firstReal := 0.0
		for slot := 0; slot < 4; slot++ {
			value := values[4*query+slot]
			realPart, imaginaryPart := real(value), imag(value)
			if math.IsNaN(realPart) || math.IsInf(realPart, 0) {
				return nil, lineagef(
					"canonical Route-B depth2 query %d slot %d real component is non-finite", query, slot,
				)
			}
			if math.IsNaN(imaginaryPart) || math.IsInf(imaginaryPart, 0) {
				return nil, lineagef(
					"canonical Route-B depth2 query %d slot %d imaginary component is non-finite", query, slot,
				)
			}
			if residual := math.Abs(imaginaryPart); residual > tolerance {
				return nil, lineagef(
					"canonical Route-B depth2 query %d slot %d imaginary residual %g exceeds %g",
					query, slot, residual, tolerance,
				)
			}
			if slot == 0 {
				firstReal = realPart
				decoded[query] = realPart
				continue
			}
			if disagreement := math.Abs(realPart - firstReal); disagreement > tolerance {
				return nil, lineagef(
					"canonical Route-B depth2 query %d slot %d real replica disagreement %g exceeds %g",
					query, slot, disagreement, tolerance,
				)
			}
		}
	}
	return decoded, nil
}

func (client *RouteBDepth2Client) decoderUnavailable() bool {
	return client.encoder == nil || client.decryptor == nil || client.secretKey == nil
}

// Close releases the installed evaluator. It is safe to call more than once.
func (server *RouteBDepth2Server) Close() {
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

func routeBDepth2NonzeroDuration(started time.Time) time.Duration {
	value := time.Since(started)
	if value <= 0 {
		return time.Nanosecond
	}
	return value
}
