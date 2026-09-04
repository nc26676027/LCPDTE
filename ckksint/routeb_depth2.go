package ckksint

import (
	"fmt"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

// CanonicalRouteBDepth2MaxQueries is the fixed capacity of one Route-B
// signed-int8 depth-2 evaluation.
const CanonicalRouteBDepth2MaxQueries = secureeval.CanonicalRouteBDepth2MaxQueries

// RouteBDepth2RequestInfo describes the validated request shape.
type RouteBDepth2RequestInfo struct {
	QueryCount       int
	PaddedQueryCount int
	FeatureCount     int
}

// RouteBDepth2SetupInfo reports the setup/keygen/install split.
type RouteBDepth2SetupInfo struct {
	ParameterArtifactWallTime time.Duration
	KeyGenerationWallTime     time.Duration
	ServerInstallWallTime     time.Duration
}

// RouteBDepth2PhaseInfo reports one client or server phase.
type RouteBDepth2PhaseInfo struct {
	Phase       string
	QueryCount  int
	WallTime    time.Duration
	TraceDigest string
}

// RouteBDepth2Client owns encryption and decryption state for one session.
type RouteBDepth2Client struct {
	inner *secureeval.RouteBDepth2Client
}

// RouteBDepth2Server owns the installed evaluator for one session.
type RouteBDepth2Server struct {
	inner *secureeval.RouteBDepth2Server
}

// RouteBDepth2EncryptedInput is an opaque session-bound request.
type RouteBDepth2EncryptedInput struct {
	inner *secureeval.RouteBDepth2EncryptedInput
}

// RouteBDepth2EncryptedOutput is an opaque session-bound result.
type RouteBDepth2EncryptedOutput struct {
	inner *secureeval.RouteBDepth2EncryptedOutput
}

// ValidateCanonicalRouteBDepth2Request checks a request without performing
// Route-B artifact construction, key generation, encryption or evaluation.
func ValidateCanonicalRouteBDepth2Request(
	features [][]int8,
	model Depth2Model,
) (RouteBDepth2RequestInfo, error) {
	internalModel, err := canonicalRouteBDepth2Model(model)
	if err != nil {
		return RouteBDepth2RequestInfo{}, err
	}
	info, err := secureeval.ValidateCanonicalRouteBDepth2Request(features, internalModel)
	if err != nil {
		return RouteBDepth2RequestInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 request: %w", err)
	}
	return RouteBDepth2RequestInfo{
		QueryCount: info.QueryCount, PaddedQueryCount: info.PaddedQueryCount, FeatureCount: info.FeatureCount,
	}, nil
}

// NewCanonicalRouteBDepth2 builds one Gao-compatible Route-B split session.
// The returned client retains the secret-key operations; the server receives
// only the installed evaluator.
func NewCanonicalRouteBDepth2() (
	*RouteBDepth2Client,
	*RouteBDepth2Server,
	RouteBDepth2SetupInfo,
	error,
) {
	client, server, report, err := secureeval.NewCanonicalRouteBDepth2Session()
	if err != nil {
		return nil, nil, RouteBDepth2SetupInfo{}, fmt.Errorf("ckksint: create canonical Route-B depth2 session: %w", err)
	}
	return &RouteBDepth2Client{inner: client}, &RouteBDepth2Server{inner: server}, RouteBDepth2SetupInfo{
		ParameterArtifactWallTime: report.ParameterArtifactWallTime,
		KeyGenerationWallTime:     report.KeyGenerationWallTime,
		ServerInstallWallTime:     report.ServerInstallWallTime,
	}, nil
}

// EncryptDepth2 validates and encrypts one batch, padding it internally to the
// canonical 512-query layout.
func (client *RouteBDepth2Client) EncryptDepth2(
	features [][]int8,
	model Depth2Model,
) (*RouteBDepth2EncryptedInput, RouteBDepth2PhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 client is nil")
	}
	internalModel, err := canonicalRouteBDepth2Model(model)
	if err != nil {
		return nil, RouteBDepth2PhaseInfo{}, err
	}
	input, report, err := client.inner.EncryptDepth2(features, internalModel)
	if err != nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: encrypt canonical Route-B depth2 request: %w", err)
	}
	return &RouteBDepth2EncryptedInput{inner: input}, routeBDepth2PhaseInfo(report), nil
}

// EvaluateDepth2 evaluates one opaque request. A canonical Route-B server is
// single-use because the installed lifecycle admits exactly one first HE run.
func (server *RouteBDepth2Server) EvaluateDepth2(
	input *RouteBDepth2EncryptedInput,
) (*RouteBDepth2EncryptedOutput, RouteBDepth2PhaseInfo, error) {
	if server == nil || server.inner == nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 server is nil")
	}
	if input == nil || input.inner == nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 encrypted input is nil")
	}
	output, report, err := server.inner.EvaluateDepth2(input.inner)
	if err != nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: evaluate canonical Route-B depth2 request: %w", err)
	}
	return &RouteBDepth2EncryptedOutput{inner: output}, routeBDepth2PhaseInfo(report), nil
}

// DecryptDepth2 decrypts the opaque result and returns only the original
// (unpadded) query count.
func (client *RouteBDepth2Client) DecryptDepth2(
	output *RouteBDepth2EncryptedOutput,
) ([]float64, RouteBDepth2PhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 client is nil")
	}
	if output == nil || output.inner == nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B depth2 encrypted output is nil")
	}
	values, report, err := client.inner.DecryptDepth2(output.inner)
	if err != nil {
		return nil, RouteBDepth2PhaseInfo{}, fmt.Errorf("ckksint: decrypt canonical Route-B depth2 result: %w", err)
	}
	return values, routeBDepth2PhaseInfo(report), nil
}

// Close releases the server-side installed evaluator. It is idempotent.
func (server *RouteBDepth2Server) Close() {
	if server == nil || server.inner == nil {
		return
	}
	server.inner.Close()
}

func canonicalRouteBDepth2Model(model Depth2Model) (secureeval.RouteBSigned8Depth2SelectedChildModel, error) {
	var featureIDs [3]uint32
	for node, featureID := range model.FeatureIDs {
		if featureID < 0 || uint64(featureID) > uint64(^uint32(0)) {
			return secureeval.RouteBSigned8Depth2SelectedChildModel{}, fmt.Errorf(
				"ckksint: canonical Route-B depth2 feature id %d at node %d is invalid", featureID, node,
			)
		}
		featureIDs[node] = uint32(featureID)
	}
	thresholds := [3]int64{int64(model.Thresholds[0]), int64(model.Thresholds[1]), int64(model.Thresholds[2])}
	result, err := secureeval.NewRouteBSigned8Depth2SelectedChildModel(featureIDs, thresholds, model.Leaves)
	if err != nil {
		return secureeval.RouteBSigned8Depth2SelectedChildModel{}, fmt.Errorf(
			"ckksint: canonical Route-B depth2 model: %w", err,
		)
	}
	return result, nil
}

func routeBDepth2PhaseInfo(report secureeval.RouteBDepth2PhaseReport) RouteBDepth2PhaseInfo {
	return RouteBDepth2PhaseInfo{
		Phase: report.Phase, QueryCount: report.QueryCount,
		WallTime: report.WallTime, TraceDigest: report.TraceDigest,
	}
}
