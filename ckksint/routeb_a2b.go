package ckksint

import (
	"fmt"
	"time"

	"github.com/nc26676027/LCPDTE/integer/secureeval"
)

// CanonicalRouteBA2BMaxWords is the fixed capacity of one canonical Route-B
// A2B ciphertext.
const CanonicalRouteBA2BMaxWords = secureeval.CanonicalRouteBA2BMaxWords

// RouteBA2BSetupInfo reports the setup/keygen/install split for the canonical
// Route-B A2B evaluator.
type RouteBA2BSetupInfo struct {
	ParameterArtifactWallTime time.Duration
	KeyGenerationWallTime     time.Duration
	ServerInstallWallTime     time.Duration
}

// RouteBA2BPhaseInfo reports one client or server phase. OnlineWallTime is the
// prepared A2B execution interval; PreparationWallTime is nonzero only when a
// server prepares the reusable circuit.
type RouteBA2BPhaseInfo struct {
	Phase               string
	WordCount           int
	WallTime            time.Duration
	PreparationWallTime time.Duration
	OnlineWallTime      time.Duration
	TraceDigest         string
}

// RouteBA2BClient owns encryption and decryption state for one session.
type RouteBA2BClient struct{ inner *secureeval.RouteBA2BClient }

// RouteBA2BServer owns the prepared evaluator for one session.
type RouteBA2BServer struct{ inner *secureeval.RouteBA2BServer }

// RouteBA2BEncryptedInput is an opaque session-bound arithmetic input.
type RouteBA2BEncryptedInput struct {
	inner *secureeval.RouteBA2BEncryptedInput
}

// RouteBA2BEncryptedOutput is an opaque session-bound Boolean result.
type RouteBA2BEncryptedOutput struct {
	inner *secureeval.RouteBA2BEncryptedOutput
}

// NewCanonicalRouteBA2B constructs the canonical Route-B A2B client/server.
func NewCanonicalRouteBA2B() (*RouteBA2BClient, *RouteBA2BServer, RouteBA2BSetupInfo, error) {
	client, server, report, err := secureeval.NewCanonicalRouteBA2BSession()
	if err != nil {
		return nil, nil, RouteBA2BSetupInfo{}, fmt.Errorf("ckksint: create canonical Route-B A2B session: %w", err)
	}
	return &RouteBA2BClient{inner: client}, &RouteBA2BServer{inner: server}, RouteBA2BSetupInfo{
		ParameterArtifactWallTime: report.ParameterArtifactWallTime,
		KeyGenerationWallTime:     report.KeyGenerationWallTime,
		ServerInstallWallTime:     report.ServerInstallWallTime,
	}, nil
}

// EncryptA2B encrypts one packed byte batch.
func (client *RouteBA2BClient) EncryptA2B(words []uint8) (*RouteBA2BEncryptedInput, RouteBA2BPhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B A2B client is nil")
	}
	input, report, err := client.inner.EncryptA2B(words)
	if err != nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: encrypt canonical Route-B A2B input: %w", err)
	}
	return &RouteBA2BEncryptedInput{inner: input}, routeBA2BPhaseInfo(report), nil
}

// EvaluateA2B executes complete 8-bit A2B. Calls are serialized and reusable.
func (server *RouteBA2BServer) EvaluateA2B(input *RouteBA2BEncryptedInput) (*RouteBA2BEncryptedOutput, RouteBA2BPhaseInfo, error) {
	if server == nil || server.inner == nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B A2B server is nil")
	}
	if input == nil || input.inner == nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B A2B encrypted input is nil")
	}
	output, report, err := server.inner.EvaluateA2B(input.inner)
	if err != nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: evaluate canonical Route-B A2B input: %w", err)
	}
	return &RouteBA2BEncryptedOutput{inner: output}, routeBA2BPhaseInfo(report), nil
}

// DecryptA2B returns one LSB-first bit vector per input byte.
func (client *RouteBA2BClient) DecryptA2B(output *RouteBA2BEncryptedOutput) ([][8]uint8, RouteBA2BPhaseInfo, error) {
	if client == nil || client.inner == nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B A2B client is nil")
	}
	if output == nil || output.inner == nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: canonical Route-B A2B encrypted output is nil")
	}
	bits, report, err := client.inner.DecryptA2B(output.inner)
	if err != nil {
		return nil, RouteBA2BPhaseInfo{}, fmt.Errorf("ckksint: decrypt canonical Route-B A2B output: %w", err)
	}
	return bits, routeBA2BPhaseInfo(report), nil
}

// Close releases the server-side evaluator.
func (server *RouteBA2BServer) Close() {
	if server == nil || server.inner == nil {
		return
	}
	server.inner.Close()
}

func routeBA2BPhaseInfo(report secureeval.RouteBA2BPhaseReport) RouteBA2BPhaseInfo {
	return RouteBA2BPhaseInfo{
		Phase: report.Phase, WordCount: report.WordCount, WallTime: report.WallTime,
		PreparationWallTime: report.PreparationWallTime, OnlineWallTime: report.OnlineWallTime,
		TraceDigest: report.TraceDigest,
	}
}
