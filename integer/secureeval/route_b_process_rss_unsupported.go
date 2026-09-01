//go:build !windows && !linux

package secureeval

func sampleProductionProcessPeakRSS() (uint64, error) {
	return 0, errUnsupportedProcessPeakRSS
}
