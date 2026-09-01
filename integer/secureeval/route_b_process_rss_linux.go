//go:build linux

package secureeval

import (
	"fmt"
	"os"
)

func sampleProductionProcessPeakRSS() (uint64, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("secureeval: open /proc/self/status: %w", err)
	}
	defer file.Close()
	return parseLinuxProcessPeakRSS(file)
}
