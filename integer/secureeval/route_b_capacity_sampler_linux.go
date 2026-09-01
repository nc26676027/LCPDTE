//go:build linux

package secureeval

import (
	"fmt"
	"os"
)

func (productionPhysicalMemorySampler) samplePhysicalMemory() (physicalMemoryTotals, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return physicalMemoryTotals{}, fmt.Errorf("secureeval: open /proc/meminfo: %w", err)
	}
	defer file.Close()
	return parseLinuxPhysicalMemoryTotals(file)
}
