//go:build !windows && !linux

package secureeval

func (productionPhysicalMemorySampler) samplePhysicalMemory() (physicalMemoryTotals, error) {
	return physicalMemoryTotals{}, errUnsupportedPhysicalMemorySampler
}
