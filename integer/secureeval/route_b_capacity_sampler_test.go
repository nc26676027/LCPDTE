package secureeval

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseLinuxPhysicalMemoryTotals(t *testing.T) {
	valid := "MemTotal:       32830200 kB\nMemFree:          100000 kB\nMemAvailable: 16789000 kB\n"
	totals, err := parseLinuxPhysicalMemoryTotals(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if totals.total != 32_830_200*1024 || totals.available != 16_789_000*1024 {
		t.Fatalf("Linux totals=%+v", totals)
	}

	tests := []struct {
		name, input string
	}{
		{"missing total", "MemAvailable: 1 kB\n"},
		{"missing available", "MemTotal: 1 kB\n"},
		{"duplicate total", "MemTotal: 1 kB\nMemTotal: 1 kB\nMemAvailable: 1 kB\n"},
		{"duplicate available", "MemTotal: 1 kB\nMemAvailable: 1 kB\nMemAvailable: 1 kB\n"},
		{"bad unit", "MemTotal: 2 MB\nMemAvailable: 1 kB\n"},
		{"negative", "MemTotal: -2 kB\nMemAvailable: 1 kB\n"},
		{"non decimal", "MemTotal: 0x20 kB\nMemAvailable: 1 kB\n"},
		{"zero total", "MemTotal: 0 kB\nMemAvailable: 0 kB\n"},
		{"available exceeds total", "MemTotal: 1 kB\nMemAvailable: 2 kB\n"},
		{"overflow", "MemTotal: " + uintString(math.MaxUint64/1024+1) + " kB\nMemAvailable: 1 kB\n"},
		{"extra fields", "MemTotal: 2 kB trailing\nMemAvailable: 1 kB\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseLinuxPhysicalMemoryTotals(strings.NewReader(test.input)); err == nil {
				t.Fatal("invalid Linux memory snapshot was accepted")
			}
		})
	}

	oversized := strings.Repeat("x", maxLinuxMeminfoBytes+1)
	if _, err = parseLinuxPhysicalMemoryTotals(strings.NewReader(oversized)); err == nil {
		t.Fatal("oversized /proc/meminfo was accepted")
	}
}

func TestProductionPhysicalMemorySamplerSmoke(t *testing.T) {
	totals, err := (productionPhysicalMemorySampler{}).samplePhysicalMemory()
	if err != nil {
		if errors.Is(err, errUnsupportedPhysicalMemorySampler) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if totals.total == 0 || totals.available > totals.total {
		t.Fatalf("production physical memory totals=%+v", totals)
	}
}

func uintString(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var scratch [20]byte
	index := len(scratch)
	for value != 0 {
		index--
		scratch[index] = digits[value%10]
		value /= 10
	}
	return string(scratch[index:])
}
