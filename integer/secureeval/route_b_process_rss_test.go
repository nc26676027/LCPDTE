package secureeval

import (
	"errors"
	"strings"
	"testing"
)

func TestParseLinuxProcessPeakRSS(t *testing.T) {
	got, err := parseLinuxProcessPeakRSS(strings.NewReader("Name:\tdt_go\nVmRSS:\t8 kB\nVmHWM:\t12345 kB\n"))
	if err != nil || got != 12_641_280 {
		t.Fatalf("valid VmHWM parsed as %d/%v", got, err)
	}
	tests := []struct {
		name    string
		payload string
	}{
		{name: "missing", payload: "VmRSS: 1 kB\n"},
		{name: "duplicate", payload: "VmHWM: 1 kB\nVmHWM: 2 kB\n"},
		{name: "zero", payload: "VmHWM: 0 kB\n"},
		{name: "bad unit", payload: "VmHWM: 1 MB\n"},
		{name: "negative", payload: "VmHWM: -1 kB\n"},
		{name: "positive sign", payload: "VmHWM: +1 kB\n"},
		{name: "nondecimal", payload: "VmHWM: 0x10 kB\n"},
		{name: "extra field", payload: "VmHWM: 1 kB trailing\n"},
		{name: "overflow", payload: "VmHWM: 18014398509481984 kB\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if value, err := parseLinuxProcessPeakRSS(strings.NewReader(test.payload)); err == nil || value != 0 {
				t.Fatalf("invalid VmHWM returned value/error=%d/%v", value, err)
			}
		})
	}
	if value, err := parseLinuxProcessPeakRSS(nil); err == nil || value != 0 {
		t.Fatalf("nil reader returned value/error=%d/%v", value, err)
	}
	failing := &processRSSFailingReader{err: errors.New("read sentinel")}
	if value, err := parseLinuxProcessPeakRSS(failing); !errors.Is(err, failing.err) || value != 0 {
		t.Fatalf("reader error returned value/error=%d/%v", value, err)
	}
	oversized := strings.NewReader(strings.Repeat("x", maxLinuxProcessStatusBytes+1))
	if value, err := parseLinuxProcessPeakRSS(oversized); err == nil || value != 0 {
		t.Fatalf("oversized status returned value/error=%d/%v", value, err)
	}
}

func TestProductionProcessPeakRSSSmoke(t *testing.T) {
	peak, err := sampleProductionProcessPeakRSS()
	if err != nil {
		t.Fatal(err)
	}
	if peak == 0 {
		t.Fatal("production process peak RSS is zero")
	}
}

type processRSSFailingReader struct{ err error }

func (reader *processRSSFailingReader) Read([]byte) (int, error) { return 0, reader.err }
