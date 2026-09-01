package secureeval

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxLinuxMeminfoBytes = 64 * 1024

var errUnsupportedPhysicalMemorySampler = errors.New("secureeval: physical-memory sampling is unsupported on this platform")

type physicalMemoryTotals struct {
	total     uint64
	available uint64
}

func (value physicalMemoryTotals) validate() error {
	if value.total == 0 || value.available > value.total {
		return fmt.Errorf("secureeval: invalid physical-memory totals %d/%d", value.total, value.available)
	}
	return nil
}

type productionPhysicalMemorySampler struct{}

type physicalMemorySampler interface {
	samplePhysicalMemory() (physicalMemoryTotals, error)
}

func parseLinuxPhysicalMemoryTotals(reader io.Reader) (physicalMemoryTotals, error) {
	if reader == nil {
		return physicalMemoryTotals{}, errors.New("secureeval: nil /proc/meminfo reader")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxLinuxMeminfoBytes+1))
	if err != nil {
		return physicalMemoryTotals{}, fmt.Errorf("secureeval: read /proc/meminfo: %w", err)
	}
	if len(payload) > maxLinuxMeminfoBytes {
		return physicalMemoryTotals{}, errors.New("secureeval: /proc/meminfo exceeds the bounded parser limit")
	}

	var value physicalMemoryTotals
	var totalSeen, availableSeen bool
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return physicalMemoryTotals{}, fmt.Errorf("secureeval: malformed %s line in /proc/meminfo", fields[0])
		}
		kilobytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil || kilobytes > ^uint64(0)/1024 {
			return physicalMemoryTotals{}, fmt.Errorf("secureeval: invalid %s value in /proc/meminfo", fields[0])
		}
		bytes := kilobytes * 1024
		switch fields[0] {
		case "MemTotal:":
			if totalSeen {
				return physicalMemoryTotals{}, errors.New("secureeval: duplicate MemTotal in /proc/meminfo")
			}
			totalSeen, value.total = true, bytes
		case "MemAvailable:":
			if availableSeen {
				return physicalMemoryTotals{}, errors.New("secureeval: duplicate MemAvailable in /proc/meminfo")
			}
			availableSeen, value.available = true, bytes
		}
	}
	if !totalSeen || !availableSeen {
		return physicalMemoryTotals{}, errors.New("secureeval: /proc/meminfo lacks MemTotal or MemAvailable")
	}
	if err = value.validate(); err != nil {
		return physicalMemoryTotals{}, err
	}
	return value, nil
}
