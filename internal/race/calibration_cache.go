package race

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// CalibrationCache holds persistently cached calibration offsets keyed by
// the SHA256 hash of the qBittorrent binary. This allows skipping the
// calibration phase on daemon restart when the binary hasn't changed.
type CalibrationCache struct {
	BinaryHash     string `json:"binary_hash"`
	SockaddrOffset int    `json:"sockaddr_offset"`
	PeerIDOffset   int    `json:"peer_id_offset"`
	CalibratedAt   string `json:"calibrated_at"`
}

// LoadCalibrationCache reads a calibration cache from a JSON file.
// Returns nil if the file doesn't exist or is unreadable.
func LoadCalibrationCache(path string) *CalibrationCache {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cache CalibrationCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	if cache.BinaryHash == "" || cache.SockaddrOffset < 0 {
		return nil
	}
	return &cache
}

// SaveCalibrationCache writes calibration offsets to a JSON file.
func SaveCalibrationCache(path string, binaryHash string, sockaddrOffset, peerIDOffset int) error {
	cache := CalibrationCache{
		BinaryHash:     binaryHash,
		SockaddrOffset: sockaddrOffset,
		PeerIDOffset:   peerIDOffset,
		CalibratedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling calibration cache: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing calibration cache: %w", err)
	}
	return nil
}

// ComputeBinaryHash returns the SHA256 hex digest of a file.
func ComputeBinaryHash(binPath string) (string, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return "", fmt.Errorf("opening binary for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing binary: %w", err)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
