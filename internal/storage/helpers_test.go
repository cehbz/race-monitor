package storage

// Schema v5 removed the race_peers table entirely. All peer information is now
// tracked via connections table with calibration-derived IP, port, peer_id, and
// client fields. No test helpers currently needed.

