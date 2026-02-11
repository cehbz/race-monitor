package capture

import "log/slog"

// LevelTrace is a verbose log level below Debug for per-event tracing.
const LevelTrace = slog.LevelDebug - 4
