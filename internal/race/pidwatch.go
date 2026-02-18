package race

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// WatchPID returns a channel that receives an error when the given PID exits.
// Uses pidfd_open (Linux 5.3+) for event-driven process death notification.
// The returned channel is buffered (size 1) and will receive exactly one value.
func WatchPID(pid int) <-chan error {
	ch := make(chan error, 1)

	go func() {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			ch <- fmt.Errorf("pidfd_open(%d): %w", pid, err)
			return
		}
		defer unix.Close(fd)

		// Block until the process exits. POLLIN becomes ready when PID dies.
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1) // block indefinitely
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				ch <- fmt.Errorf("polling pidfd for PID %d: %w", pid, err)
				return
			}
			ch <- fmt.Errorf("target qBittorrent process (PID %d) exited", pid)
			return
		}
	}()

	return ch
}
