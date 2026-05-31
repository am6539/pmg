// Package heartbeat installs an OS-level scheduled task that periodically runs
// `pmg cloud heartbeat`. PMG is not a daemon, so without a scheduler the
// dashboard only sees a machine when a package manager command runs. The
// scheduled task keeps the agent's last_seen fresh while the machine is on and
// gives self-update a regular chance to fire.
package heartbeat

const (
	// taskName identifies the PMG heartbeat scheduled task / cron marker.
	taskName = "pmg-heartbeat"

	// intervalMinutes is how often the heartbeat runs.
	intervalMinutes = 15
)

// Scheduler installs and removes the periodic heartbeat task for the host OS.
type Scheduler interface {
	// Install registers a scheduled task running `pmgPath cloud heartbeat`
	// every intervalMinutes. Calling Install again replaces any existing task.
	Install(pmgPath string) error
	// Remove deletes the scheduled task. Removing a non-existent task is not an error.
	Remove() error
}

// NewScheduler returns the platform-specific scheduler implementation.
func NewScheduler() Scheduler {
	return newScheduler()
}
