//go:build darwin || freebsd || openbsd || netbsd

package heartbeat

func newScheduler() Scheduler { return &cronScheduler{} }
