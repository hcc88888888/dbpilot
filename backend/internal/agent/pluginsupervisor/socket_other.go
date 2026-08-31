//go:build !linux

package pluginsupervisor

func prepareRuntimeSocket(string) error { return nil }
