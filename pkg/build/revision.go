package build

import "runtime/debug"

var revision = vcsRevision()

func vcsRevision() string {
	rev := "unknown"
	dirty := false
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return rev
	}
	for _, setting := range buildInfo.Settings {
		switch setting.Key {
		case "vcs.revision":
			rev = setting.Value
			if len(rev) > 7 {
				rev = rev[:7]
			}
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}
