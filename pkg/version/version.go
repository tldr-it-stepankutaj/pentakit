package version

var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "20250830160101"
)

// String returns a human-readable version string.
func String() string {
	return "pentakit " + Version + " (" + GitCommit + ", " + BuildDate + ")"
}
