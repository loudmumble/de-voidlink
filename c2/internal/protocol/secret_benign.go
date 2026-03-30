//go:build !operational

package protocol

// GetSecret returns the hardcoded test key for benign/development builds.
// In operational mode, this is replaced by environment variable lookup.
func GetSecret() string {
	return "de-voidlink-test-key-do-not-use"
}
