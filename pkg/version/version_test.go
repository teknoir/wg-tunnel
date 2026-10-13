package version

import "testing"

func TestDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must never be empty")
	}
}
