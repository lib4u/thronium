//go:build debug

package parentcheck

func CheckParentProcess() {}

var ManagedWorker bool

func Fork() bool           { return false }
func ManagedAllowed() bool { return false }
