//go:build linux

package parentcheck

import (
	"fmt"
	"io/fs"
	"os"
	"testing"
)

func TestOnlyAPermissionRefusalMarksAnImageRootCannotReach(t *testing.T) {
	if !unreachableForRoot(&fs.PathError{Op: "stat", Path: "/tmp/.mount_x/usr/bin/Thronium", Err: fs.ErrPermission}) {
		t.Fatal("a FUSE mount root cannot open was not recognised")
	}
	for _, err := range []error{nil, os.ErrNotExist, fmt.Errorf("other")} {
		if unreachableForRoot(err) {
			t.Fatal(err)
		}
	}
	// An ordinary user never gets the exception, whatever the parent.
	if os.Geteuid() != 0 && imageParent("/tmp/.mount_x/usr/bin/Thronium") {
		t.Fatal("exception outside root")
	}
}
