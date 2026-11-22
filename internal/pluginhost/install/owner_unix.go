// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package install

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// verifyTreeOwner asserts that every published file and directory belongs to
// root. ARCH §5.1/§6.2 requires it because a plugin runs as an unprivileged
// user and must not be able to rewrite its own code; the installer gets that
// for free by running as root, so this is a cheap assertion that it actually
// happened (for example, a setgid plugin root would break it). Unprivileged
// runs, which is how the tests run, skip the check.
func verifyTreeOwner(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if st.Uid != 0 || st.Gid != 0 {
			return fmt.Errorf("install: %s is owned by %d:%d, but a published package must belong to root", p, st.Uid, st.Gid)
		}
		return nil
	})
}
