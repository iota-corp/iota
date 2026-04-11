//go:build !windows

package audittail

import (
	"os"
	"syscall"
)

func inodeOf(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}
