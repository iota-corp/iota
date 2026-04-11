//go:build windows

package audittail

import "os"

func inodeOf(_ os.FileInfo) uint64 {
	return 0
}
