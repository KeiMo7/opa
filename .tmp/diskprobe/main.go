package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

type entry struct {
	path string
	size int64
}

func main() {
	roots := []string{"/tmp", "/home/wll"}
	var entries []entry
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			entries = append(entries, entry{path, info.Size()})
			return nil
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].size > entries[j].size })
	out, err := os.Create("/home/wll/uid82/.tmp/diskprobe/out.txt")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	fmt.Fprintln(out, "TOP 30 FILES:")
	for i, e := range entries {
		if i >= 30 {
			break
		}
		fmt.Fprintf(out, "%12d  %s\n", e.size, e.path)
	}
	var tmpTotal int64
	for _, e := range entries {
		if len(e.path) >= 4 && e.path[:4] == "/tmp" {
			tmpTotal += e.size
		}
	}
	fmt.Fprintf(out, "\n/tmp regular-file total: %d bytes (%.2f GB)\n", tmpTotal, float64(tmpTotal)/1e9)

	fmt.Fprintln(out, "\nSTATFS:")
	for _, p := range []string{"/tmp", "/", "/home/wll"} {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(p, &stat); err != nil {
			fmt.Fprintln(out, p, err)
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		fmt.Fprintf(out, "%s total=%.2fGB free=%.2fGB\n", p, float64(total)/1e9, float64(free)/1e9)
	}
}
