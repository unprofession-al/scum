package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

type RootFS struct {
	fs.Inode
	data map[string][]byte
}

func (r *RootFS) OnAdd(ctx context.Context) {
	counter := uint64(2)
	for filename, data := range r.data {
		ch := r.NewPersistentInode(
			ctx, &fs.MemRegularFile{
				Data: data,
				Attr: fuse.Attr{
					Mode: 0600,
				},
			}, fs.StableAttr{Ino: counter})
		r.AddChild(filename, ch, false)
		counter++
	}
}

func (r *RootFS) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = 0700
	return 0
}

var _ = (fs.NodeGetattrer)((*RootFS)(nil))
var _ = (fs.NodeOnAdder)((*RootFS)(nil))

func mount(mountpoint string, data map[string][]byte, timeout int, debug bool) {
	opts := &fs.Options{}
	opts.Debug = debug
	server, err := fs.Mount(mountpoint, &RootFS{data: data}, opts)
	if err != nil {
		log.Fatalf("Mount fail: %v\n", err)
	}
	fmt.Printf("Mounted for %d seconds or until Ctrl+C is pressed...\n", timeout)
	w := Wait{
		Seconds: timeout,
		Out:     os.Stderr,
	}
	w.Start()
	fmt.Printf("\n")

	server.Unmount()
}
