//go:build sam_debug

package main

/*
#include <stdlib.h>
*/
import "C"

import "github.com/google/sam/mobile/sam-node-ffi/ffi"

//export PublishSharedMeshA2AService
func PublishSharedMeshA2AService(request *C.char) *C.char {
	return C.CString(ffi.PublishSharedMeshA2AService(C.GoString(request)))
}

//export StartSharedMeshA2AGateway
func StartSharedMeshA2AGateway() *C.char {
	return C.CString(ffi.StartSharedMeshA2AGateway())
}

//export DiscoverSharedMeshA2AServices
func DiscoverSharedMeshA2AServices() *C.char {
	return C.CString(ffi.DiscoverSharedMeshA2AServices())
}
