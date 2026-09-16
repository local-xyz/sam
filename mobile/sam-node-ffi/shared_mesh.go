//go:build sam_debug

package main

/*
#include <stdlib.h>
*/
import "C"

import "github.com/google/sam/mobile/sam-node-ffi/ffi"

//export StartSharedMesh
func StartSharedMesh(config *C.char) *C.char {
	if err := ffi.StartSharedMesh(C.GoString(config)); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export StopSharedMesh
func StopSharedMesh() *C.char {
	if err := ffi.StopSharedMesh(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export SharedMeshStatus
func SharedMeshStatus() *C.char { return C.CString(ffi.SharedMeshStatus()) }

//export DiscoverSharedMeshTools
func DiscoverSharedMeshTools() *C.char { return C.CString(ffi.DiscoverSharedMeshTools()) }

//export CallSharedMeshTool
func CallSharedMeshTool(request *C.char) *C.char {
	return C.CString(ffi.CallSharedMeshTool(C.GoString(request)))
}
