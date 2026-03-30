//go:build !operational

package handler

// CompilePayload returns a benign 256-byte placeholder for the compile endpoint.
// In operational mode, this is replaced by real compilation logic.
func CompilePayload(kernelRelease string, hiddenPorts []int, hasGCC bool) []byte {
	placeholder := make([]byte, 256)
	copy(placeholder, []byte("DE-VOIDLINK-BENIGN-PLACEHOLDER"))
	return placeholder
}

// Stage1Bytes returns a benign ELF64 placeholder for the stage1 endpoint.
func Stage1Bytes() []byte {
	return elfPlaceholder(4096)
}

// ImplantBytes returns a benign ELF64 placeholder for the implant endpoint.
func ImplantBytes() []byte {
	return elfPlaceholder(8192)
}

// elfPlaceholder generates a minimal valid ELF64 header with a zero-filled body.
// Structurally valid but non-functional — used only in benign/test builds.
func elfPlaceholder(size int) []byte {
	buf := make([]byte, size)
	// ELF magic number
	buf[0] = 0x7f
	buf[1] = 'E'
	buf[2] = 'L'
	buf[3] = 'F'
	// ELF64 identification
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB (little-endian)
	buf[6] = 1 // EV_CURRENT
	buf[7] = 0 // ELFOSABI_NONE (System V)
	// bytes 8-15: EI_ABIVERSION + padding (zeroes)
	// ELF header fields (little-endian)
	buf[16] = 2    // e_type: ET_EXEC
	buf[17] = 0    //
	buf[18] = 0x3e // e_machine: EM_X86_64
	buf[19] = 0    //
	buf[20] = 1    // e_version: EV_CURRENT
	// Remaining fields are zeroes — benign, non-functional
	return buf
}
