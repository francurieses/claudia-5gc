package gtpu

import (
	"log/slog"
	"testing"
)

// dlBenchSink keeps the compiler from eliding the header write.
var dlBenchSink byte

// BenchmarkDLHeader measures the in-place 16-octet DL encapsulation alone
// (GTP-U header + PDU Session Container, no options). REL19-6.3 baseline:
// the no-option path must stay within ±3 % of the pre-refactor figure.
// Ref: TS 29.281 §5.1, §5.2.1; TS 38.415 §5.5.2.1.
func BenchmarkDLHeader(b *testing.B) {
	h := make([]byte, dlHeadroom)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		putDLHeader(h, 0xDEADBEEF, uint8(i), 1400)
	}
	dlBenchSink = h[14]
}

// BenchmarkDLEncap1400Info and BenchmarkDLEncap64Info run the full TUN→N3
// iteration (copy, header write, sendto) used by benchDownlink.
func BenchmarkDLEncap1400Info(b *testing.B) { benchDownlink(b, slog.LevelInfo, 1400) }
func BenchmarkDLEncap64Info(b *testing.B)   { benchDownlink(b, slog.LevelInfo, 64) }
