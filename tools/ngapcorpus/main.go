// Command ngapcorpus extracts NGAP-PDUs from local pcaps (tshark) into sanitised hex vectors for the
// NGAP equivalence corpus (shared/ngap/testdata/corpus/pcap-*.hex, REL19-4.4).
//
// Pcaps are git-ignored; only the sanitised hex vectors are committed. Sanitisation: every NAS
// 5GS mobile identity carrying a null-scheme SUCI (TS 24.501 §9.11.3.4) has its MSIN digits
// overwritten in place with "0" filler, so lengths (and the PER encoding) stay valid. Run from the
// repository root via scripts/ngap-corpus-from-pcap.sh.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/francurieses/claudia-5gc/shared/ngap"
)

// sanitiseSUCI overwrites the MSIN of every null-scheme SUCI found in b with zero digits and
// returns the number of identities blanked. The IE is LV-E: len(2) | 0x01 (type SUCI, SUPI format
// IMSI) | PLMN(3) | routing indicator(2) | scheme 0x00 | HN key id 0x00 | MSIN (BCD, len-8 octets).
func sanitiseSUCI(b []byte) int {
	n := 0
	for i := 2; i+8 <= len(b); i++ {
		if b[i] != 0x01 || b[i+6] != 0x00 || b[i+7] != 0x00 {
			continue
		}
		l := int(b[i-2])<<8 | int(b[i-1])
		if l < 9 || l > 13 || i+l > len(b) {
			continue
		}
		for j := i + 8; j < i+l; j++ {
			b[j] = 0x00
		}
		n++
	}
	return n
}

type vec struct {
	data []byte
	name string // procedure name + kind
	key  string
}

func procedureNames(path string) (map[int64]string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`const ProcedureCode(\w+) int64 = (\d+)`)
	out := map[int64]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		v, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse procedure code %s: %w", m[1], err)
		}
		out[v] = m[1]
	}
	return out, nil
}

// rawPDUs flattens the tshark ngap_raw field: [hex pos len mask type] or a list of those for
// frames carrying several NGAP-PDUs.
func rawPDUs(v interface{}) []string {
	l, ok := v.([]interface{})
	if !ok || len(l) == 0 {
		return nil
	}
	if s, ok := l[0].(string); ok {
		return []string{s}
	}
	var out []string
	for _, e := range l {
		out = append(out, rawPDUs(e)...)
	}
	return out
}

func main() {
	pcapDir := flag.String("pcaps", "pcaps/amf", "directory of *.pcap files")
	outDir := flag.String("out", "shared/ngap/testdata/corpus", "output directory")
	consts := flag.String("consts", "shared/ngap/ngapType/ngap_constants.go", "ngapType constants (procedure names)")
	tshark := flag.String("tshark", "tshark", "tshark binary")
	perGroup := flag.Int("per-group", 3, "max vectors per (procedure, PDU kind)")
	maxTotal := flag.Int("max", 60, "max vectors written")
	flag.Parse()

	names, err := procedureNames(*consts)
	if err != nil {
		fatal(err)
	}
	pcaps, err := filepath.Glob(filepath.Join(*pcapDir, "*.pcap"))
	if err != nil {
		fatal(fmt.Errorf("glob pcaps: %w", err))
	}
	sort.Strings(pcaps)
	if len(pcaps) == 0 {
		fatal(fmt.Errorf("no pcaps in %s", *pcapDir))
	}
	kinds := []string{"im", "so", "uo"}
	seen := map[string]bool{}
	groups := map[string][]vec{}
	var order []string
	blanked, readOK := 0, 0
	for _, p := range pcaps {
		out, err := exec.Command(*tshark, //nolint:gosec // G204: dev tool, tshark path is the operator-supplied flag
			"-r", p, "-Y", "ngap", "-T", "json", "-j", "ngap", "-x").Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", p, err)
			continue
		}
		var pkts []struct {
			Source struct {
				Layers map[string]interface{} `json:"layers"`
			} `json:"_source"`
		}
		if err := json.Unmarshal(out, &pkts); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", p, err)
			continue
		}
		readOK++
		for _, pk := range pkts {
			for _, h := range rawPDUs(pk.Source.Layers["ngap_raw"]) {
				b, err := hex.DecodeString(h)
				if err != nil || len(b) == 0 {
					continue
				}
				blanked += sanitiseSUCI(b)
				pdu, err := ngap.Decoder(b)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: %s: PDU does not decode (kept out): %v\n", p, err)
					continue
				}
				var pc int64
				switch {
				case pdu.InitiatingMessage != nil:
					pc = pdu.InitiatingMessage.ProcedureCode.Value
				case pdu.SuccessfulOutcome != nil:
					pc = pdu.SuccessfulOutcome.ProcedureCode.Value
				case pdu.UnsuccessfulOutcome != nil:
					pc = pdu.UnsuccessfulOutcome.ProcedureCode.Value
				}
				sum := sha256.Sum256(b)
				id := hex.EncodeToString(sum[:])
				if seen[id] {
					continue
				}
				seen[id] = true
				name := names[pc]
				if name == "" {
					name = "Procedure" + strconv.FormatInt(pc, 10)
				}
				if pdu.Present < 1 || pdu.Present > len(kinds) {
					fmt.Fprintf(os.Stderr, "warn: %s: NGAP-PDU with unknown CHOICE %d (kept out)\n", p, pdu.Present)
					continue
				}
				k := kinds[pdu.Present-1]
				g := name + "-" + k
				if _, ok := groups[g]; !ok {
					order = append(order, g)
				}
				groups[g] = append(groups[g], vec{data: b, name: g, key: id})
			}
		}
	}
	if readOK == 0 {
		fatal(fmt.Errorf("tshark failed on every pcap in %s", *pcapDir))
	}
	if len(order) == 0 {
		fatal(fmt.Errorf("no decodable NGAP PDUs in %s", *pcapDir))
	}
	// Round-robin over groups so distinct procedures are preferred over repeats.
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}
	written := 0
	for round := 0; round < *perGroup && written < *maxTotal; round++ {
		for _, g := range order {
			if round >= len(groups[g]) || written >= *maxTotal {
				continue
			}
			v := groups[g][round]
			f := filepath.Join(*outDir, fmt.Sprintf("pcap-%s-%s.hex", v.name, v.key[:8]))
			if err := os.WriteFile(f, append([]byte(hex.EncodeToString(v.data)), '\n'), 0o644); err != nil { //nolint:gosec // G306: corpus fixtures are meant to be world-readable
				fatal(err)
			}
			written++
		}
	}
	fmt.Printf("ngapcorpus: %d vectors written to %s (%d SUCI MSIN blanked, %d groups)\n", written, *outDir, blanked, len(order))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ngapcorpus:", err)
	os.Exit(1)
}
