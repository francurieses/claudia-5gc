package nia

// NIA1/NIA3 test vectors: TS 33.401 Annex C.4 (128-EIA1) and TS 35.223 /
// TS 33.401 Annex C.6 (128-EIA3) conformance test sets 1-6 and 1-5 (EIA1 set 7,
// 16448 bits, omitted), transcribed via free5GC nas internal/algo/nia_test.go
// (Apache-2.0).

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

type macVector struct {
	name   string
	count  uint32
	bearer byte
	dir    byte
	key    string
	bitLen int
	msg    string
	mac    string
}

var nia1Vectors = []macVector{
	{"TS 33.401 Annex C.4 128-EIA1 test set 1", 0x38a6f056, 0x1f, 0, "2bd6459f82c5b300952c49104881ff48", 88,
		"3332346263393861373479",
		"731f1165"},
	{"TS 33.401 Annex C.4 128-EIA1 test set 2", 0x36af6144, 0x18, 1, "7e5e94431e11d73828d739cc6ced4573", 254,
		"b3d3c9170a4e1632f60f861013d22d84b726b6a278d802d1eeaf1321ba5929dc",
		"e3259f6f"},
	{"TS 33.401 Annex C.4 128-EIA1 test set 3", 0xc7590ea9, 0x17, 0, "d3419be821087acd02123a9248033359", 511,
		"bbb057038809496bcff86d6fbc8ce5b135a06b166054f2d565be8ace75dc851e0bcdd8f07141c495872fb5d8c0c66a8b" +
			"6da556663e4e461205d84580bee5bc7e",
		"9a16c77d"},
	{"TS 33.401 Annex C.4 128-EIA1 test set 4", 0x36af6144, 0x0f, 1, "83fd23a244a74cf358da3019f1722635", 768,
		"35c68716633c66fb750c266865d53c11ea05b1e9fa49c8398d48e1efa5909d3947902837f5ae96d5a05bc8d61ca8dbef" +
			"1b13a4b4abfe4fb1006045b674bb54729304c382be53a5af05556176f6eaa2ef1d05e4b083181ee674cda5a485f74d7a",
		"bba74492"},
	{"TS 33.401 Annex C.4 128-EIA1 test set 5", 0x36af6144, 0x18, 0, "6832a65cff4473621ebdd4ba26a921fe", 383,
		"d3c53839626820717765667620323837636240981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc",
		"4145e4b0"},
	{"TS 33.401 Annex C.4 128-EIA1 test set 6", 0x7827fab2, 0x05, 1, "5d0a80d8134ae19677824b671e838af4", 2558,
		"70dedf2dc42c5cbd3a96f8a0b11418b3608d5733604a2cd36aabc70ce3193bb5153be2d3c06dfdb2d16e9c357158be6a" +
			"41d6b861e491db3fbfeb518efcf048d7d58953730ff30c9ec470ffcd663dc34201c36addc0111c35b38afee7cfdb582e" +
			"3731f8b4baa8d1a89c06e81199a9716227be344efcb436ddd0f096c064c3b5e2c399993fc77394f9e09720a811850ef2" +
			"3b2ee05d9e6173609d86e1c0c18ea51a012a00bb413b9cb8188a703cd6bae31cc67b34b1b00019e6a2b2a690f02671fe" +
			"7c9ef8dec0094e533763478d58d2c5f5b827a0148c5948a96931acf84f465a64e62ce74007e991e37ea823fa0fb21923" +
			"b79905b733b631e6c7d6860a3831ac351a9c730c52ff72d9d308eedbab21fde143a0ea17e23edc1f74cbb3638a2033aa" +
			"a15464eaa733385dbbeb6fd73509b857e6a419dca1d8907af977fbac4dfa35ec",
		"0fa2b1ee"},
}

var nia3Vectors = []macVector{
	{"TS 35.223 / TS 33.401 Annex C.6 128-EIA3 test set 1", 0x0, 0x0, 0, "00000000000000000000000000000000", 1,
		"00",
		"c8a9595e"},
	{"TS 35.223 / TS 33.401 Annex C.6 128-EIA3 test set 2", 0x561eb2dd, 0x14, 0, "47054125561eb2dda94059da05097850", 90,
		"000000000000000000000000",
		"6719a088"},
	{"TS 35.223 / TS 33.401 Annex C.6 128-EIA3 test set 3", 0xa94059da, 0xa, 1, "c9e6cec4607c72db000aefa88385ab0a", 577,
		"983b41d47d780c9e1ad11d7eb70391b1de0b35da2dc62f83e7b78d6306ca0ea07e941b7be91348f9fcb170e2217fecd9" +
			"7f9f68adb16e5d7d21e569d280ed775cebde3f4093c5388100",
		"fae8ff0b"},
	{"TS 35.223 / TS 33.401 Annex C.6 128-EIA3 test set 4", 0x05097850, 0x10, 1, "c8a48262d0c2e2bac4b96ef77e80ca59", 2079,
		"b546430bf87b4f1ee834704cd6951c36e26f108cf731788f48dc34f1678c05221c8fa7ff2f39f477e7e49ef60a4ec2c3" +
			"de24312a96aa26e1cfba57563838b297f47e8510c779fd6654b143386fa639d31edbd6c06e47d159d94362f26aeeedee" +
			"0e4f49d9bf8412995415bfad56ee82d1ca7463abf085b082b09904d6d990d43cf2e062f40839d93248b1eb92cdfed530" +
			"0bc148280430b6d0caa094b6ec8911ab7dc36824b824dc0af6682b0935fde7b492a14dc2f43648038da2cf79170d2d50" +
			"133fd49416cb6e33bea90b8bf4559b03732a01ea290e6d074f79bb83c10e580015cc1a85b36b5501046e9c4bdcae5135" +
			"690b8666bd54b7a703ea7b6f220a5469a568027e",
		"004ac4d6"},
	{"TS 35.223 / TS 33.401 Annex C.6 128-EIA3 test set 5", 0x561eb2dd, 0x1c, 0, "6b8b08ee79e0b5982d6d128ea9f220cb", 5670,
		"5bad724710ba1c56d5a315f8d40f6e093780be8e8de07b6992432018e08ed96a5734af8bad8a575d3a1f162f85045cc7" +
			"70925571d9f5b94e454a77c16e72936bf016ae157499f0543b5d52caa6dbeab697d2bb73e41b8075dce79b4b86044f66" +
			"1d4485a543dd78606e0419e8059859d3cb2b67ce0977603f81ff839e331859544cfbc8d00fef1a4c8510fb547d6b06c6" +
			"11ef44f1bce107cfa45a06aab360152b28dc1ebe6f7fe09b0516f9a5b02a1bd84bb0181e2e89e19bd8125930d178682f" +
			"3862dc51b636f04e720c47c3ce51ad70d94b9b2255fbae906549f499f8c6d39947ed5e5df8e2def113253e7b08d0a76b" +
			"6bfc68c812f375c79b8fe5fd85976aa6d46b4a2339d8ae5147f680fbe70f978b38effd7b2f7866a22554e193a94e98a6" +
			"8b74bd25bb2b3f5fb0a5fd59887f9ab68159b7178d5b7b677cb546bf41eadca216fc10850128f8bdef5c8d89f96afa4f" +
			"a8b54885565ed838a950fee5f1c3b0a4f6fb71e54dfd169e82cecc7266c850e67c5ef0ba960f5214060e71eb172a75fc" +
			"1486835cbea6534465b055c96a72e4105224182325d830414b40214daa8091d2e0fb010ae15c6de90850973bdf1e423b" +
			"e148a237b87a0c9f34d4b47605b803d743a86a90399a4af396d3a1200a62f3d9507962e8e5bee6d3da2bb3f7237664ac" +
			"7a292823900bc63503b29e80d63f6067bf8e1716ac25beba350deb62a99fe03185eb4f69937ecd387941fda544ba67db" +
			"0911774938b01827bcc69c92b3f772a9d2859ef003398b1f6bbad7b574f7989a1d10b2df798e0dbf30d6587464d24878" +
			"cd00c0eaee8a1a0cc753a27979e11b41db1de3d5038afaf49f5c682c3748d8a3a9ec54e6a371275f1683510f8e4f9093" +
			"8f9ab6e134c2cfdf4841cba88e0cff2b0bcc8e6adcb71109b5198fecf1bb7e5c531aca50a56a8a3b6de59862d41fa113" +
			"d9cd957808f08571d9a4bb792af271f6cc6dbb8dc7ec36e36be1ed308164c31c7c0afc541c",
		"0ca12792"},
}

func runMACVectors(t *testing.T, vs []macVector, f func(key []byte, count uint32, bearer, dir byte, msg []byte, bitLen int) ([]byte, error)) {
	t.Helper()
	for _, v := range vs {
		t.Run(v.name, func(t *testing.T) {
			key, _ := hex.DecodeString(v.key)
			msg, _ := hex.DecodeString(v.msg)
			want, _ := hex.DecodeString(v.mac)
			got, err := f(key, v.count, v.bearer, v.dir, msg, v.bitLen)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("MAC = %x, want %x", got, want)
			}
		})
	}
}

func TestNIA1Vectors(t *testing.T) { runMACVectors(t, nia1Vectors, NIA1Bits) }

func TestNIA3Vectors(t *testing.T) { runMACVectors(t, nia3Vectors, NIA3Bits) }

// TestNIABitsIgnoresTrailingBits: bits past bitLen must not change the MAC.
func TestNIABitsIgnoresTrailingBits(t *testing.T) {
	for _, f := range []func([]byte, uint32, byte, byte, []byte, int) ([]byte, error){NIA1Bits, NIA3Bits} {
		key := make([]byte, 16)
		a, err := f(key, 1, 1, 0, []byte{0xA0}, 3)
		if err != nil {
			t.Fatal(err)
		}
		b, err := f(key, 1, 1, 0, []byte{0xBF}, 3)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("trailing bits changed the MAC: %x vs %x", a, b)
		}
	}
}

// TestNIAWholeByteMatchesBits: the NAS whole-byte API equals the bit API.
func TestNIAWholeByteMatchesBits(t *testing.T) {
	key, _ := hex.DecodeString("2bd6459f82c5b300952c49104881ff48")
	msg := []byte{0x00, 0x7e, 0x00, 0x5d, 0x02, 0x00}
	for _, p := range []struct {
		w func([]byte, uint32, byte, byte, []byte) ([]byte, error)
		b func([]byte, uint32, byte, byte, []byte, int) ([]byte, error)
	}{{NIA1, NIA1Bits}, {NIA3, NIA3Bits}} {
		w, err1 := p.w(key, 7, 1, 1, msg)
		b, err2 := p.b(key, 7, 1, 1, msg, len(msg)*8)
		if err1 != nil || err2 != nil || !bytes.Equal(w, b) {
			t.Fatalf("whole-byte %x (%v) != bits %x (%v)", w, err1, b, err2)
		}
	}
}

// TestNIAInputErrors: wrong key length and bit lengths are rejected.
func TestNIAInputErrors(t *testing.T) {
	for _, f := range []func([]byte, uint32, byte, byte, []byte, int) ([]byte, error){NIA1Bits, NIA3Bits} {
		if _, err := f(make([]byte, 15), 0, 0, 0, []byte{0}, 8); err != ErrKeyLength {
			t.Fatalf("short key: err = %v, want ErrKeyLength", err)
		}
		if _, err := f(make([]byte, 16), 0, 0, 0, []byte{0}, 9); err == nil {
			t.Fatal("bitLen past message: want error")
		}
		if _, err := f(make([]byte, 16), 0, 0, 0, []byte{0}, -1); err == nil {
			t.Fatal("negative bitLen: want error")
		}
	}
}

// mul64Reference is the original branching MUL64 (SAGE UIA2 §4.3), kept as a
// test-only oracle for the constant-time mul64.
func mul64Reference(v, p uint64) uint64 {
	var r uint64
	for i := 0; i < 64; i++ {
		if p>>uint(i)&1 == 1 {
			r ^= v
		}
		if v&0x8000000000000000 != 0 {
			v = v<<1 ^ uia2PolyC
		} else {
			v <<= 1
		}
	}
	return r
}

func TestMul64MatchesReference(t *testing.T) {
	edge := []uint64{0, 1, 1 << 63, ^uint64(0), uia2PolyC}
	for _, v := range edge {
		for _, p := range edge {
			if got, want := mul64(v, p), mul64Reference(v, p); got != want {
				t.Fatalf("mul64(%#x,%#x)=%#x want %#x", v, p, got, want)
			}
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		v, p := rng.Uint64(), rng.Uint64()
		if got, want := mul64(v, p), mul64Reference(v, p); got != want {
			t.Fatalf("mul64(%#x,%#x)=%#x want %#x", v, p, got, want)
		}
	}
}
