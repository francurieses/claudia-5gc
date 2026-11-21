package nea

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

// cipherVector is one conformance test set (hex strings; bit length may be
// non-multiple of 8).
type cipherVector struct {
	name   string
	count  uint32
	bearer byte
	dir    byte
	key    string
	bits   int
	plain  string
	cipher string
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// maskTail zeroes the unused trailing bits of the last byte of b[:ceil(bits/8)].
func maskTail(b []byte, bits int) []byte {
	n := (bits + 7) / 8
	out := append([]byte(nil), b[:n]...)
	if r := bits % 8; r != 0 {
		out[n-1] &= 0xFF << (8 - uint(r))
	}
	return out
}

type bitsFunc func(key []byte, count uint32, bearer, dir byte, msg []byte, bitLen int) ([]byte, error)
type byteFunc func(key []byte, count uint32, bearer, dir byte, msg []byte) ([]byte, error)

func runVectors(t *testing.T, vecs []cipherVector, bitsFn bitsFunc, byteFn byteFunc) {
	t.Helper()
	for _, v := range vecs {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.key)
			plain := mustHex(t, v.plain)
			want := maskTail(mustHex(t, v.cipher), v.bits)

			got, err := bitsFn(key, v.count, v.bearer, v.dir, plain, v.bits)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("encrypt mismatch\n got %x\nwant %x", got, want)
			}
			// Decrypt (symmetric) recovers the plaintext.
			back, err := bitsFn(key, v.count, v.bearer, v.dir, got, v.bits)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(back, maskTail(plain, v.bits)) {
				t.Errorf("round trip mismatch\n got %x\nwant %x", back, maskTail(plain, v.bits))
			}
			if v.bits%8 == 0 {
				got2, err := byteFn(key, v.count, v.bearer, v.dir, plain[:v.bits/8])
				if err != nil {
					t.Fatalf("byte API: %v", err)
				}
				if !bytes.Equal(got2, want) {
					t.Errorf("byte API mismatch\n got %x\nwant %x", got2, want)
				}
			}
		})
	}
}

func runCommon(t *testing.T, bitsFn bitsFunc, byteFn byteFunc) {
	t.Helper()
	t.Run("wrong key length", func(t *testing.T) {
		for _, n := range []int{0, 15, 17, 32} {
			if _, err := byteFn(make([]byte, n), 0, 0, 0, []byte{1}); err == nil {
				t.Errorf("key len %d: expected error", n)
			}
		}
	})
	t.Run("empty message", func(t *testing.T) {
		out, err := byteFn(make([]byte, 16), 1, 1, 1, nil)
		if err != nil || len(out) != 0 {
			t.Errorf("got %x, %v; want empty, nil", out, err)
		}
	})
	t.Run("short message for bit length", func(t *testing.T) {
		if _, err := bitsFn(make([]byte, 16), 0, 0, 0, []byte{1}, 16); err == nil {
			t.Error("expected error")
		}
		if _, err := bitsFn(make([]byte, 16), 0, 0, 0, []byte{1}, -1); err == nil {
			t.Error("expected error for negative bit length")
		}
	})
	t.Run("input not modified, new slice", func(t *testing.T) {
		in := []byte{1, 2, 3, 4, 5}
		cp := append([]byte(nil), in...)
		out, err := byteFn(make([]byte, 16), 7, 0, 1, in)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(in, cp) {
			t.Error("input modified")
		}
		if len(out) > 0 && &out[0] == &in[0] {
			t.Error("output aliases input")
		}
	})
}

// NEA1 vectors: TS 35.217 (UEA2/UIA2 test data) UEA2 test sets 1-6, as
// reproduced in free5GC nas internal/algo/nea_test.go.
var nea1Vectors = []cipherVector{
	{"TS 35.217 UEA2 test set 1", 0x72a4f20f, 0x0c, 1, "2bd6459f82c5b300952c49104881ff48", 798,
		"7ec61272743bf1614726446a6c38ced166f6ca76eb5430044286346cef130f92922b03450d3a9975e5bd2ea0eb55ad8e1b199e3ec4316020e9a1b285e762795359b7bdfd39bef4b2484583d5afe082aee638bf5fd5a606193901a08f4ab41aab9b134880",
		"8ceba62943dced3a0990b06ea1b0a2c4fb3cedc71b369f42ba64c1eb6665e72aa1c9bb0deaa20fe86058b8baee2c2e7f0becce48b52932a53c9d5f931a3a7c532259af4325e2a65e3084ad5f6a513b7bddc1b65f0aa0d97a053db55a88c4c4f9605e4140"},
	{"TS 35.217 UEA2 test set 2", 0xe28bcf7b, 0x18, 0, "efa8b2229e720c2a7c36ea55e9605695", 510,
		"10111231e060253a43fd3f57e37607ab2827b599b6b1bbda37a8abcc5a8c550d1bfb2f494624fb50367fa36ce3bc68f11cf93b1510376b02130f812a9fa169d8",
		"e0da15ca8e2554f5e56c9468dc6c7c129c568aa5032317e04e0729646cabefa689864c410f24f919e61e3dfdfad77e560db0a9cd36c34ae4181490b29f5fa2fc"},
	{"TS 35.217 UEA2 test set 3", 0xfa556b26, 0x03, 1, "5acb1d644c0d51204ea5f1451010d852", 120,
		"ad9c441f890b38c457a49d421407e800",
		"ba0f31300334c56b52a7497cbac04600"},
	{"TS 35.217 UEA2 test set 4", 0x398a59b4, 0x05, 1, "d3c5d592327fb11c4035c6680af8c6d1", 253,
		"981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0",
		"989b719cdc33ceb7cf276a52827cef94a56c40c0ab9d81f7a2a9bac60e11c4b0"},
	{"TS 35.217 UEA2 test set 5", 0x72a4f20f, 0x09, 0, "6090eae04c83706eecbf652be8e36566", 837,
		"40981ba6824c1bfb4286b299783daf442c099f7ab0f58d5c8e46b104f08f01b41ab485472029b71d36bd1a3d90dc3a41b46d51672ac4c9663a2be063da4bc8d2808ce33e2cccbfc634e1b259060876a0fbb5a437ebcc8d31c19e4454318745e3987645987a986f2cb0",
		"5892bba88bbbcaaeae769aa06b683d3a17cc04a369881697435e44fed5ff9af57b9e890d4d5c64709885d48ae40690ec043baae9705796e4a9ff5a4b8d8b36d7f3fe57cc6cfd6cd005cd3852a85e94ce6bcd90d0d07839ce09733544ca8e350843248550922ac12818"},
	{"NAS sample (free5GC nea_test.go NEA1TestCase6, not a TS vector)", 0x02, 0x01, 0, "aa3fc78b4c1bb61af0a37fa5f623abfc", 224,
		"be406194d30bd75e90eae3d75771ae7b3a026229e70dd43051e3a71c",
		"7e00670100082e0501c1ffff91a1120581250908696e7465726e6574"},
}

// NEA3 vectors: TS 35.223 (128-EEA3/EIA3 test data) EEA3 test sets 1-5 (and
// further sets present in the free5GC reference test).
var nea3Vectors = []cipherVector{
	{"TS 35.223 EEA3 test set 1", 0x66035492, 0x0f, 0, "173d14ba5003731d7a60049470f00a29", 193,
		"6cf65340735552ab0c9752fa6f9025fe0bd675d9005875b200000000",
		"a6c85fc66afb8533aafc2518dfe784940ee1e4b030238cc800000000"},
	{"TS 35.223 EEA3 test set 2", 0x56823, 0x18, 1, "e5bd3ea0eb55ade866c6ac58bd54302a", 800,
		"14a8ef693d678507bbe7270a7f67ff5006c3525b9807e467c4e56000ba338f5d429559036751822246c80d3b38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d",
		"131d43e0dea1be5c5a1bfd971d852cbf712d7b4f57961fea3208afa8bca433f456ad09c7417e58bc69cf8866d1353f74865e80781d202dfb3ecff7fcbc3b190fe82a204ed0e350fc0f6f2613b2f2bca6df5a473a57a4a00d985ebad880d6f23864a07b01"},
	{"TS 35.223 EEA3 test set 3", 0x76452ec1, 0x2, 1, "d4552a8fd6e61cc81a2009141a29c10b", 1570,
		"38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d3ca4ec41e074595f54ae2b454fd971432043601965cca85c2417ed6cbec3bada84fc8a579aea7837b0271177242a64dc0a9de71a8edee86ca3d47d033d6bf539804eca86c584a9052de46ad3fced65543bd90207372b27afb79234f5ff43ea870820e2c2b78a8aae61cce52a0515e348d196664a3456b182a07c406e4a20791271cfeda165d535ec5ea2d4df40000000",
		"8383b0229fcc0b9d2295ec41c977e9c2bb72e220378141f9c8318f3a270dfbcdee6411c2b3044f176dc6e00f8960f97afacd131ad6a3b49b16b7babcf2a509ebb16a75dcab14ff275dbeeea1a2b155f9d52c26452d0187c310a4ee55beaa78ab4024615ba9f5d5adc7728f73560671f013e5e550085d3291df7d5fecedded559641b6c2f585233bc71e9602bd2305855bbd25ffa7f17ecbc042daae38c1f57ad8e8ebd37346f71befdbb7432e0e0bb2cfc09bcd96570cb0c0c39df5e29294e82703a637f80000000"},
	{"TS 35.223 EEA3 test set 4", 0xe4850fe1, 0x10, 1, "db84b4fbccda563b66227bfe456f0f77", 2798,
		"e539f3b8973240da03f2b8aa05ee0a00dbafc0e182055dfe3d7383d92cef40e92928605d52d05f4f9018a1f189ae3997ce19155fb1221db8bb0951a853ad852ce16cff07382c93a157de00ddb125c7539fd85045e4ee07e0c43f9e9d6f414fc4d1c62917813f74c00fc83f3e2ed7c45ba5835264b43e0b20afda6b3053bfb6423b7fce25479ff5f139dd9b5b995558e2a56be18dd581cd017c735e6f0d0d97c4ddc1d1da70c6db4a12cc92778e2fbbd6f3ba52af91c9c6b64e8da4f7a2c266d02d001753df08960393c5d56888bf49eb5c16d9a80427a416bcb597df5bfe6f13890a07ee1340e6476b0d9aa8f822ab0fd1ab0d204f40b7ce6f2e136eb67485e507804d504588ad37ffd816568b2dc40311dfb654cdead47e2385c3436203dd836f9c64d97462ad5dfa63b5cfe08acb9532866f5ca787566fca93e6b1693ee15cf6f7a2d689d9741798dc1c238e1be650733b18fb34ff880e16bbd21b47ac0000",
		"4bbfa91ba25d47db9a9f190d962a19ab323926b351fbd39e351e05da8b8925e30b1cce0d1221101095815cc7cb6319509ec0d67940491987e13f0affac332aa6aa64626d3e9a1917519e0b97b655c6a165e44ca9feac0790d2a321ad3d86b79c5138739fa38d887ec7def449ce8abdd3e7f8dc4ca9e7b73314ad310f9025e61946b3a56dc649ec0da0d63943dff592cf962a7efb2c8524e35a2a6e7879d62604ef268695fa4003027e22e6083077522064bd4a5b906b5f531274f235ed506cff0154c754928a0ce5476f2cb1020a1222d32c1455ecaef1e368fb344d1735bfbedeb71d0a33a2a54b1da5a294e679144ddf11eb1a3de8cf0cc061917974f35c1d9ca0ac81807f8fcce6199a6c7712da865021b04ce0439516f1a526ccda9fd9abbd53c3a684f9ae1e7ee6b11da138ea826c5516b5aadf1abbe36fa7fff92e3a1176064e8d95f2e4882b5500b93228b2194a475c1a27f63f9ffd264989a1bc0000"},
	{"TS 35.223 EEA3 test set 5", 0x2738cdaa, 0x1a, 0, "e13fed21b46e4e7ec31253b2bb17b3e0", 4019,
		"8d74e20d54894e06d3cb13cb3933065e8674be62adb1c72b3a646965ab63cb7b7854dfdc27e84929f49c64b872a490b13f957b64827e71f41fbd4269a42c97f824537027f86e9f4ad82d1df451690fdd98b6d03f3a0ebe3a312d6b840ba5a1820b2a2c9709c090d245ed267cf845ae41fa975d3333ac3009fd40eba9eb5b885714b768b697138baf21380eca49f644d48689e4215760b906739f0d2b3f091133ca15d981cbe401baf72d05ace05cccb2d297f4ef6a5f58d91246cfa77215b892ab441d5278452795ccb7f5d79057a1c4f77f80d46db2033cb79bedf8e60551ce10c667f62a97abafabbcd6772018df96a282ea737ce2cb331211f60d5354ce78f9918d9c206ca042c9b62387dd709604a50af16d8d35a8906be484cf2e74a9289940364353249b27b4c9ae29eddfc7da6418791a4e7baa0660fa64511f2d685cc3a5ff70e0d2b74292e3b8a0cd6b04b1c790b8ead2703708540dea2fc09c3da770f65449e84d817a4f551055e19ab85018a0028b71a144d96791e9a3577933504eee0060340c69d274e1bf9d805dcbcc1a6faa976800b6ff2b671dc463652fa8a33ee50974c1c21be01eabb2167430269d72ee511c9dde30797c9a25d86ce74f5b961be5fdfb6807814039e7137636bd1d7fa9e09efd2007505906a5ac45dfdeed7757bbee745749c29633350bee0ea6f409df4580160000",
		"94eaa4aa30a57137ddf09b97b25618a20a13e2f10fa5bf8161a879cc2ae797a6b4cf2d9df31debb9905ccfec97de605d21c61ab8531b7f3c9da5f03931f8a0642de48211f5f52ffea10f392a047669985da454a28f080961a6c2b62daa17f33cd60a4971f48d2d909394a55f48117ace43d708e6b77d3dc46d8bc017d4d1abb77b7428c042b06f2f99d8d07c9879d99600127a31985f1099bbd7d6c1519ede8f5eeb4a610b349ac01ea2350691756bd105c974a53eddb35d1d4100b012e522ab41f4c5f2fde76b59cb8b96d885cfe4080d1328a0d636cc0edc05800b76acca8fef672084d1f52a8bbd8e0993320992c7ffbae17c408441e0ee883fc8a8b05e22f5ff7f8d1b48c74c468c467a028f09fd7ce91109a570a2d5c4d5f4fa18c5dd3e4562afe24ef771901f59af645898acef088abae07e92d52eb2de55045bb1b7c4164ef2d7a6cac15eeb926d7ea2f08b66e1f759f3aee44614725aa3c7482b30844c143ff85b53f1e583c501257dddd096b81268daa303f17234c2333541f0bb8e190648c5807c866d7193228609adb948686f7de294a802cc38f7fe5208f5ea3196d0167b9bdd02f0d2a5221ca508f893af5c4b4bb9f4f520fd84289b3dbe7e61497a7e2a584037ea637b6981127174af57b471df4b2768fd79c1540fb3edf2ea22cb69bec0cf8d933d9c6fdd645e850591cca3d62c0cc000"},
}

func TestNEA1(t *testing.T) {
	runVectors(t, nea1Vectors, NEA1Bits, NEA1)
	runCommon(t, NEA1Bits, NEA1)
}

func TestNEA3(t *testing.T) {
	runVectors(t, nea3Vectors, NEA3Bits, NEA3)
	runCommon(t, NEA3Bits, NEA3)
}

// TestNEA1NEA3BitLenGuard: an oversized, overflowing or negative bit length is
// an error, never a panic.
func TestNEA1NEA3BitLenGuard(t *testing.T) {
	key := make([]byte, 16)
	msg := make([]byte, 4)
	for _, bl := range []int{-1, 33, 1 << 20, math.MaxInt, math.MaxInt - 3, math.MinInt} {
		if _, err := NEA1Bits(key, 0, 1, 0, msg, bl); err == nil {
			t.Errorf("NEA1Bits bitLen=%d: want error", bl)
		}
		if _, err := NEA3Bits(key, 0, 1, 0, msg, bl); err == nil {
			t.Errorf("NEA3Bits bitLen=%d: want error", bl)
		}
	}
}
