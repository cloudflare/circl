package bbs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testMessages() [][]byte {
	messages := []string{
		"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
		"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
		"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
		"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
		"496694774c5604ab1b2544eababcf0f53278ff50",
		"515ae153e22aae04ad16f759e07237b4",
		"d183ddc6e2665aa4e2f088af",
		"ac55fb33a75909ed",
		"96012096",
		"",
	}
	decodedMessages := make([][]byte, len(messages))
	for i := 0; i < len(messages); i++ {
		decodedMessages[i] = mustDecodeHex(messages[i])
	}
	return decodedMessages
}

func TestDifference(t *testing.T) {
	N := 10
	skipped := []int{0, 1, 5}
	expected := []int{2, 3, 4, 6, 7, 8, 9}
	diff := difference(skipped, N)
	if len(expected) != len(diff) {
		t.Fatal("mismatch difference")
	}
	for i := 0; i < len(diff); i++ {
		if expected[i] != diff[i] {
			t.Fatal("mismatch difference")
		}
	}
}

func mustDecodeHex(s string) []byte {
	x, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return x
}

func TestP1(t *testing.T) {
	p1 := computeP1()
	expectedEnc := mustDecodeHex("a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9")
	p1Enc := p1.BytesCompressed()
	if !bytes.Equal(p1Enc, expectedEnc) {
		t.Fatalf("Incorrect P1 computation, got %s, want %s", hex.EncodeToString(p1Enc), hex.EncodeToString(expectedEnc))
	}
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-key-pair-2
func TestKeyGen(t *testing.T) {
	ikm := mustDecodeHex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579")
	keyInfo := mustDecodeHex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e")
	expectedSkEnc := mustDecodeHex("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
	expectedPkEnc := mustDecodeHex("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")

	sk, err := keyGen(ikm, keyInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	skEnc, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skEnc, expectedSkEnc) {
		t.Fatalf("derived secret key mismatch, got %s, wanted %s", hex.EncodeToString(skEnc), hex.EncodeToString(expectedSkEnc))
	}

	pkEnc := publicKey(sk)
	if !bytes.Equal(pkEnc, expectedPkEnc) {
		t.Fatalf("derived public key mismatch, got %s, wanted %s", hex.EncodeToString(pkEnc), hex.EncodeToString(expectedPkEnc))
	}
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-map-messages-to-scalars-2
func TestMessageMap(t *testing.T) {
	mappings := []string{
		"1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430",
		"154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952",
		"0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22",
		"4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888",
		"34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e",
		"4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08",
		"064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743",
		"34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02",
		"57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74",
		"08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16",
	}
	decodedMappings := make([][]byte, len(mappings))
	for i := 0; i < len(mappings); i++ {
		decodedMappings[i] = mustDecodeHex(mappings[i])
	}

	messages := testMessages()
	scalars := messagesToScalars(messages)
	for i := 0; i < len(scalars); i++ {
		scalarEnc, err := scalars[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(scalarEnc, decodedMappings[i]) {
			t.Fatalf("incorrect message-to-scalar mapping for index %d, got %s, wanted %s", i, hex.EncodeToString(scalarEnc), hex.EncodeToString(decodedMappings[i]))
		}
	}
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-message-generators
func TestMessageGenerators(t *testing.T) {
	testGenerators := []string{
		"a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be",
		"98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4",
		"a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a",
		"b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62",
		"ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035",
		"b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335",
		"8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39",
		"abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1",
		"80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17",
		"82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f",
		"a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca",
	}
	decodedGenerators := make([][]byte, len(testGenerators))
	for i := 0; i < len(testGenerators); i++ {
		decodedGenerators[i] = mustDecodeHex(testGenerators[i])
	}

	generators := createGenerators(len(testGenerators), nil)
	generatorEnc := generators[0].BytesCompressed()
	if !bytes.Equal(generatorEnc, decodedGenerators[0]) {
		t.Fatalf("incorrect Q1 generator, got %s, wanted %s", hex.EncodeToString(generatorEnc), hex.EncodeToString(decodedGenerators[0]))
	}
	for i := 1; i < len(generators); i++ {
		generatorEnc := generators[i].BytesCompressed()
		if !bytes.Equal(generatorEnc, decodedGenerators[i]) {
			t.Fatalf("incorrect generator for index %d, got %s, wanted %s", i, hex.EncodeToString(generatorEnc), hex.EncodeToString(decodedGenerators[i]))
		}
	}
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-03#name-valid-single-message-signatu
func TestSingleMessageSignature(t *testing.T) {
	header := mustDecodeHex("11223344556677889900aabbccddeeff")
	message := mustDecodeHex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
	messages := [][]byte{message}
	expectedSigEnc := mustDecodeHex("88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103")

	ikm := mustDecodeHex("746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579")
	keyInfo := mustDecodeHex("746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e")

	sk, err := keyGen(ikm, keyInfo, nil)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := rawSign(sk, publicKey(sk), header, messages)
	if err != nil {
		t.Fatal(err)
	}

	// sigEEnc, err := sig.e.MarshalBinary()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Println(hex.EncodeToString(sigEEnc))

	sigEnc := sig.Encode()
	if !bytes.Equal(sigEnc, expectedSigEnc) {
		t.Fatalf("incorrect signature, got %s, wanted %s", hex.EncodeToString(sigEnc), hex.EncodeToString(expectedSigEnc))
	}
}

func TestRoundTrip(t *testing.T) {
	ikm := make([]byte, 32)
	keyInfo := []byte{}
	keyDst := []byte{}

	sk, err := keyGen(ikm, keyInfo, keyDst)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte("test header")
	ph := []byte("presentation header")

	messages := make([][]byte, 5)
	messages[0] = []byte("hello")
	messages[1] = []byte("world")
	messages[1] = []byte("foo")
	messages[1] = []byte("bar")
	messages[1] = []byte("baz")

	sig, err := rawSign(sk, publicKey(sk), header, messages)
	if err != nil {
		t.Fatal(err)
	}

	err = rawVerify(publicKey(sk), sig, header, messages)
	if err != nil {
		t.Fatal(err)
	}

	disclosedIndexes := []int{0, 1}
	disclosedMessages := make([][]byte, len(disclosedIndexes))
	for i := 0; i < len(disclosedIndexes); i++ {
		disclosedMessages[i] = messages[disclosedIndexes[i]]
	}
	proof, err := rawProofGen(publicKey(sk), sig, header, ph, messages, disclosedIndexes)
	if err != nil {
		t.Fatal(err)
	}

	err = rawProofVerify(publicKey(sk), proof, header, ph, disclosedMessages, disclosedIndexes)
	if err != nil {
		t.Fatal(err)
	}
}
