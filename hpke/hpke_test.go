package hpke_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
)

func TestBase(t *testing.T) {
	v := a3v

	var m = hpke.Mode{v.mode, v.kemID, v.hkdfID, v.aeadID}
	dhkem, _ := m.GetKem()
	pkR, _ := dhkem.UnmarshalBinaryPublicKey(v.setup.pkRm)
	skR, _ := dhkem.UnmarshalBinaryPrivateKey(v.setup.skRm)
	enc, encCtx, err := m.SetupBaseS(pkR, v.setup.info)
	if err != nil {
		fmt.Println(err)
	}
	decCtx, err := m.SetupBaseR(skR, enc, v.setup.info)
	if err != nil {
		fmt.Println(err)
	}
	for _, encv := range v.enc[1:] {
		ct, err := encCtx.Seal(encv.Aad, encv.Pt)
		if err != nil {
			fmt.Println(err)
		}

		pt, err := decCtx.Open(encv.Aad, ct)
		if err != nil {
			fmt.Println(err)
		}
		if !bytes.Equal(pt, encv.Pt) {
			test.ReportError(t, toHex(pt), toHex(encv.Pt))
		}
	}
}

func toHex(b []byte) string { return hex.EncodeToString(b) }
func hexB(x string) []byte  { z, _ := hex.DecodeString(x); return z }

type setupInfo struct {
	info []byte

	ikmE []byte
	pkEm []byte
	skEm []byte

	ikmR []byte
	pkRm []byte
	skRm []byte

	enc       []byte
	ss        []byte
	ksc       []byte
	secret    []byte
	key       []byte
	baseNonce []byte
	exporter  []byte
}

type encryption struct {
	Seq   uint
	Pt    []byte `json:"pt"`
	Aad   []byte `json:"aad"`
	Nonce []byte `json:"nonce"`
	Ct    []byte `json:"ct"`
}

type vector struct {
	mode   hpke.ModeID
	kemID  hpke.DHkemID
	hkdfID hpke.HkdfID
	aeadID hpke.AeadID
	setup  setupInfo
	enc    []encryption
}

var a3v = vector{
	mode:   hpke.Base,
	kemID:  hpke.DHKemP256hkdfsha256,
	hkdfID: hpke.HkdfSHA256,
	aeadID: hpke.AeadAES128GCM,
	setup: setupInfo{
		info:      hexB("4f6465206f6e2061204772656369616e2055726e"),
		ikmE:      hexB("827f27da166dfeaa8929c92d2a67018a66d7b465a44c168220088d430461bb72"),
		pkEm:      hexB("04a01b79a7807750c860610342450d54b5d4d91b8c51b698b37b6fdee6b97fa73da344ce28dafd89dc1daa929d1aa76349f6f4bc2bb0782674121a620072eb3b15"),
		skEm:      hexB("a679400e350e9da1bd1c36de49fc481cc6150e172d5f7aa9e97740b09f16f557"),
		ikmR:      hexB("3c991968c9ce6f8e8f0fef41083ab91e9855b368b8714d78aacde3fc74b0fb5e"),
		pkRm:      hexB("04a33be520167c96134a03754478b115880f307fcfc7ae9873d6449963e2487b3a021be50200f71d4fe9c6dc4a2db04451fa8ff8b5840e1263697df8854b1187df"),
		skRm:      hexB("31de13900c6f7ca8844239628949b07969cec1968fdc3307e5868d1ae10d7e2d"),
		enc:       hexB("04a01b79a7807750c860610342450d54b5d4d91b8c51b698b37b6fdee6b97fa73da344ce28dafd89dc1daa929d1aa76349f6f4bc2bb0782674121a620072eb3b15"),
		ss:        hexB("98ce9c4505de60f00baa68df92dfbcc89ccd1cf2bbfcbabb368a68b9e43b99be"),
		ksc:       hexB("007a447b53a1bab6377f6d0fcd13c880e84b7b6f8c9d48909c2681378f2dae2f735fb35e69f4b2ad8cb96fdecc61f90a4e3168e52786bc426eada7863da4b00f23"),
		secret:    hexB("273a04827b269dd8f670ff33e60150bda39af36783b5e2c15e5973bbfc89e20d"),
		key:       hexB("0f1d817716a9fcfb3a733d7a9495b5ea"),
		baseNonce: hexB("1b961630d98ed4bfde61a590"),
		exporter:  hexB("cec277f90ab42ff8b7e35a10802b5155f112eaf5b97ce19f9986ffccf77aa59e"),
	},
	enc: []encryption{
		{
			Seq:   0,
			Pt:    hexB("4265617574792069732074727574682c20747275746820626561757479"),
			Aad:   hexB("436f756e742d30"),
			Nonce: hexB("1b961630d98ed4bfde61a590"),
			Ct:    hexB("6691e12b2ff62ee7afd44b1ffeb5cc90399f0509d153d8c1bd56dec39bc1df84617a6daf3c1a96dcfa5d6eab5d"),
		},
		{
			Seq:   1,
			Pt:    hexB("4265617574792069732074727574682c20747275746820626561757479"),
			Aad:   hexB("436f756e742d31"),
			Nonce: hexB("1b961630d98ed4bfde61a591"),
			Ct:    hexB("3bcc473facb1803c3b526b61e0cb5158ea0c9148df3a2b86b55e8e49464720491fd557093f8303d825ead9b864"),
		},
		{
			Seq:   2,
			Pt:    hexB("4265617574792069732074727574682c20747275746820626561757479"),
			Aad:   hexB("436f756e742d32"),
			Nonce: hexB("1b961630d98ed4bfde61a592"),
			Ct:    hexB("32a45576443463950cca04906d2ca90d7271b6cab593a3a76bc5f19447ee1890c1eb07c3b5419c6a2f3f480851"),
		},
		{
			Seq:   4,
			Pt:    hexB("4265617574792069732074727574682c20747275746820626561757479"),
			Aad:   hexB("436f756e742d34"),
			Nonce: hexB("1b961630d98ed4bfde61a594"),
			Ct:    hexB("03ac6b8b51f5a1897b59115d3b4854e1f044e25942c802531c1766db9552f6262986eb089bbc171405b4c4cf7b"),
		},
	},
}
