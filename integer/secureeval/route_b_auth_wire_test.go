package secureeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRBAUTHGoldenBuildSpecCompileRed(t *testing.T) {
	spec := goldenArtifactBuildSpec(t)

	want := independentMarshalBuildSpec(t, spec)
	got, err := spec.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical build spec mismatch\n got=%x\nwant=%x", got, want)
	}

	identity, err := RBAUTHRecordIdentity(got)
	if err != nil {
		t.Fatal(err)
	}
	if identity != RBAUTHDigest(sha256.Sum256(want[:len(want)-sha256.Size])) {
		t.Fatalf("identity is not the trailing canonical seal: %x", identity)
	}

	parsed, err := ParseArtifactBuildSpec(got)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, want) {
		t.Fatal("parsed build spec did not round-trip canonically")
	}
}

func TestRBAUTHGoldenAllRecordTypes(t *testing.T) {
	spec, permit, ready, readyPermit, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	tests := []struct {
		name        string
		production  func() ([]byte, error)
		independent func() []byte
		parse       func([]byte) ([]byte, error)
		wantHex     string
		wantSHA256  string
	}{
		{
			name: "artifact build spec", production: spec.MarshalBinary,
			independent: func() []byte { return independentMarshalBuildSpec(t, spec) },
			parse: func(encoded []byte) ([]byte, error) {
				value, err := ParseArtifactBuildSpec(encoded)
				if err != nil {
					return nil, err
				}
				return value.MarshalBinary()
			},
			wantHex:    "4c43504454452d5242415554482d7631011d0000006c61747469676f5f7061636b696e675f61646170746174696f6e5f723129000000726f7574655f625f61727469666163745f6275696c645f617574686f72697a6174696f6e5f6f6e6c792d000000726f7574655f625f636f6e737472756374696f6e5f636f6e74726163745f6f6e6c795f756e766572696669656400001c0000006c31312d61756469742d666978747572652d323032362d30382d3330f0a7c6d307000000190456fe030000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111110001000000010000310000006c61747469676f2d726f7574652d622d7072656275696c742d6466742d73747265616d696e672d6275696c6465722d7631240000007368613235362d63616e6f6e6963616c2d73747265616d696e672d62696e6172792d76311d0000007374632d7468656e2d6374732d73696e676c652d666163746f722d7631190000006c6f676963616c2d7265666572656e63652d64726f702d76311d000000707269766174652d6578636c75736976652d7472616e736665722d76310102000000020000003f000000400000000300000003000000100000001f0000000f000000000000000000000000000000000000000000000000000000020000000000000000012000000000000880000000000000000018000000000000000002000000000000f80000000000088138040000000008812802000000000000d80400000000f87e9f00000000004dc71b9f10f0932ff1762302f2d46e3a1a0c8fddc04c06c2b0d1164c6addaa20000fe9b000000000000ff9a8010000004c5d78d30100000003521c9a000000000000709d00000000fdad5303000000005a28b02b82aa7bd8a3cbcc5187e9f2fdb568c8cd082d3fea44b7b5b756ab30d821c21d849ce6743d9be784ea879c1f0b12f81e8413816fb254c7c02d3deb2c8f",
			wantSHA256: "09270619b021a78b71852976854117a154accf4c683b80fa784d3d89289d5128",
		},
		{
			name: "artifact build permit", production: permit.MarshalBinary,
			independent: func() []byte { return independentMarshalBuildPermit(t, permit) },
			parse: func(encoded []byte) ([]byte, error) {
				value, err := ParseArtifactBuildPermit(encoded)
				if err != nil {
					return nil, err
				}
				return value.MarshalBinary()
			},
			wantHex:    "4c43504454452d5242415554482d76310221c21d849ce6743d9be784ea879c1f0b12f81e8413816fb254c7c02d3deb2c8f1d0000006c61747469676f5f7061636b696e675f61646170746174696f6e5f723129000000726f7574655f625f61727469666163745f6275696c645f617574686f72697a6174696f6e5f6f6e6c792d000000726f7574655f625f636f6e737472756374696f6e5f636f6e74726163745f6f6e6c795f756e766572696669656400001c0000006c31312d61756469742d666978747572652d323032362d30382d3330f0a7c6d307000000190456fe030000000101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111110001000000010000310000006c61747469676f2d726f7574652d622d7072656275696c742d6466742d73747265616d696e672d6275696c6465722d7631240000007368613235362d63616e6f6e6963616c2d73747265616d696e672d62696e6172792d76311d0000007374632d7468656e2d6374732d73696e676c652d666163746f722d7631190000006c6f676963616c2d7265666572656e63652d64726f702d76311d000000707269766174652d6578636c75736976652d7472616e736665722d76310102000000020000003f000000400000000300000003000000100000001f0000000f000000000000000000000000000000000000000000000000000000020000000000000000012000000000000880000000000000000018000000000000000002000000000000f80000000000088138040000000008812802000000000000d80400000000f87e9f00000000004dc71b9f10f0932ff1762302f2d46e3a1a0c8fddc04c06c2b0d1164c6addaa20000fe9b000000000000ff9a8010000004c5d78d30100000003521c9a000000000000709d00000000fdad5303000000005a28b02b82aa7bd8a3cbcc5187e9f2fdb568c8cd082d3fea44b7b5b756ab30d806297aa3056b9829f5bb9f6f678f9bc99613ff4027d2f072cb42f224e2f6e22f",
			wantSHA256: "3ca7e237c2ba90793b7008abe71f886c6f3d0d89bde6a7f148faf5ed60709822",
		},
		{
			name: "ready spec", production: ready.MarshalBinary,
			independent: func() []byte { return independentMarshalReadySpec(t, ready) },
			parse: func(encoded []byte) ([]byte, error) {
				value, err := ParseReadySpec(encoded)
				if err != nil {
					return nil, err
				}
				return value.MarshalBinary()
			},
			wantHex:    "4c43504454452d5242415554482d7631031d0000006c61747469676f5f7061636b696e675f61646170746174696f6e5f723129000000726f7574655f625f61727469666163745f72656164795f617574686f72697a6174696f6e5f6f6e6c792d000000726f7574655f625f636f6e737472756374696f6e5f636f6e74726163745f6f6e6c795f756e766572696669656400001c0000006c31312d61756469742d666978747572652d323032362d30382d3330f0a7c6d307000000190456fe0300000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060607070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808090909090909090909090909090909090909090909090909090909090909090921c21d849ce6743d9be784ea879c1f0b12f81e8413816fb254c7c02d3deb2c8f06297aa3056b9829f5bb9f6f678f9bc99613ff4027d2f072cb42f224e2f6e22faae3c2b57e19b3ebd04194e438ae1c826bd82b55e5e9f895419771e27948913af33c626d313523fbd61e0b8553502320dbe0815c36a79a579a31f8fb46c282fe1414141414141414141414141414141414141414141414141414141414141414650000000000000015151515151515151515151515151515151515151515151515151515151515156600000000000000161616161616161616161616161616161616161616161616161616161616161667000000000000001717171717171717171717171717171717171717171717171717171717171717680000000000000013000000707269766174652d756e696e7374616c6c65644ced68b9364f2409d8448bd6fc4181030952a4c1a79510ee26558270fcd72abe",
			wantSHA256: "d4cb7b46930b4917cd5663d6cfd6b59990e2df6d7f853be345ea849cc60ddd46",
		},
		{
			name: "ready permit", production: readyPermit.MarshalBinary,
			independent: func() []byte { return independentMarshalReadyPermit(t, readyPermit) },
			parse: func(encoded []byte) ([]byte, error) {
				value, err := ParseReadyPermit(encoded)
				if err != nil {
					return nil, err
				}
				return value.MarshalBinary()
			},
			wantHex:    "4c43504454452d5242415554482d7631044ced68b9364f2409d8448bd6fc4181030952a4c1a79510ee26558270fcd72abe1d0000006c61747469676f5f7061636b696e675f61646170746174696f6e5f723129000000726f7574655f625f61727469666163745f72656164795f617574686f72697a6174696f6e5f6f6e6c792d000000726f7574655f625f636f6e737472756374696f6e5f636f6e74726163745f6f6e6c795f756e766572696669656400001c0000006c31312d61756469742d666978747572652d323032362d30382d3330f0a7c6d307000000190456fe0300000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060607070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808090909090909090909090909090909090909090909090909090909090909090921c21d849ce6743d9be784ea879c1f0b12f81e8413816fb254c7c02d3deb2c8f06297aa3056b9829f5bb9f6f678f9bc99613ff4027d2f072cb42f224e2f6e22faae3c2b57e19b3ebd04194e438ae1c826bd82b55e5e9f895419771e27948913af33c626d313523fbd61e0b8553502320dbe0815c36a79a579a31f8fb46c282fe1414141414141414141414141414141414141414141414141414141414141414650000000000000015151515151515151515151515151515151515151515151515151515151515156600000000000000161616161616161616161616161616161616161616161616161616161616161667000000000000001717171717171717171717171717171717171717171717171717171717171717680000000000000013000000707269766174652d756e696e7374616c6c6564b64fcec006f15412872dc58abadb03fd65ba912630c68a5215ca7c4f673edddd",
			wantSHA256: "408785db84149779bf472ae0a2e7d4164b7196b4ac9e5b05f3e0bdd34c6a3857",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := test.independent()
			if test.wantHex != stringHex(want) {
				t.Fatalf("freeze %s record hex as %s", test.name, stringHex(want))
			}
			got, err := test.production()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("production and independent records differ\n got=%x\nwant=%x", got, want)
			}
			roundTrip, err := test.parse(got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(roundTrip, want) {
				t.Fatal("canonical parse round-trip changed bytes")
			}
			fullHash := sha256.Sum256(want)
			if test.wantSHA256 != stringHex(fullHash[:]) {
				t.Fatalf("freeze %s full-record SHA256 as %s", test.name, stringHex(fullHash[:]))
			}
			identity, err := RBAUTHRecordIdentity(got)
			if err != nil {
				t.Fatal(err)
			}
			var trailing RBAUTHDigest
			copy(trailing[:], got[len(got)-sha256.Size:])
			if identity != trailing {
				t.Fatal("record identity is not trailing seal")
			}
		})
	}

	if err := permit.ValidateEmbeddedIdentity(); err != nil {
		t.Fatal(err)
	}
	if err := readyPermit.ValidateEmbeddedIdentity(); err != nil {
		t.Fatal(err)
	}
	buildSpecRecord, _ := spec.MarshalBinary()
	buildPermitRecord, _ := permit.MarshalBinary()
	if err := ready.ValidateLinks(buildSpecRecord, buildPermitRecord, receiptRecord, pairRecord); err != nil {
		t.Fatal(err)
	}
}

func TestRBAUTHGoldenReadyUsesFullyValidatedCanonicalRBDFTRecords(t *testing.T) {
	if independentRBDFTWireFixtureLabel != "wire_fixture_only" ||
		independentRBDFTWireFixtureScope != "canonical_wire_grammar_and_cross_record_identity_only" {
		t.Fatalf(
			"RBDFT golden fixture scope changed: label=%q scope=%q",
			independentRBDFTWireFixtureLabel,
			independentRBDFTWireFixtureScope,
		)
	}
	spec, permit, ready, _, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	permitRecord := independentMarshalBuildPermit(t, permit)
	permitIdentity := independentRecordIdentity(t, permitRecord)

	if err := independentValidateRBDFTReadyLinks(
		receiptRecord,
		pairRecord,
		permitIdentity,
		spec.PreparedParameterDigest,
		ready.ActualPayload,
	); err != nil {
		t.Fatalf("golden Ready does not use fully validated canonical RBDFT records: %v", err)
	}
	if err := independentAuthorizeRBDFTReady(
		ready,
		receiptRecord,
		pairRecord,
		permitIdentity,
		spec.PreparedParameterDigest,
	); err != nil {
		t.Fatalf("golden Ready failed the independent full RBDFT authorizer: %v", err)
	}
}

func TestRBAUTHCanonicalRBDFTLinkedRecordsFrozen(t *testing.T) {
	_, _, _, _, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	tests := []struct {
		name       string
		record     []byte
		wantBytes  int
		wantHex    string
		wantSHA256 string
	}{
		{
			name: "type05 pair", record: pairRecord, wantBytes: 210,
			wantHex:    "4c43504454452d52424446542d763100050006297aa3056b9829f5bb9f6f678f9bc99613ff4027d2f072cb42f224e2f6e22f14141414141414141414141414141414141414141414141414141414141414146500000000000000151515151515151515151515151515151515151515151515151515151515151566000000000000001616161616161616161616161616161616161616161616161616161616161616670000000000000017171717171717171717171717171717171717171717171717171717171717176800000000000000",
			wantSHA256: "f33c626d313523fbd61e0b8553502320dbe0815c36a79a579a31f8fb46c282fe",
		},
		{
			name: "type07 receipt", record: receiptRecord, wantBytes: 585,
			wantHex:    "4c43504454452d52424446542d763100070006297aa3056b9829f5bb9f6f678f9bc99613ff4027d2f072cb42f224e2f6e22f0909090909090909090909090909090909090909090909090909090909090909310000006c61747469676f2d726f7574652d622d7072656275696c742d6466742d73747265616d696e672d6275696c6465722d7631240000007368613235362d63616e6f6e6963616c2d73747265616d696e672d62696e6172792d76311d0000007374632d7468656e2d6374732d73696e676c652d666163746f722d7631190000006c6f676963616c2d7265666572656e63652d64726f702d76311d000000707269766174652d6578636c75736976652d7472616e736665722d76310001000000010000000000000000000000000000000000000000000000000000020000000000000018181818181818181818181818181818181818181818181818181818181818180100000002000000030000001414141414141414141414141414141414141414141414141414141414141414151515151515151515151515151515151515151515151515151515151515151516161616161616161616161616161616161616161616161616161616161616161717171717171717171717171717171717171717171717171717171717171717650000000000000066000000000000006700000000000000680000000000000015cd5b0700000000000fe9b00000000013000000707269766174652d756e696e7374616c6c6564f33c626d313523fbd61e0b8553502320dbe0815c36a79a579a31f8fb46c282fe",
			wantSHA256: "aae3c2b57e19b3ebd04194e438ae1c826bd82b55e5e9f895419771e27948913a",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if len(test.record) != test.wantBytes {
				t.Fatalf("canonical RBDFT record bytes=%d, want %d", len(test.record), test.wantBytes)
			}
			if got := stringHex(test.record); got != test.wantHex {
				t.Fatalf("freeze canonical RBDFT record hex as %s", got)
			}
			fullHash := sha256.Sum256(test.record)
			if got := stringHex(fullHash[:]); got != test.wantSHA256 {
				t.Fatalf("freeze canonical RBDFT full-record SHA256 as %s", got)
			}
		})
	}
}

func TestRBAUTHFullRBDFTAuthorizerRejectsHeaderCorrectMalformedBodies(t *testing.T) {
	spec, permit, ready, _, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	specRecord := independentMarshalBuildSpec(t, spec)
	permitRecord := independentMarshalBuildPermit(t, permit)
	permitIdentity := independentRecordIdentity(t, permitRecord)

	t.Run("truncated pair body", func(t *testing.T) {
		truncated := append([]byte(nil), pairRecord[:len(pairRecord)-1]...)
		if _, err := independentParseRBDFTPair(truncated); err == nil {
			t.Fatal("full RBDFT parser accepted a header-correct truncated pair body")
		}
		linked := ready
		linked.ArtifactPairManifestDigest = RBAUTHDigest(sha256.Sum256(truncated))
		// ReadySpec.ValidateLinks deliberately authenticates only RBDFT header,
		// type, role, and whole-record identity. Full RBDFT grammar belongs to
		// the later artifact authorizer represented independently below.
		if err := linked.ValidateLinks(specRecord, permitRecord, receiptRecord, truncated); err != nil {
			t.Fatalf("scoped ReadySpec link check unexpectedly performed full RBDFT validation: %v", err)
		}
		if err := independentAuthorizeRBDFTReady(
			linked, receiptRecord, truncated, permitIdentity, spec.PreparedParameterDigest,
		); err == nil {
			t.Fatal("full independent authorizer accepted a truncated pair body")
		}
	})

	t.Run("receipt identifier fields out of order", func(t *testing.T) {
		reordered := independentSwapFirstTwoRBDFTReceiptStrings(t, receiptRecord)
		if _, err := independentParseRBDFTReceipt(reordered); err != nil {
			t.Fatalf("structurally complete reordered receipt did not parse: %v", err)
		}
		linked := ready
		linked.BuildReceiptDigest = RBAUTHDigest(sha256.Sum256(reordered))
		if err := linked.ValidateLinks(specRecord, permitRecord, reordered, pairRecord); err != nil {
			t.Fatalf("scoped ReadySpec link check unexpectedly performed full RBDFT validation: %v", err)
		}
		if err := independentValidateRBDFTReadyLinks(
			reordered, pairRecord, permitIdentity, spec.PreparedParameterDigest, linked.ActualPayload,
		); err == nil {
			t.Fatal("full independent RBDFT validator accepted reordered receipt identifiers")
		}
		if err := independentAuthorizeRBDFTReady(
			linked, reordered, pairRecord, permitIdentity, spec.PreparedParameterDigest,
		); err == nil {
			t.Fatal("full independent authorizer accepted reordered receipt identifiers")
		}
	})
}

func TestRBAUTHStrictPrefixSuffixInsertionMagicAndType(t *testing.T) {
	spec, permit, ready, readyPermit, _, _ := goldenRBAUTHRecords(t)
	records := []struct {
		name    string
		maximum int
		record  []byte
		parse   func([]byte) error
	}{
		{name: "build spec", maximum: RBAUTHArtifactBuildSpecMaxBytes, record: mustMarshal(t, spec), parse: parseBuildSpecExpectZero},
		{name: "build permit", maximum: RBAUTHArtifactBuildPermitMaxBytes, record: mustMarshal(t, permit), parse: parseBuildPermitExpectZero},
		{name: "ready spec", maximum: RBAUTHReadySpecMaxBytes, record: mustMarshal(t, ready), parse: parseReadySpecExpectZero},
		{name: "ready permit", maximum: RBAUTHReadyPermitMaxBytes, record: mustMarshal(t, readyPermit), parse: parseReadyPermitExpectZero},
	}

	for _, test := range records {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(nil); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("nil input error=%v, want malformed", err)
			}
			for length := 0; length < len(test.record); length++ {
				if err := test.parse(test.record[:length]); !errors.Is(err, ErrRBAUTHMalformed) {
					t.Fatalf("prefix length %d error=%v, want malformed", length, err)
				}
			}
			for candidate := 0; candidate <= math.MaxUint8; candidate++ {
				suffixed := append(append([]byte(nil), test.record...), byte(candidate))
				if err := test.parse(suffixed); !errors.Is(err, ErrRBAUTHMalformed) {
					t.Fatalf("seal suffix %#x error=%v, want malformed", candidate, err)
				}
				inserted := insertBeforeSealAndReseal(test.record, byte(candidate))
				if err := test.parse(inserted); !errors.Is(err, ErrRBAUTHMalformed) {
					t.Fatalf("before-seal insertion %#x error=%v, want malformed", candidate, err)
				}
			}
			oversized := make([]byte, test.maximum+1)
			copy(oversized, test.record)
			if err := test.parse(oversized); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("oversized error=%v, want malformed", err)
			}
			for index := 0; index < len(RBAUTHMagic); index++ {
				changed := append([]byte(nil), test.record...)
				changed[index] ^= 1
				changed = resealRBAUTH(changed)
				if err := test.parse(changed); !errors.Is(err, ErrRBAUTHMalformed) {
					t.Fatalf("magic byte %d error=%v, want malformed", index, err)
				}
			}
			for candidate := 0; candidate <= math.MaxUint8; candidate++ {
				recordType := byte(candidate)
				if recordType == test.record[len(RBAUTHMagic)] {
					continue
				}
				changed := append([]byte(nil), test.record...)
				changed[len(RBAUTHMagic)] = recordType
				changed = resealRBAUTH(changed)
				if err := test.parse(changed); !errors.Is(err, ErrRBAUTHMalformed) {
					t.Fatalf("type %#x error=%v, want malformed", recordType, err)
				}
			}
		})
	}
}

func TestRBAUTHEverySingleBitMutationInvalidatesSeal(t *testing.T) {
	spec, permit, ready, readyPermit, _, _ := goldenRBAUTHRecords(t)
	records := []struct {
		record []byte
		parse  func([]byte) error
	}{
		{mustMarshal(t, spec), parseBuildSpecExpectZero},
		{mustMarshal(t, permit), parseBuildPermitExpectZero},
		{mustMarshal(t, ready), parseReadySpecExpectZero},
		{mustMarshal(t, readyPermit), parseReadyPermitExpectZero},
	}
	for _, test := range records {
		for index := range test.record {
			changed := append([]byte(nil), test.record...)
			changed[index] ^= 1
			if err := test.parse(changed); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("record length %d byte %d error=%v, want malformed", len(test.record), index, err)
			}
		}
	}
}

func TestRBAUTHFramingVersusSemanticReseal(t *testing.T) {
	spec, permit, ready, readyPermit, receiptRecord, pairRecord := goldenRBAUTHRecords(t)

	semanticBuild := spec
	semanticBuild.GeneratorPrecisionBits = 255
	semanticBuildRecord := mustMarshal(t, semanticBuild)
	parsedBuild, err := ParseArtifactBuildSpec(semanticBuildRecord)
	if err != nil {
		t.Fatalf("canonical semantic mutation did not parse: %v", err)
	}
	if err = parsedBuild.ValidateFrozenSemantics(); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("semantic precision mutation error=%v, want blocked", err)
	}

	promoted := spec
	promoted.Classification.SourceFaithful = true
	promotedRecord := mustMarshal(t, promoted)
	parsedPromoted, err := ParseArtifactBuildSpec(promotedRecord)
	if err != nil {
		t.Fatalf("canonical promotion did not parse: %v", err)
	}
	if err = parsedPromoted.ValidateFrozenSemantics(); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("promotion error=%v, want blocked", err)
	}

	staleCapacity := spec
	staleCapacity.Capacity.CapacityReportDigest = digestByte(0x71)
	parsedStale, err := ParseArtifactBuildSpec(mustMarshal(t, staleCapacity))
	if err != nil {
		t.Fatalf("canonical stale-capacity report did not parse: %v", err)
	}
	if parsedStale.Capacity.CapacityReportDigest != digestByte(0x71) {
		t.Fatal("semantic report mutation was not preserved for later authorizer comparison")
	}

	badPermit := permit
	badPermit.BuildSpecDigest = digestByte(0x72)
	parsedPermit, err := ParseArtifactBuildPermit(mustMarshal(t, badPermit))
	if err != nil {
		t.Fatalf("canonical cross-link mutation did not parse: %v", err)
	}
	if err = parsedPermit.ValidateEmbeddedIdentity(); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("build embedded-link error=%v, want blocked", err)
	}

	badReady := ready
	badReady.ActualPayload.STCEncoded, badReady.ActualPayload.CTSEncoded =
		badReady.ActualPayload.CTSEncoded, badReady.ActualPayload.STCEncoded
	parsedReady, err := ParseReadySpec(mustMarshal(t, badReady))
	if err != nil {
		t.Fatalf("canonical payload role swap did not parse: %v", err)
	}
	if err = parsedReady.ValidateLinks(mustMarshal(t, spec), mustMarshal(t, permit), receiptRecord, pairRecord); !errors.Is(err, ErrRBAUTHBlocked) {
		// Links intentionally do not authenticate tuple contents; frozen semantics
		// also cannot know them. This remains an inert report for the later artifact authorizer.
		if err != nil {
			t.Fatalf("unexpected non-blocked payload role-swap link error: %v", err)
		}
	}

	badReadyPermit := readyPermit
	badReadyPermit.ReadySpecDigest = digestByte(0x73)
	parsedReadyPermit, err := ParseReadyPermit(mustMarshal(t, badReadyPermit))
	if err != nil {
		t.Fatalf("canonical ready-link mutation did not parse: %v", err)
	}
	if err = parsedReadyPermit.ValidateEmbeddedIdentity(); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("ready embedded-link error=%v, want blocked", err)
	}
}

func TestRBAUTHPeakContractIsSnapshotDerivedAndSaturating(t *testing.T) {
	tests := []struct {
		name                      string
		total, available          uint64
		wantRemaining, wantExcess uint64
	}{
		{
			name: "audit golden", total: 33_617_782_768, available: 17_151_951_897,
			wantRemaining: 2_585_547_267, wantExcess: 55_815_677,
		},
		{
			name: "distinct admitted host", total: 33_618_251_776, available: 17_192_038_400,
			wantRemaining: 2_625_539_968, wantExcess: 15_822_976,
		},
		{
			name: "one below duplicate threshold", total: 50_000_000_000, available: 20_484_211_019,
			wantRemaining: 2_641_362_943, wantExcess: 1,
		},
		{
			name: "at duplicate threshold", total: 50_000_000_000, available: 20_484_211_020,
			wantRemaining: 2_641_362_944, wantExcess: 0,
		},
		{
			name: "one above duplicate threshold", total: 50_000_000_000, available: 20_484_211_021,
			wantRemaining: 2_641_362_945, wantExcess: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peak, err := rbauthPeakContractForCapacity(test.total, test.available)
			if err != nil {
				t.Fatalf("derive peak: %v", err)
			}
			if peak.RemainingBelowLimitBytes != test.wantRemaining ||
				peak.DuplicateDefaultExcessBytes != test.wantExcess ||
				peak.FullArtifactPeakBytes != 2_968_063_744 ||
				peak.PreGuardIncrementalPeakBytes != 7_129_861_888 ||
				peak.GuardedRequirementBytes != 7_842_848_076 ||
				peak.ForbiddenDuplicateDefaultBytes != 2_641_362_944 ||
				peak.Digest != RBAUTHPeakIdentity(peak) {
				t.Fatalf("derived peak = %+v", peak)
			}

			spec := goldenArtifactBuildSpec(t)
			spec.Capacity.SnapshotID = test.name
			spec.Capacity.TotalPhysicalBytes = test.total
			spec.Capacity.AvailablePhysicalBytes = test.available
			spec.Peak = peak
			if err = spec.ValidateFrozenSemantics(); err != nil {
				t.Fatalf("dynamic semantic validation: %v", err)
			}
			record := mustMarshal(t, spec)
			parsed, err := ParseArtifactBuildSpec(record)
			if err != nil || parsed != spec || parsed.ValidateFrozenSemantics() != nil {
				t.Fatalf("dynamic round trip failed: parse=%v equal=%v semantic=%v", err, parsed == spec, parsed.ValidateFrozenSemantics())
			}
		})
	}

	spec := goldenArtifactBuildSpec(t)
	peak, err := rbauthPeakContractForCapacity(spec.Capacity.TotalPhysicalBytes, spec.Capacity.AvailablePhysicalBytes)
	if err != nil {
		t.Fatal(err)
	}
	peak.RemainingBelowLimitBytes++
	peak.Digest = RBAUTHPeakIdentity(peak)
	spec.Peak = peak
	if err = spec.ValidateFrozenSemantics(); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("coherently resealed dynamic mismatch error=%v, want blocked", err)
	}

	for _, invalid := range []struct{ total, available uint64 }{
		{0, 0}, {1, 2}, {math.MaxUint64, math.MaxUint64},
	} {
		if _, err = rbauthPeakContractForCapacity(invalid.total, invalid.available); err == nil {
			t.Fatalf("invalid capacity %d/%d was accepted", invalid.total, invalid.available)
		}
	}
}

func TestRBAUTHRecordIdentityRejectsDoubleHashAlternates(t *testing.T) {
	spec, permit, ready, readyPermit, receiptRecord, pairRecord := goldenRBAUTHRecords(t)
	specRecord := mustMarshal(t, spec)
	readyRecord := mustMarshal(t, ready)

	bodyOnly := sha256.Sum256(specRecord[len(RBAUTHMagic)+1 : len(specRecord)-sha256.Size])
	wholeRecord := sha256.Sum256(specRecord)
	for name, wrong := range map[string]RBAUTHDigest{
		"body hash":                 RBAUTHDigest(bodyOnly),
		"sealed-record double hash": RBAUTHDigest(wholeRecord),
	} {
		t.Run("build "+name, func(t *testing.T) {
			changed := permit
			changed.BuildSpecDigest = wrong
			parsed, err := ParseArtifactBuildPermit(mustMarshal(t, changed))
			if err != nil {
				t.Fatal(err)
			}
			if err = parsed.ValidateEmbeddedIdentity(); !errors.Is(err, ErrRBAUTHBlocked) {
				t.Fatalf("error=%v, want blocked", err)
			}
		})
	}

	readyBodyOnly := sha256.Sum256(readyRecord[len(RBAUTHMagic)+1 : len(readyRecord)-sha256.Size])
	readyWhole := sha256.Sum256(readyRecord)
	for name, wrong := range map[string]RBAUTHDigest{
		"body hash":                 RBAUTHDigest(readyBodyOnly),
		"sealed-record double hash": RBAUTHDigest(readyWhole),
	} {
		t.Run("ready "+name, func(t *testing.T) {
			changed := readyPermit
			changed.ReadySpecDigest = wrong
			parsed, err := ParseReadyPermit(mustMarshal(t, changed))
			if err != nil {
				t.Fatal(err)
			}
			if err = parsed.ValidateEmbeddedIdentity(); !errors.Is(err, ErrRBAUTHBlocked) {
				t.Fatalf("error=%v, want blocked", err)
			}
		})
	}

	changedReady := ready
	changedReady.BuildSpecDigest = RBAUTHDigest(sha256.Sum256(specRecord))
	parsedReady, err := ParseReadySpec(mustMarshal(t, changedReady))
	if err != nil {
		t.Fatal(err)
	}
	if err = parsedReady.ValidateLinks(specRecord, mustMarshal(t, permit), receiptRecord, pairRecord); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("ready build-spec double hash error=%v, want blocked", err)
	}

	badNestedPermit := permit
	badNestedPermit.BuildSpecDigest = RBAUTHDigest(sha256.Sum256(specRecord))
	badNestedPermitRecord := mustMarshal(t, badNestedPermit)
	readyForBadNestedPermit := ready
	readyForBadNestedPermit.BuildPermitDigest = independentRecordIdentity(t, badNestedPermitRecord)
	parsedReady, err = ParseReadySpec(mustMarshal(t, readyForBadNestedPermit))
	if err != nil {
		t.Fatal(err)
	}
	if err = parsedReady.ValidateLinks(specRecord, badNestedPermitRecord, receiptRecord, pairRecord); !errors.Is(err, ErrRBAUTHBlocked) {
		t.Fatalf("ready nested build-permit double hash error=%v, want blocked", err)
	}

	for name, mutate := range map[string]func(*ReadySpec){
		"receipt": func(value *ReadySpec) {
			identity := sha256.Sum256(receiptRecord)
			value.BuildReceiptDigest = RBAUTHDigest(sha256.Sum256(identity[:]))
		},
		"pair manifest": func(value *ReadySpec) {
			identity := sha256.Sum256(pairRecord)
			value.ArtifactPairManifestDigest = RBAUTHDigest(sha256.Sum256(identity[:]))
		},
	} {
		t.Run("RBDFT "+name+" double hash", func(t *testing.T) {
			changed := ready
			mutate(&changed)
			parsed, parseErr := ParseReadySpec(mustMarshal(t, changed))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if linkErr := parsed.ValidateLinks(specRecord, mustMarshal(t, permit), receiptRecord, pairRecord); !errors.Is(linkErr, ErrRBAUTHBlocked) {
				t.Fatalf("error=%v, want blocked", linkErr)
			}
		})
	}
}

func TestRBAUTHStringCountBooleanDigestAndMaximumBoundaries(t *testing.T) {
	spec, permit, ready, readyPermit, _, _ := goldenRBAUTHRecords(t)

	for _, length := range []int{1, 255, 256} {
		changed := spec
		changed.Capacity.SnapshotID = strings.Repeat("s", length)
		record := mustMarshal(t, changed)
		if _, err := ParseArtifactBuildSpec(record); err != nil {
			t.Fatalf("snapshot length %d rejected: %v", length, err)
		}
	}
	for _, length := range []int{0, 257} {
		changed := spec
		changed.Capacity.SnapshotID = strings.Repeat("s", length)
		if _, err := changed.MarshalBinary(); !errors.Is(err, ErrRBAUTHMalformed) {
			t.Fatalf("snapshot length %d marshal error=%v, want malformed", length, err)
		}
	}

	base := mustMarshal(t, spec)
	for name, length := range map[string]uint32{"zero": 0, "257": 257, "max": math.MaxUint32} {
		t.Run("raw string "+name, func(t *testing.T) {
			changed := append([]byte(nil), base...)
			binary.LittleEndian.PutUint32(changed[len(RBAUTHMagic)+1:], length)
			changed = resealRBAUTH(changed)
			if _, err := ParseArtifactBuildSpec(changed); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("error=%v, want malformed", err)
			}
		})
	}
	invalidUTF8 := append([]byte(nil), base...)
	invalidUTF8[len(RBAUTHMagic)+1+4] = 0xff
	invalidUTF8 = resealRBAUTH(invalidUTF8)
	if _, err := ParseArtifactBuildSpec(invalidUTF8); !errors.Is(err, ErrRBAUTHMalformed) {
		t.Fatalf("invalid UTF-8 error=%v, want malformed", err)
	}

	boolOffset := buildSpecFirstBoolOffset(base)
	invalidBool := append([]byte(nil), base...)
	invalidBool[boolOffset] = 2
	invalidBool = resealRBAUTH(invalidBool)
	if _, err := ParseArtifactBuildSpec(invalidBool); !errors.Is(err, ErrRBAUTHMalformed) {
		t.Fatalf("invalid Boolean error=%v, want malformed", err)
	}

	digestOffset := buildSpecFirstDigestOffset(base)
	zeroDigest := append([]byte(nil), base...)
	clear(zeroDigest[digestOffset : digestOffset+sha256.Size])
	zeroDigest = resealRBAUTH(zeroDigest)
	if _, err := ParseArtifactBuildSpec(zeroDigest); !errors.Is(err, ErrRBAUTHMalformed) {
		t.Fatalf("all-zero digest error=%v, want malformed", err)
	}

	countOffset := buildSpecSTCListCountOffset(base)
	for _, count := range []uint32{0, 1, 3, math.MaxUint32} {
		changed := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(changed[countOffset:], count)
		changed = resealRBAUTH(changed)
		if _, err := ParseArtifactBuildSpec(changed); !errors.Is(err, ErrRBAUTHMalformed) {
			t.Fatalf("STC list count %d error=%v, want malformed", count, err)
		}
	}

	maxString := strings.Repeat("m", 256)
	maxBuild := spec
	maxBuild.Classification = RBAUTHClassification{AdaptationLabel: maxString, EvidenceScope: maxString, Maturity: maxString}
	maxBuild.Capacity.SnapshotID = maxString
	maxBuild.BuilderID, maxBuild.DigestID, maxBuild.AllocationID, maxBuild.ReleaseID, maxBuild.OwnershipID =
		maxString, maxString, maxString, maxString, maxString
	maxBuildRecord := mustMarshal(t, maxBuild)
	if len(maxBuildRecord) != RBAUTHArtifactBuildSpecMaxBytes {
		t.Fatalf("max build length=%d", len(maxBuildRecord))
	}
	if _, err := ParseArtifactBuildSpec(maxBuildRecord); err != nil {
		t.Fatalf("max build parse: %v", err)
	}
	maxPermit := permit
	maxPermit.Spec = maxBuild
	maxPermitRecord := mustMarshal(t, maxPermit)
	if len(maxPermitRecord) != RBAUTHArtifactBuildPermitMaxBytes {
		t.Fatalf("max permit length=%d", len(maxPermitRecord))
	}
	if _, err := ParseArtifactBuildPermit(maxPermitRecord); err != nil {
		t.Fatalf("max permit parse: %v", err)
	}
	maxReady := ready
	maxReady.Classification = RBAUTHClassification{AdaptationLabel: maxString, EvidenceScope: maxString, Maturity: maxString}
	maxReady.Capacity.SnapshotID, maxReady.ArtifactState = maxString, maxString
	maxReadyRecord := mustMarshal(t, maxReady)
	if len(maxReadyRecord) != RBAUTHReadySpecMaxBytes {
		t.Fatalf("max ready length=%d", len(maxReadyRecord))
	}
	if _, err := ParseReadySpec(maxReadyRecord); err != nil {
		t.Fatalf("max ready parse: %v", err)
	}
	maxReadyPermit := readyPermit
	maxReadyPermit.Spec = maxReady
	maxReadyPermitRecord := mustMarshal(t, maxReadyPermit)
	if len(maxReadyPermitRecord) != RBAUTHReadyPermitMaxBytes {
		t.Fatalf("max ready permit length=%d", len(maxReadyPermitRecord))
	}
	if _, err := ParseReadyPermit(maxReadyPermitRecord); err != nil {
		t.Fatalf("max ready permit parse: %v", err)
	}
}

func TestRBAUTHNullableBigFloatCanonicalBoundariesAndMetadata(t *testing.T) {
	absent, err := NewRBAUTHNullableBigFloat(nil)
	if err != nil {
		t.Fatal(err)
	}
	absentBytes, err := absent.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(absentBytes, []byte{0}) {
		t.Fatalf("nil encoding=%x", absentBytes)
	}
	parsedAbsent, err := ParseRBAUTHNullableBigFloat(absentBytes)
	if err != nil || parsedAbsent.Present() {
		t.Fatalf("nil round trip=%+v err=%v", parsedAbsent, err)
	}
	if _, err = RBAUTHScalingIdentity(RBAUTHRoleSTC, RBAUTHPhaseEffective, absent); !errors.Is(err, ErrRBAUTHMalformed) {
		t.Fatalf("nil effective scaling error=%v, want malformed", err)
	}
	if _, err = RBAUTHScalingIdentity(RBAUTHRoleSTC, RBAUTHPhaseRaw, absent); err != nil {
		t.Fatal(err)
	}

	for _, precision := range []uint{1, 255, 256} {
		for mode := big.ToNearestEven; mode <= big.ToPositiveInf; mode++ {
			value := new(big.Float).SetPrec(precision).SetMode(mode).SetFloat64(1.25)
			wrapped, wrapErr := NewRBAUTHNullableBigFloat(value)
			if wrapErr != nil {
				t.Fatalf("precision=%d mode=%d: %v", precision, mode, wrapErr)
			}
			encoded, marshalErr := wrapped.MarshalBinary()
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			parsed, parseErr := ParseRBAUTHNullableBigFloat(encoded)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if parsed.Precision() != uint32(precision) || parsed.RoundingMode() != byte(mode) ||
				parsed.Accuracy() != int8(value.Acc()) || parsed.ExactHex() != wrapped.ExactHex() {
				t.Fatalf("metadata changed: got=%+v want=%+v", parsed, wrapped)
			}
		}
	}

	positiveZero, err := NewRBAUTHNullableBigFloat(new(big.Float).SetPrec(53).SetFloat64(0))
	if err != nil {
		t.Fatal(err)
	}
	negativeZero, err := NewRBAUTHNullableBigFloat(new(big.Float).SetPrec(53).SetFloat64(math.Copysign(0, -1)))
	if err != nil {
		t.Fatal(err)
	}
	if positiveZero.Signbit() || !negativeZero.Signbit() {
		t.Fatal("zero sign metadata changed")
	}
	positiveDigest, _ := RBAUTHScalingIdentity(RBAUTHRoleSTC, RBAUTHPhaseRaw, positiveZero)
	negativeDigest, _ := RBAUTHScalingIdentity(RBAUTHRoleSTC, RBAUTHPhaseRaw, negativeZero)
	if positiveDigest == negativeDigest {
		t.Fatal("positive and negative zero have the same scaling identity")
	}

	baseValue := new(big.Float).SetPrec(53).SetMode(big.ToNearestEven).SetFloat64(1.25)
	base, err := NewRBAUTHNullableBigFloat(baseValue)
	if err != nil {
		t.Fatal(err)
	}
	for _, accuracy := range []int8{-1, 0, 1} {
		changed := base
		changed.accuracy = accuracy
		encoded, marshalErr := changed.MarshalBinary()
		if marshalErr != nil {
			t.Fatalf("accuracy %d marshal: %v", accuracy, marshalErr)
		}
		parsed, parseErr := ParseRBAUTHNullableBigFloat(encoded)
		if parseErr != nil || parsed.Accuracy() != accuracy {
			t.Fatalf("accuracy %d round trip got=%d err=%v", accuracy, parsed.Accuracy(), parseErr)
		}
	}
	variants := []RBAUTHNullableBigFloat{base, base, base}
	variants[0].precision = 64
	variants[1].roundingMode = byte(big.ToZero)
	variants[2].accuracy = int8(big.Above)
	digests := make(map[RBAUTHDigest]struct{})
	for index, variant := range variants {
		if err = variant.validate(); err != nil {
			t.Fatalf("orthogonal variant %d: %v", index, err)
		}
		digest, digestErr := RBAUTHScalingIdentity(RBAUTHRoleCTS, RBAUTHPhaseEffective, variant)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		digests[digest] = struct{}{}
		parsedValue, valueErr := variant.BigFloat()
		if valueErr != nil || parsedValue.Cmp(baseValue) != 0 {
			t.Fatalf("variant %d changed value", index)
		}
	}
	baseDigest, _ := RBAUTHScalingIdentity(RBAUTHRoleCTS, RBAUTHPhaseEffective, base)
	digests[baseDigest] = struct{}{}
	if len(digests) != 4 {
		t.Fatalf("orthogonal metadata produced %d identities, want 4", len(digests))
	}

	validBytes, err := base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	invalids := map[string][]byte{
		"present":        append([]byte(nil), validBytes...),
		"precision zero": append([]byte(nil), validBytes...),
		"precision 257":  append([]byte(nil), validBytes...),
		"rounding":       append([]byte(nil), validBytes...),
		"accuracy":       append([]byte(nil), validBytes...),
		"sign":           append([]byte(nil), validBytes...),
		"trailing":       append(append([]byte(nil), validBytes...), 0),
		"truncated":      append([]byte(nil), validBytes[:len(validBytes)-1]...),
	}
	invalids["present"][0] = 2
	binary.LittleEndian.PutUint32(invalids["precision zero"][1:], 0)
	binary.LittleEndian.PutUint32(invalids["precision 257"][1:], 257)
	invalids["rounding"][5] = 6
	invalids["accuracy"][6] = 2
	invalids["sign"][7] = 2
	for name, encoded := range invalids {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRBAUTHNullableBigFloat(encoded); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("error=%v, want malformed", err)
			}
		})
	}
	for name, exactHex := range map[string]string{
		"empty hex":     "",
		"oversized hex": strings.Repeat("a", 257),
		"uppercase hex": "0X1.4P+00",
		"nan":           "nan",
		"infinity":      "inf",
		"trailing hex":  base.exactHex + "x",
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			changed.exactHex = exactHex
			if _, err := changed.MarshalBinary(); !errors.Is(err, ErrRBAUTHMalformed) {
				t.Fatalf("error=%v, want malformed", err)
			}
		})
	}
	negativeAccuracy := append([]byte(nil), validBytes...)
	negativeAccuracy[6] = 0xfe
	if _, err := ParseRBAUTHNullableBigFloat(negativeAccuracy); !errors.Is(err, ErrRBAUTHMalformed) {
		t.Fatalf("accuracy -2 error=%v, want malformed", err)
	}
}

func TestRBAUTHTypedFragmentIdentitiesAreIndependent(t *testing.T) {
	literal := RBAUTHMatrixLiteralIdentity{
		Role: RBAUTHRoleSTC, Phase: RBAUTHPhaseRaw, Type: 1,
		LogSlots: 11, LevelQ: 18, LevelP: 6, Levels: []int32{1, 1},
		Format: 1, BitReversed: false, LogBSGSRatio: 0,
	}
	want := independentLiteralIdentity(literal)
	got, err := RBAUTHLiteralIdentity(literal)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("literal digest=%x want=%x", got, want)
	}

	variants := []RBAUTHMatrixLiteralIdentity{}
	add := func(change func(*RBAUTHMatrixLiteralIdentity)) {
		variant := literal
		variant.Levels = append([]int32(nil), literal.Levels...)
		change(&variant)
		variants = append(variants, variant)
	}
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.Role = RBAUTHRoleCTS })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.Phase = RBAUTHPhaseEffective })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.Type = 0 })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.LogSlots++ })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.LevelQ++ })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.LevelP++ })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.Levels[0]++ })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.Format++ })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.BitReversed = true })
	add(func(v *RBAUTHMatrixLiteralIdentity) { v.LogBSGSRatio++ })
	for index, variant := range variants {
		digest, digestErr := RBAUTHLiteralIdentity(variant)
		if digestErr != nil {
			t.Fatalf("variant %d: %v", index, digestErr)
		}
		if digest == got {
			t.Fatalf("variant %d did not change literal identity", index)
		}
	}
	for name, levels := range map[string][]int32{"nil": nil, "empty": {}, "too many": {1, 1, 1, 1}} {
		changed := literal
		changed.Levels = levels
		if _, err = RBAUTHLiteralIdentity(changed); !errors.Is(err, ErrRBAUTHMalformed) {
			t.Fatalf("%s levels error=%v, want malformed", name, err)
		}
	}

	scratch := defaultRBAUTHScratchLedger()
	if RBAUTHScratchIdentity(scratch) != independentScratchDigest(scratch) {
		t.Fatal("scratch digest differs from independent encoder")
	}
	changedScratch := scratch
	changedScratch.RootsBytes++
	if RBAUTHScratchIdentity(changedScratch) == scratch.Digest {
		t.Fatal("scratch field change retained digest")
	}
	peak := defaultRBAUTHPeakContract()
	if RBAUTHPeakIdentity(peak) != independentPeakDigest(peak) {
		t.Fatal("peak digest differs from independent encoder")
	}
	changedPeak := peak
	changedPeak.FullArtifactPeakBytes++
	if RBAUTHPeakIdentity(changedPeak) == peak.Digest {
		t.Fatal("peak field change retained digest")
	}
}

func TestRBAUTHBuildTypesCannotCarryReadyOnlyEvidenceOrLineage(t *testing.T) {
	for _, root := range []reflect.Type{
		reflect.TypeOf(ArtifactBuildSpec{}), reflect.TypeOf(ArtifactBuildPermitReport{}),
	} {
		inspectNoForbiddenBuildFields(t, root, map[reflect.Type]bool{})
	}
	for _, permit := range []reflect.Type{
		reflect.TypeOf(ArtifactBuildPermitReport{}), reflect.TypeOf(ReadyPermitReport{}),
	} {
		inspectNoCapabilityKinds(t, permit, map[reflect.Type]bool{})
	}
	payloadType := reflect.TypeOf(RBAUTHActualPayload{})
	if payloadType.NumField() != 4 {
		t.Fatalf("ready payload tuple count=%d, want 4", payloadType.NumField())
	}
}

func TestRBAUTHBoundedResealAndParserAllocationCeilings(t *testing.T) {
	spec, permit, ready, readyPermit, _, _ := goldenRBAUTHRecords(t)
	records := []struct {
		recordType byte
		maximum    int
		record     []byte
	}{
		{RBAUTHArtifactBuildSpecType, RBAUTHArtifactBuildSpecMaxBytes, mustMarshal(t, spec)},
		{RBAUTHArtifactBuildPermitType, RBAUTHArtifactBuildPermitMaxBytes, mustMarshal(t, permit)},
		{RBAUTHReadySpecType, RBAUTHReadySpecMaxBytes, mustMarshal(t, ready)},
		{RBAUTHReadyPermitType, RBAUTHReadyPermitMaxBytes, mustMarshal(t, readyPermit)},
	}
	for _, test := range records {
		t.Run(fmt.Sprintf("type-%02x", test.recordType), func(t *testing.T) {
			body := test.record[len(RBAUTHMagic)+1 : len(test.record)-sha256.Size]
			seed := append([]byte{test.recordType - 1}, body...)
			if candidate := boundedResealedRBAUTHCandidate(seed); !bytes.Equal(candidate, test.record) {
				t.Fatal("bounded candidate helper did not reconstruct its canonical seed")
			}

			oversizedInput := make([]byte, 2*RBAUTHArtifactBuildPermitMaxBytes)
			oversizedInput[0] = test.recordType - 1
			candidate := boundedResealedRBAUTHCandidate(oversizedInput)
			if len(candidate) != test.maximum {
				t.Fatalf("bounded candidate length=%d, want type ceiling %d", len(candidate), test.maximum)
			}
			if candidate[len(RBAUTHMagic)] != test.recordType {
				t.Fatalf("bounded candidate type=%#x", candidate[len(RBAUTHMagic)])
			}
			bodyEnd := len(candidate) - sha256.Size
			seal := sha256.Sum256(candidate[:bodyEnd])
			if !bytes.Equal(seal[:], candidate[bodyEnd:]) {
				t.Fatal("bounded candidate was not resealed")
			}
			assertSelectedRBAUTHParserCanonicalIfValid(t, candidate)
		})
	}

	// MaxUint32 must be rejected from the fixed prefix, before any attempt to
	// allocate an exact-hex string of attacker-declared size.
	nullableLengthMax := make([]byte, 12)
	nullableLengthMax[0] = 1
	binary.LittleEndian.PutUint32(nullableLengthMax[1:], 256)
	nullableLengthMax[5] = byte(big.ToNearestEven)
	binary.LittleEndian.PutUint32(nullableLengthMax[8:], math.MaxUint32)
	if value, err := ParseRBAUTHNullableBigFloat(nullableLengthMax); !errors.Is(err, ErrRBAUTHMalformed) || value != (RBAUTHNullableBigFloat{}) {
		t.Fatalf("nullable MaxUint32 length returned value=%+v error=%v", value, err)
	}

	// The transform factor count is fixed-size on the destination type. A
	// MaxUint32 wire count must fail without count-proportional allocation.
	countMax := mustMarshal(t, spec)
	binary.LittleEndian.PutUint32(countMax[buildSpecSTCListCountOffset(countMax):], math.MaxUint32)
	countMax = resealRBAUTH(countMax)
	if value, err := ParseArtifactBuildSpec(countMax); !errors.Is(err, ErrRBAUTHMalformed) || value != (ArtifactBuildSpec{}) {
		t.Fatalf("build-spec MaxUint32 count returned value=%+v error=%v", value, err)
	}
}

func FuzzRBAUTHParsers(f *testing.F) {
	spec, permit, ready, readyPermit, _, _ := goldenRBAUTHRecords(f)
	for _, record := range [][]byte{
		mustMarshal(f, spec), mustMarshal(f, permit), mustMarshal(f, ready), mustMarshal(f, readyPermit),
	} {
		f.Add(record)
	}
	absent, err := NewRBAUTHNullableBigFloat(nil)
	if err != nil {
		f.Fatal(err)
	}
	present, err := NewRBAUTHNullableBigFloat(
		new(big.Float).SetPrec(256).SetMode(big.ToNearestEven).SetFloat64(1.25),
	)
	if err != nil {
		f.Fatal(err)
	}
	for _, value := range []RBAUTHNullableBigFloat{absent, present} {
		encoded, marshalErr := value.MarshalBinary()
		if marshalErr != nil {
			f.Fatal(marshalErr)
		}
		f.Add(encoded)
	}
	f.Add([]byte(nil))
	f.Add([]byte(RBAUTHMagic))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		assertAllRBAUTHParsersCanonicalIfValid(t, encoded)
		if value, parseErr := ParseRBAUTHNullableBigFloat(encoded); parseErr == nil {
			roundTrip, marshalErr := value.MarshalBinary()
			if marshalErr != nil || !bytes.Equal(roundTrip, encoded) {
				t.Fatal("nullable big.Float non-canonical round trip")
			}
		}
		if candidate := boundedResealedRBAUTHCandidate(encoded); candidate != nil {
			assertSelectedRBAUTHParserCanonicalIfValid(t, candidate)
		}
	})
}

func boundedResealedRBAUTHCandidate(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	recordType := byte(1 + input[0]%4)
	maximum := map[byte]int{
		RBAUTHArtifactBuildSpecType:   RBAUTHArtifactBuildSpecMaxBytes,
		RBAUTHArtifactBuildPermitType: RBAUTHArtifactBuildPermitMaxBytes,
		RBAUTHReadySpecType:           RBAUTHReadySpecMaxBytes,
		RBAUTHReadyPermitType:         RBAUTHReadyPermitMaxBytes,
	}[recordType]
	body := input[1:]
	maximumBodyBytes := maximum - len(RBAUTHMagic) - 1 - sha256.Size
	if len(body) > maximumBodyBytes {
		body = body[:maximumBodyBytes]
	}
	record := make([]byte, 0, maximum)
	record = append(record, RBAUTHMagic...)
	record = append(record, recordType)
	record = append(record, body...)
	seal := sha256.Sum256(record)
	return append(record, seal[:]...)
}

func assertAllRBAUTHParsersCanonicalIfValid(t *testing.T, encoded []byte) {
	t.Helper()
	if value, err := ParseArtifactBuildSpec(encoded); err == nil {
		assertRBAUTHMarshalRoundTrip(t, "build spec", encoded, value)
	}
	if value, err := ParseArtifactBuildPermit(encoded); err == nil {
		assertRBAUTHMarshalRoundTrip(t, "build permit", encoded, value)
	}
	if value, err := ParseReadySpec(encoded); err == nil {
		assertRBAUTHMarshalRoundTrip(t, "ready spec", encoded, value)
	}
	if value, err := ParseReadyPermit(encoded); err == nil {
		assertRBAUTHMarshalRoundTrip(t, "ready permit", encoded, value)
	}
}

func assertSelectedRBAUTHParserCanonicalIfValid(t *testing.T, encoded []byte) {
	t.Helper()
	if len(encoded) <= len(RBAUTHMagic) {
		t.Fatal("selected RBAUTH candidate is missing its type")
	}
	switch encoded[len(RBAUTHMagic)] {
	case RBAUTHArtifactBuildSpecType:
		if value, err := ParseArtifactBuildSpec(encoded); err == nil {
			assertRBAUTHMarshalRoundTrip(t, "selected build spec", encoded, value)
		}
	case RBAUTHArtifactBuildPermitType:
		if value, err := ParseArtifactBuildPermit(encoded); err == nil {
			assertRBAUTHMarshalRoundTrip(t, "selected build permit", encoded, value)
		}
	case RBAUTHReadySpecType:
		if value, err := ParseReadySpec(encoded); err == nil {
			assertRBAUTHMarshalRoundTrip(t, "selected ready spec", encoded, value)
		}
	case RBAUTHReadyPermitType:
		if value, err := ParseReadyPermit(encoded); err == nil {
			assertRBAUTHMarshalRoundTrip(t, "selected ready permit", encoded, value)
		}
	default:
		t.Fatalf("unsupported selected RBAUTH type %#x", encoded[len(RBAUTHMagic)])
	}
}

func assertRBAUTHMarshalRoundTrip(t *testing.T, name string, encoded []byte, value binaryMarshaler) {
	t.Helper()
	roundTrip, err := value.MarshalBinary()
	if err != nil || !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("%s non-canonical round trip: err=%v", name, err)
	}
}

type binaryMarshaler interface {
	MarshalBinary() ([]byte, error)
}

func mustMarshal(t testing.TB, value binaryMarshaler) []byte {
	t.Helper()
	encoded, err := value.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func parseBuildSpecExpectZero(encoded []byte) error {
	value, err := ParseArtifactBuildSpec(encoded)
	if err != nil && value != (ArtifactBuildSpec{}) {
		return errors.New("build-spec parser returned a partial report")
	}
	return err
}

func parseBuildPermitExpectZero(encoded []byte) error {
	value, err := ParseArtifactBuildPermit(encoded)
	if err != nil && value != (ArtifactBuildPermitReport{}) {
		return errors.New("build-permit parser returned a partial report")
	}
	return err
}

func parseReadySpecExpectZero(encoded []byte) error {
	value, err := ParseReadySpec(encoded)
	if err != nil && value != (ReadySpec{}) {
		return errors.New("ready-spec parser returned a partial report")
	}
	return err
}

func parseReadyPermitExpectZero(encoded []byte) error {
	value, err := ParseReadyPermit(encoded)
	if err != nil && value != (ReadyPermitReport{}) {
		return errors.New("ready-permit parser returned a partial report")
	}
	return err
}

func resealRBAUTH(record []byte) []byte {
	result := append([]byte(nil), record...)
	if len(result) < sha256.Size {
		return result
	}
	bodyEnd := len(result) - sha256.Size
	seal := sha256.Sum256(result[:bodyEnd])
	copy(result[bodyEnd:], seal[:])
	return result
}

func insertBeforeSealAndReseal(record []byte, inserted byte) []byte {
	bodyEnd := len(record) - sha256.Size
	result := append([]byte(nil), record[:bodyEnd]...)
	result = append(result, inserted)
	seal := sha256.Sum256(result)
	result = append(result, seal[:]...)
	return result
}

func testSkipString(record []byte, offset int) int {
	length := int(binary.LittleEndian.Uint32(record[offset:]))
	return offset + 4 + length
}

func buildSpecFirstBoolOffset(record []byte) int {
	offset := len(RBAUTHMagic) + 1
	for range 3 {
		offset = testSkipString(record, offset)
	}
	return offset
}

func buildSpecFirstDigestOffset(record []byte) int {
	offset := buildSpecFirstBoolOffset(record) + 2
	offset = testSkipString(record, offset)
	return offset + 16
}

func buildSpecSTCListCountOffset(record []byte) int {
	offset := buildSpecFirstDigestOffset(record)
	offset += 8 * sha256.Size             // capacity digests
	offset += sha256.Size + 8*sha256.Size // prepared and transform digests
	offset += 8                           // two precision uint32 values
	for range 5 {
		offset = testSkipString(record, offset)
	}
	offset++    // construction order
	offset += 4 // STC factor count
	return offset
}

func independentLiteralIdentity(value RBAUTHMatrixLiteralIdentity) RBAUTHDigest {
	var buffer bytes.Buffer
	buffer.WriteString(RBAUTHMagic)
	buffer.WriteByte(RBAUTHLiteralDigestDomain)
	buffer.WriteByte(value.Role)
	buffer.WriteByte(value.Phase)
	buffer.WriteByte(value.Type)
	independentWriteUint32(&buffer, uint32(value.LogSlots))
	independentWriteUint32(&buffer, uint32(value.LevelQ))
	independentWriteUint32(&buffer, uint32(value.LevelP))
	independentWriteUint32(&buffer, uint32(len(value.Levels)))
	for _, level := range value.Levels {
		independentWriteUint32(&buffer, uint32(level))
	}
	buffer.WriteByte(value.Format)
	if value.BitReversed {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}
	independentWriteUint32(&buffer, uint32(value.LogBSGSRatio))
	return RBAUTHDigest(sha256.Sum256(buffer.Bytes()))
}

func inspectNoForbiddenBuildFields(t *testing.T, value reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			lower := strings.ToLower(field.Name)
			for _, forbidden := range []string{
				"numericpayload", "encodedpayload", "actualpayload",
				"numericfactordigest", "encodedfactordigest",
				"numericrecordbytes", "encodedrecordbytes",
				"artifactdigest", "pairmanifest", "manifestdigest",
				"lifecycledigest", "receiptdigest", "artifacthandle", "artifactstate",
				"wallnanoseconds", "walltime", "peakrss", "actualconstructordelta", "actualdelta", "lineage",
			} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("build report type %s contains forbidden field %s", value, field.Name)
				}
			}
			inspectNoForbiddenBuildFields(t, field.Type, seen)
		}
	case reflect.Array:
		inspectNoForbiddenBuildFields(t, value.Elem(), seen)
	case reflect.Slice, reflect.Map, reflect.Interface, reflect.UnsafePointer:
		t.Fatalf("build report type graph contains mutable/capability kind %s in %s", value.Kind(), value)
	}
}

func inspectNoCapabilityKinds(t *testing.T, value reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			inspectNoCapabilityKinds(t, value.Field(index).Type, seen)
		}
	case reflect.Array:
		inspectNoCapabilityKinds(t, value.Elem(), seen)
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface, reflect.UnsafePointer, reflect.Func, reflect.Chan:
		t.Fatalf("parsed permit report graph contains capability-bearing kind %s in %s", value.Kind(), value)
	}
}

func goldenRBAUTHRecords(t testing.TB) (
	ArtifactBuildSpec,
	ArtifactBuildPermitReport,
	ReadySpec,
	ReadyPermitReport,
	[]byte,
	[]byte,
) {
	t.Helper()
	spec := goldenArtifactBuildSpec(t)
	specRecord := independentMarshalBuildSpec(t, spec)
	permit := ArtifactBuildPermitReport{
		BuildSpecDigest: independentRecordIdentity(t, specRecord),
		Spec:            spec,
	}
	permitRecord := independentMarshalBuildPermit(t, permit)
	actualPayload := RBAUTHActualPayload{
		STCNumeric: RBAUTHPayloadTuple{AggregateDigest: digestByte(20), RecordBytes: 101},
		STCEncoded: RBAUTHPayloadTuple{AggregateDigest: digestByte(21), RecordBytes: 102},
		CTSNumeric: RBAUTHPayloadTuple{AggregateDigest: digestByte(22), RecordBytes: 103},
		CTSEncoded: RBAUTHPayloadTuple{AggregateDigest: digestByte(23), RecordBytes: 104},
	}
	buildPermitIdentity := independentRecordIdentity(t, permitRecord)
	receiptRecord, pairRecord := independentCanonicalRBDFTRecords(
		buildPermitIdentity,
		spec.PreparedParameterDigest,
		actualPayload,
	)
	if err := independentValidateRBDFTReadyLinks(
		receiptRecord,
		pairRecord,
		buildPermitIdentity,
		spec.PreparedParameterDigest,
		actualPayload,
	); err != nil {
		t.Fatalf("invalid independent RBDFT golden fixture: %v", err)
	}
	ready := ReadySpec{
		Classification: RBAUTHClassification{
			AdaptationLabel: RBAUTHAdaptationLabel,
			EvidenceScope:   RBAUTHReadyEvidenceScope,
			Maturity:        RBAUTHMaturity,
		},
		Capacity:                   valueCopyCapacity(spec.Capacity),
		PreparedParameterDigest:    spec.PreparedParameterDigest,
		BuildSpecDigest:            independentRecordIdentity(t, specRecord),
		BuildPermitDigest:          independentRecordIdentity(t, permitRecord),
		BuildReceiptDigest:         RBAUTHDigest(sha256.Sum256(receiptRecord)),
		ArtifactPairManifestDigest: RBAUTHDigest(sha256.Sum256(pairRecord)),
		ActualPayload:              actualPayload,
		ArtifactState:              RBAUTHPrivateUninstalledState,
	}
	readyRecord := independentMarshalReadySpec(t, ready)
	readyPermit := ReadyPermitReport{
		ReadySpecDigest: independentRecordIdentity(t, readyRecord),
		Spec:            ready,
	}
	return spec, permit, ready, readyPermit, receiptRecord, pairRecord
}

func goldenArtifactBuildSpec(t testing.TB) ArtifactBuildSpec {
	t.Helper()
	scratch := RBAUTHScratchLedger{
		RootsBytes: 2097408, Pow5Bytes: 32776, ABCLayerBytes: 1572864,
		LargestSTCNumericFactorBytes: 33554432, LargestCTSNumericFactorBytes: 16252928,
		STCPhaseMaximumBytes: 70811912, CTSPhaseMaximumBytes: 36208904,
		ArtifactEnvelopeBytes: 81264640, RemainingEnvelopeBytes: 10452728,
	}
	scratch.Digest = independentScratchDigest(scratch)
	peak := RBAUTHPeakContract{
		FullArtifactPeakBytes: 2968063744, PreGuardIncrementalPeakBytes: 7129861888,
		GuardedRequirementBytes: 7842848076, RemainingBelowLimitBytes: 2585547267,
		ForbiddenDuplicateDefaultBytes: 2641362944, DuplicateDefaultExcessBytes: 55815677,
	}
	peak.Digest = independentPeakDigest(peak)
	return ArtifactBuildSpec{
		Classification: RBAUTHClassification{
			AdaptationLabel: "lattigo_packing_adaptation_r1",
			EvidenceScope:   "route_b_artifact_build_authorization_only",
			Maturity:        "route_b_construction_contract_only_unverified",
		},
		Capacity: RBAUTHCapacityBinding{
			SnapshotID: "l11-audit-fixture-2026-08-30", TotalPhysicalBytes: 33617782768,
			AvailablePhysicalBytes: 17151951897,
			CapacityPlanDigest:     digestByte(1), CapacityProbeDigest: digestByte(2),
			CapacityReportDigest: digestByte(3), CapacityPermitDigest: digestByte(4),
			ParameterDigest: digestByte(5), ProfileDigest: digestByte(6),
			ShapeDigest: digestByte(7), PolicyDigest: digestByte(8),
		},
		PreparedParameterDigest: digestByte(9),
		Transforms: RBAUTHTransformDigests{
			RawSTCLiteralDigest: digestByte(10), RawSTCScalingDigest: digestByte(11),
			EffectiveSTCLiteralDigest: digestByte(12), EffectiveSTCScalingDigest: digestByte(13),
			RawCTSLiteralDigest: digestByte(14), RawCTSScalingDigest: digestByte(15),
			EffectiveCTSLiteralDigest: digestByte(16), EffectiveCTSScalingDigest: digestByte(17),
		},
		GeneratorPrecisionBits: 256, EncoderPrecisionBits: 256,
		BuilderID:         "lattigo-route-b-prebuilt-dft-streaming-builder-v1",
		DigestID:          "sha256-canonical-streaming-binary-v1",
		AllocationID:      "stc-then-cts-single-factor-v1",
		ReleaseID:         "logical-reference-drop-v1",
		OwnershipID:       "private-exclusive-transfer-v1",
		ConstructionOrder: 1,
		STCFactorCount:    2, STCDiagonalCounts: [2]uint32{63, 64},
		CTSFactorCount: 3, CTSDiagonalCounts: [3]uint32{16, 31, 15},
		ExpectedObservedStreamingDelta: 2,
		Scratch:                        scratch, Peak: peak,
	}
}

func independentMarshalBuildSpec(t testing.TB, value ArtifactBuildSpec) []byte {
	t.Helper()
	var body bytes.Buffer
	independentWriteBuildSpecBody(&body, value)
	return independentSealRecord(RBAUTHArtifactBuildSpecType, body.Bytes())
}

func independentMarshalBuildPermit(t testing.TB, value ArtifactBuildPermitReport) []byte {
	t.Helper()
	var body bytes.Buffer
	independentWriteDigest(&body, value.BuildSpecDigest)
	independentWriteBuildSpecBody(&body, value.Spec)
	return independentSealRecord(RBAUTHArtifactBuildPermitType, body.Bytes())
}

func independentWriteBuildSpecBody(body *bytes.Buffer, value ArtifactBuildSpec) {
	independentWriteClassification(body, value.Classification)
	independentWriteCapacity(body, value.Capacity)
	independentWriteDigest(body, value.PreparedParameterDigest)
	for _, digest := range []RBAUTHDigest{
		value.Transforms.RawSTCLiteralDigest, value.Transforms.RawSTCScalingDigest,
		value.Transforms.EffectiveSTCLiteralDigest, value.Transforms.EffectiveSTCScalingDigest,
		value.Transforms.RawCTSLiteralDigest, value.Transforms.RawCTSScalingDigest,
		value.Transforms.EffectiveCTSLiteralDigest, value.Transforms.EffectiveCTSScalingDigest,
	} {
		independentWriteDigest(body, digest)
	}
	independentWriteUint32(body, value.GeneratorPrecisionBits)
	independentWriteUint32(body, value.EncoderPrecisionBits)
	for _, field := range []string{value.BuilderID, value.DigestID, value.AllocationID, value.ReleaseID, value.OwnershipID} {
		independentWriteString(body, field)
	}
	body.WriteByte(value.ConstructionOrder)
	independentWriteUint32(body, value.STCFactorCount)
	independentWriteUint32(body, uint32(len(value.STCDiagonalCounts)))
	for _, count := range value.STCDiagonalCounts {
		independentWriteUint32(body, count)
	}
	independentWriteUint32(body, value.CTSFactorCount)
	independentWriteUint32(body, uint32(len(value.CTSDiagonalCounts)))
	for _, count := range value.CTSDiagonalCounts {
		independentWriteUint32(body, count)
	}
	for _, delta := range []uint64{
		value.ExpectedDefaultWholeDelta, value.ExpectedExplicitWholeDelta,
		value.ExpectedRawNumericDelta, value.ExpectedObservedStreamingDelta,
	} {
		independentWriteUint64(body, delta)
	}
	independentWriteScratch(body, value.Scratch)
	independentWritePeak(body, value.Peak)

}

func independentMarshalReadySpec(t testing.TB, value ReadySpec) []byte {
	t.Helper()
	var body bytes.Buffer
	independentWriteReadySpecBody(&body, value)
	return independentSealRecord(RBAUTHReadySpecType, body.Bytes())
}

func independentMarshalReadyPermit(t testing.TB, value ReadyPermitReport) []byte {
	t.Helper()
	var body bytes.Buffer
	independentWriteDigest(&body, value.ReadySpecDigest)
	independentWriteReadySpecBody(&body, value.Spec)
	return independentSealRecord(RBAUTHReadyPermitType, body.Bytes())
}

func independentWriteReadySpecBody(body *bytes.Buffer, value ReadySpec) {
	independentWriteClassification(body, value.Classification)
	independentWriteCapacity(body, value.Capacity)
	for _, digest := range []RBAUTHDigest{
		value.PreparedParameterDigest, value.BuildSpecDigest, value.BuildPermitDigest,
		value.BuildReceiptDigest, value.ArtifactPairManifestDigest,
	} {
		independentWriteDigest(body, digest)
	}
	for _, tuple := range []RBAUTHPayloadTuple{
		value.ActualPayload.STCNumeric, value.ActualPayload.STCEncoded,
		value.ActualPayload.CTSNumeric, value.ActualPayload.CTSEncoded,
	} {
		independentWriteDigest(body, tuple.AggregateDigest)
		independentWriteUint64(body, tuple.RecordBytes)
	}
	independentWriteString(body, value.ArtifactState)
}

func independentSealRecord(recordType byte, body []byte) []byte {
	result := append([]byte("LCPDTE-RBAUTH-v1"), recordType)
	result = append(result, body...)
	seal := sha256.Sum256(result)
	return append(result, seal[:]...)
}

func independentRecordIdentity(t testing.TB, record []byte) (result RBAUTHDigest) {
	t.Helper()
	if len(record) < sha256.Size {
		t.Fatal("independent record is shorter than a seal")
	}
	copy(result[:], record[len(record)-sha256.Size:])
	return
}

func independentRBDFTRecord(recordType byte, payload []byte) []byte {
	record := append([]byte("LCPDTE-RBDFT-v1\x00"), recordType, byte(0))
	return append(record, payload...)
}

func independentCanonicalRBDFTRecords(
	buildPermitDigest, preparedParameterDigest RBAUTHDigest,
	payload RBAUTHActualPayload,
) (receiptRecord, pairRecord []byte) {
	var pairBody bytes.Buffer
	independentWriteDigest(&pairBody, buildPermitDigest)
	for _, tuple := range []RBAUTHPayloadTuple{
		payload.STCNumeric, payload.STCEncoded, payload.CTSNumeric, payload.CTSEncoded,
	} {
		independentWriteDigest(&pairBody, tuple.AggregateDigest)
		independentWriteUint64(&pairBody, tuple.RecordBytes)
	}
	pairRecord = independentRBDFTRecord(0x05, pairBody.Bytes())
	pairManifestDigest := RBAUTHDigest(sha256.Sum256(pairRecord))

	var receiptBody bytes.Buffer
	independentWriteDigest(&receiptBody, buildPermitDigest)
	independentWriteDigest(&receiptBody, preparedParameterDigest)
	for _, identifier := range []string{
		independentRBDFTBuilderID,
		independentRBDFTDigestID,
		independentRBDFTAllocationID,
		independentRBDFTReleaseID,
		independentRBDFTOwnershipID,
	} {
		independentWriteString(&receiptBody, identifier)
	}
	independentWriteUint32(&receiptBody, 256)
	independentWriteUint32(&receiptBody, 256)
	for _, delta := range []uint64{0, 0, 0, 2} {
		independentWriteUint64(&receiptBody, delta)
	}
	independentWriteDigest(&receiptBody, digestByte(0x18))
	independentWriteUint32(&receiptBody, 1)
	independentWriteUint32(&receiptBody, 2)
	independentWriteUint32(&receiptBody, 3)
	for _, tuple := range []RBAUTHPayloadTuple{
		payload.STCNumeric, payload.STCEncoded, payload.CTSNumeric, payload.CTSEncoded,
	} {
		independentWriteDigest(&receiptBody, tuple.AggregateDigest)
	}
	for _, tuple := range []RBAUTHPayloadTuple{
		payload.STCNumeric, payload.STCEncoded, payload.CTSNumeric, payload.CTSEncoded,
	} {
		independentWriteUint64(&receiptBody, tuple.RecordBytes)
	}
	independentWriteUint64(&receiptBody, 123456789)
	independentWriteUint64(&receiptBody, 2968063744)
	independentWriteString(&receiptBody, independentRBDFTArtifactState)
	independentWriteDigest(&receiptBody, pairManifestDigest)
	receiptRecord = independentRBDFTRecord(0x07, receiptBody.Bytes())
	return receiptRecord, pairRecord
}

const (
	independentRBDFTWireFixtureLabel = "wire_fixture_only"
	independentRBDFTWireFixtureScope = "canonical_wire_grammar_and_cross_record_identity_only"
	independentRBDFTMaxStringBytes   = 256
	independentRBDFTBuilderID        = "lattigo-route-b-prebuilt-dft-streaming-builder-v1"
	independentRBDFTDigestID         = "sha256-canonical-streaming-binary-v1"
	independentRBDFTAllocationID     = "stc-then-cts-single-factor-v1"
	independentRBDFTReleaseID        = "logical-reference-drop-v1"
	independentRBDFTOwnershipID      = "private-exclusive-transfer-v1"
	independentRBDFTArtifactState    = "private-uninstalled"
)

type independentRBDFTPayloadTuple struct {
	digest      RBAUTHDigest
	recordBytes uint64
}

type independentRBDFTPair struct {
	buildPermitDigest RBAUTHDigest
	stcNumeric        independentRBDFTPayloadTuple
	stcEncoded        independentRBDFTPayloadTuple
	ctsNumeric        independentRBDFTPayloadTuple
	ctsEncoded        independentRBDFTPayloadTuple
}

type independentRBDFTReceipt struct {
	buildPermitDigest       RBAUTHDigest
	preparedParameterDigest RBAUTHDigest
	builderID               string
	digestID                string
	allocationID            string
	releaseID               string
	ownershipID             string
	generatorPrecision      uint32
	encoderPrecision        uint32
	defaultCounterDelta     uint64
	explicitCounterDelta    uint64
	rawNumericCounterDelta  uint64
	observedCounterDelta    uint64
	lifecycleDigest         RBAUTHDigest
	maxLiveNumeric          uint32
	stcFactorCount          uint32
	ctsFactorCount          uint32
	stcNumeric              independentRBDFTPayloadTuple
	stcEncoded              independentRBDFTPayloadTuple
	ctsNumeric              independentRBDFTPayloadTuple
	ctsEncoded              independentRBDFTPayloadTuple
	buildWallNanoseconds    uint64
	buildPeakRSSBytes       uint64
	artifactState           string
	artifactManifestDigest  RBAUTHDigest
}

type independentRBDFTReader struct {
	data   []byte
	offset int
}

func (reader *independentRBDFTReader) take(count int) ([]byte, error) {
	if count < 0 || reader.offset > len(reader.data)-count {
		return nil, fmt.Errorf("RBDFT body truncated at offset %d", reader.offset)
	}
	result := reader.data[reader.offset : reader.offset+count]
	reader.offset += count
	return result, nil
}

func (reader *independentRBDFTReader) u32() (uint32, error) {
	encoded, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(encoded), nil
}

func (reader *independentRBDFTReader) u64() (uint64, error) {
	encoded, err := reader.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(encoded), nil
}

func (reader *independentRBDFTReader) digest() (RBAUTHDigest, error) {
	encoded, err := reader.take(sha256.Size)
	if err != nil {
		return RBAUTHDigest{}, err
	}
	var result RBAUTHDigest
	copy(result[:], encoded)
	return result, nil
}

func (reader *independentRBDFTReader) string() (string, error) {
	length, err := reader.u32()
	if err != nil {
		return "", err
	}
	if length == 0 || length > independentRBDFTMaxStringBytes {
		return "", fmt.Errorf("RBDFT string length %d is outside [1,%d]", length, independentRBDFTMaxStringBytes)
	}
	encoded, err := reader.take(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(encoded) {
		return "", errors.New("RBDFT string is not UTF-8")
	}
	return string(encoded), nil
}

func (reader *independentRBDFTReader) finish() error {
	if reader.offset != len(reader.data) {
		return fmt.Errorf("RBDFT record has %d trailing bytes", len(reader.data)-reader.offset)
	}
	return nil
}

func independentRBDFTBodyReader(encoded []byte, recordType byte) (*independentRBDFTReader, error) {
	magic := []byte("LCPDTE-RBDFT-v1\x00")
	if len(encoded) < len(magic)+2 || !bytes.Equal(encoded[:len(magic)], magic) {
		return nil, errors.New("RBDFT magic is missing or truncated")
	}
	if encoded[len(magic)] != recordType || encoded[len(magic)+1] != 0 {
		return nil, fmt.Errorf("RBDFT header is type=%#x role=%#x, want type=%#x role=0", encoded[len(magic)], encoded[len(magic)+1], recordType)
	}
	return &independentRBDFTReader{data: encoded[len(magic)+2:]}, nil
}

func independentReadRBDFTTuple(reader *independentRBDFTReader) (independentRBDFTPayloadTuple, error) {
	digest, err := reader.digest()
	if err != nil {
		return independentRBDFTPayloadTuple{}, err
	}
	recordBytes, err := reader.u64()
	if err != nil {
		return independentRBDFTPayloadTuple{}, err
	}
	if digest == (RBAUTHDigest{}) || recordBytes == 0 {
		return independentRBDFTPayloadTuple{}, errors.New("RBDFT payload tuple is empty")
	}
	return independentRBDFTPayloadTuple{digest: digest, recordBytes: recordBytes}, nil
}

func independentParseRBDFTPair(encoded []byte) (independentRBDFTPair, error) {
	reader, err := independentRBDFTBodyReader(encoded, 0x05)
	if err != nil {
		return independentRBDFTPair{}, err
	}
	var value independentRBDFTPair
	if value.buildPermitDigest, err = reader.digest(); err != nil {
		return independentRBDFTPair{}, err
	}
	for _, target := range []*independentRBDFTPayloadTuple{
		&value.stcNumeric, &value.stcEncoded, &value.ctsNumeric, &value.ctsEncoded,
	} {
		if *target, err = independentReadRBDFTTuple(reader); err != nil {
			return independentRBDFTPair{}, err
		}
	}
	if value.buildPermitDigest == (RBAUTHDigest{}) {
		return independentRBDFTPair{}, errors.New("RBDFT pair build-permit digest is zero")
	}
	if err = reader.finish(); err != nil {
		return independentRBDFTPair{}, err
	}
	return value, nil
}

func independentParseRBDFTReceipt(encoded []byte) (independentRBDFTReceipt, error) {
	reader, err := independentRBDFTBodyReader(encoded, 0x07)
	if err != nil {
		return independentRBDFTReceipt{}, err
	}
	var value independentRBDFTReceipt
	if value.buildPermitDigest, err = reader.digest(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	if value.preparedParameterDigest, err = reader.digest(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	for _, target := range []*string{
		&value.builderID, &value.digestID, &value.allocationID, &value.releaseID, &value.ownershipID,
	} {
		if *target, err = reader.string(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	for _, target := range []*uint32{&value.generatorPrecision, &value.encoderPrecision} {
		if *target, err = reader.u32(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	for _, target := range []*uint64{
		&value.defaultCounterDelta, &value.explicitCounterDelta,
		&value.rawNumericCounterDelta, &value.observedCounterDelta,
	} {
		if *target, err = reader.u64(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	if value.lifecycleDigest, err = reader.digest(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	for _, target := range []*uint32{&value.maxLiveNumeric, &value.stcFactorCount, &value.ctsFactorCount} {
		if *target, err = reader.u32(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	for _, target := range []*independentRBDFTPayloadTuple{
		&value.stcNumeric, &value.stcEncoded, &value.ctsNumeric, &value.ctsEncoded,
	} {
		if target.digest, err = reader.digest(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	for _, target := range []*independentRBDFTPayloadTuple{
		&value.stcNumeric, &value.stcEncoded, &value.ctsNumeric, &value.ctsEncoded,
	} {
		if target.recordBytes, err = reader.u64(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	for _, target := range []*uint64{&value.buildWallNanoseconds, &value.buildPeakRSSBytes} {
		if *target, err = reader.u64(); err != nil {
			return independentRBDFTReceipt{}, err
		}
	}
	if value.artifactState, err = reader.string(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	if value.artifactManifestDigest, err = reader.digest(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	if err = reader.finish(); err != nil {
		return independentRBDFTReceipt{}, err
	}
	return value, nil
}

func independentRBDFTTupleFromRBAUTH(value RBAUTHPayloadTuple) independentRBDFTPayloadTuple {
	return independentRBDFTPayloadTuple{digest: value.AggregateDigest, recordBytes: value.RecordBytes}
}

func independentValidateRBDFTReadyLinks(
	receiptRecord, pairRecord []byte,
	expectedBuildPermitDigest, expectedPreparedParameterDigest RBAUTHDigest,
	expectedPayload RBAUTHActualPayload,
) error {
	pair, err := independentParseRBDFTPair(pairRecord)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	receipt, err := independentParseRBDFTReceipt(receiptRecord)
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	expectedTuples := [4]independentRBDFTPayloadTuple{
		independentRBDFTTupleFromRBAUTH(expectedPayload.STCNumeric),
		independentRBDFTTupleFromRBAUTH(expectedPayload.STCEncoded),
		independentRBDFTTupleFromRBAUTH(expectedPayload.CTSNumeric),
		independentRBDFTTupleFromRBAUTH(expectedPayload.CTSEncoded),
	}
	pairTuples := [4]independentRBDFTPayloadTuple{pair.stcNumeric, pair.stcEncoded, pair.ctsNumeric, pair.ctsEncoded}
	receiptTuples := [4]independentRBDFTPayloadTuple{receipt.stcNumeric, receipt.stcEncoded, receipt.ctsNumeric, receipt.ctsEncoded}
	manifest := RBAUTHDigest(sha256.Sum256(pairRecord))
	if pair.buildPermitDigest != expectedBuildPermitDigest || receipt.buildPermitDigest != expectedBuildPermitDigest {
		return errors.New("RBDFT records do not bind the expected build permit")
	}
	if receipt.preparedParameterDigest != expectedPreparedParameterDigest {
		return errors.New("RBDFT receipt does not bind the expected prepared parameters")
	}
	if pairTuples != expectedTuples || receiptTuples != expectedTuples || pairTuples != receiptTuples {
		return errors.New("RBDFT payload tuples changed role, order, digest, or byte count")
	}
	if receipt.builderID != independentRBDFTBuilderID || receipt.digestID != independentRBDFTDigestID ||
		receipt.allocationID != independentRBDFTAllocationID || receipt.releaseID != independentRBDFTReleaseID ||
		receipt.ownershipID != independentRBDFTOwnershipID {
		return errors.New("RBDFT receipt identifier or identifier order changed")
	}
	if receipt.generatorPrecision != 256 || receipt.encoderPrecision != 256 ||
		receipt.defaultCounterDelta != 0 || receipt.explicitCounterDelta != 0 ||
		receipt.rawNumericCounterDelta != 0 || receipt.observedCounterDelta != 2 ||
		receipt.maxLiveNumeric != 1 || receipt.stcFactorCount != 2 || receipt.ctsFactorCount != 3 {
		return errors.New("RBDFT receipt precision, counter, liveness, or factor-count contract changed")
	}
	// This pure-wire fixture only requires the lifecycle-digest field to be
	// present. It does not carry or validate the private lifecycle anchor.
	if receipt.lifecycleDigest == (RBAUTHDigest{}) || receipt.buildWallNanoseconds == 0 || receipt.buildPeakRSSBytes == 0 {
		return errors.New("RBDFT wire-fixture receipt fields are empty")
	}
	if receipt.artifactState != independentRBDFTArtifactState || receipt.artifactManifestDigest != manifest {
		return errors.New("RBDFT receipt artifact state or pair-manifest link changed")
	}
	return nil
}

func independentAuthorizeRBDFTReady(
	ready ReadySpec,
	receiptRecord, pairRecord []byte,
	expectedBuildPermitDigest, expectedPreparedParameterDigest RBAUTHDigest,
) error {
	if err := independentValidateRBDFTReadyLinks(
		receiptRecord,
		pairRecord,
		expectedBuildPermitDigest,
		expectedPreparedParameterDigest,
		ready.ActualPayload,
	); err != nil {
		return err
	}
	if ready.BuildPermitDigest != expectedBuildPermitDigest ||
		ready.PreparedParameterDigest != expectedPreparedParameterDigest ||
		ready.ArtifactState != independentRBDFTArtifactState {
		return errors.New("ReadySpec does not bind the expected RBDFT authority or artifact state")
	}
	receiptDigest := RBAUTHDigest(sha256.Sum256(receiptRecord))
	pairDigest := RBAUTHDigest(sha256.Sum256(pairRecord))
	if ready.BuildReceiptDigest != receiptDigest || ready.ArtifactPairManifestDigest != pairDigest {
		return errors.New("ReadySpec does not bind the fully validated RBDFT records")
	}
	return nil
}

func independentSwapFirstTwoRBDFTReceiptStrings(t *testing.T, record []byte) []byte {
	t.Helper()
	headerBytes := len("LCPDTE-RBDFT-v1\x00") + 2
	firstStart := headerBytes + 2*sha256.Size
	if firstStart+4 > len(record) {
		t.Fatal("RBDFT receipt fixture is too short for its first identifier")
	}
	firstEnd := firstStart + 4 + int(binary.LittleEndian.Uint32(record[firstStart:]))
	if firstEnd+4 > len(record) {
		t.Fatal("RBDFT receipt fixture is too short for its second identifier")
	}
	secondEnd := firstEnd + 4 + int(binary.LittleEndian.Uint32(record[firstEnd:]))
	if secondEnd > len(record) {
		t.Fatal("RBDFT receipt fixture has a truncated second identifier")
	}
	result := append([]byte(nil), record[:firstStart]...)
	result = append(result, record[firstEnd:secondEnd]...)
	result = append(result, record[firstStart:firstEnd]...)
	result = append(result, record[secondEnd:]...)
	return result
}

func valueCopyCapacity(value RBAUTHCapacityBinding) RBAUTHCapacityBinding { return value }

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[2*index], result[2*index+1] = alphabet[current>>4], alphabet[current&0x0f]
	}
	return string(result)
}

func independentWriteClassification(buffer *bytes.Buffer, value RBAUTHClassification) {
	independentWriteString(buffer, value.AdaptationLabel)
	independentWriteString(buffer, value.EvidenceScope)
	independentWriteString(buffer, value.Maturity)
	if value.SourceFaithful {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}
	if value.FullPacked {
		buffer.WriteByte(1)
	} else {
		buffer.WriteByte(0)
	}
}

func independentWriteCapacity(buffer *bytes.Buffer, value RBAUTHCapacityBinding) {
	independentWriteString(buffer, value.SnapshotID)
	independentWriteUint64(buffer, value.TotalPhysicalBytes)
	independentWriteUint64(buffer, value.AvailablePhysicalBytes)
	for _, digest := range []RBAUTHDigest{
		value.CapacityPlanDigest, value.CapacityProbeDigest, value.CapacityReportDigest,
		value.CapacityPermitDigest, value.ParameterDigest, value.ProfileDigest,
		value.ShapeDigest, value.PolicyDigest,
	} {
		independentWriteDigest(buffer, digest)
	}
}

func independentWriteScratch(buffer *bytes.Buffer, value RBAUTHScratchLedger) {
	for _, field := range []uint64{
		value.RootsBytes, value.Pow5Bytes, value.ABCLayerBytes,
		value.LargestSTCNumericFactorBytes, value.LargestCTSNumericFactorBytes,
		value.STCPhaseMaximumBytes, value.CTSPhaseMaximumBytes,
		value.ArtifactEnvelopeBytes, value.RemainingEnvelopeBytes,
	} {
		independentWriteUint64(buffer, field)
	}
	independentWriteDigest(buffer, value.Digest)
}

func independentWritePeak(buffer *bytes.Buffer, value RBAUTHPeakContract) {
	for _, field := range []uint64{
		value.FullArtifactPeakBytes, value.PreGuardIncrementalPeakBytes,
		value.GuardedRequirementBytes, value.RemainingBelowLimitBytes,
		value.ForbiddenDuplicateDefaultBytes, value.DuplicateDefaultExcessBytes,
	} {
		independentWriteUint64(buffer, field)
	}
	independentWriteDigest(buffer, value.Digest)
}

func independentScratchDigest(value RBAUTHScratchLedger) RBAUTHDigest {
	var buffer bytes.Buffer
	buffer.WriteString("LCPDTE-RBAUTH-v1")
	buffer.WriteByte(0x83)
	independentWriteScratchFields(&buffer, value)
	return RBAUTHDigest(sha256.Sum256(buffer.Bytes()))
}

func independentWriteScratchFields(buffer *bytes.Buffer, value RBAUTHScratchLedger) {
	for _, field := range []uint64{
		value.RootsBytes, value.Pow5Bytes, value.ABCLayerBytes,
		value.LargestSTCNumericFactorBytes, value.LargestCTSNumericFactorBytes,
		value.STCPhaseMaximumBytes, value.CTSPhaseMaximumBytes,
		value.ArtifactEnvelopeBytes, value.RemainingEnvelopeBytes,
	} {
		independentWriteUint64(buffer, field)
	}
}

func independentPeakDigest(value RBAUTHPeakContract) RBAUTHDigest {
	var buffer bytes.Buffer
	buffer.WriteString("LCPDTE-RBAUTH-v1")
	buffer.WriteByte(0x84)
	for _, field := range []uint64{
		value.FullArtifactPeakBytes, value.PreGuardIncrementalPeakBytes,
		value.GuardedRequirementBytes, value.RemainingBelowLimitBytes,
		value.ForbiddenDuplicateDefaultBytes, value.DuplicateDefaultExcessBytes,
	} {
		independentWriteUint64(&buffer, field)
	}
	return RBAUTHDigest(sha256.Sum256(buffer.Bytes()))
}

func digestByte(value byte) (result RBAUTHDigest) {
	for index := range result {
		result[index] = value
	}
	return
}

func independentWriteString(buffer *bytes.Buffer, value string) {
	independentWriteUint32(buffer, uint32(len(value)))
	buffer.WriteString(value)
}
func independentWriteDigest(buffer *bytes.Buffer, value RBAUTHDigest) { buffer.Write(value[:]) }
func independentWriteUint32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	buffer.Write(encoded[:])
}
func independentWriteUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	buffer.Write(encoded[:])
}
