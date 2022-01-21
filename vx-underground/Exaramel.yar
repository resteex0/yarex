
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Exaramel 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Exaramel {
	meta: 
		 description= "vx_underground2_Exaramel Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-56-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8eff45383a7a0c6e3ea6d526a599610d"

	strings:

	
 		 $s1= "!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13!#%')+-/13" fullword wide
		 $a1= "app/vendor/github.com/satori/go%2euuid.(*UUID).UnmarshalText" fullword ascii
		 $a2= "func(*vendor/golang_org/x/text/unicode/norm.reorderBuffer) bool" fullword ascii
		 $a3= "go.itab.*app/vendor/cron.SpecSchedule,app/vendor/cron.Schedule" fullword ascii
		 $a4= "go.itab.*crypto/tls.certificateMsg,crypto/tls.handshakeMessage" fullword ascii
		 $a5= "go.itab.*crypto/tls.clientHelloMsg,crypto/tls.handshakeMessage" fullword ascii
		 $a6= "go.itab.*crypto/tls.ecdheKeyAgreement,crypto/tls.keyAgreement" fullword ascii
		 $a7= "go.itab.*crypto/tls.helloRequestMsg,crypto/tls.handshakeMessage" fullword ascii
		 $a8= "go.itab.*crypto/tls.nextProtoMsg,crypto/tls.handshakeMessage" fullword ascii
		 $a9= "go.itab.*crypto/tls.serverHelloMsg,crypto/tls.handshakeMessage" fullword ascii
		 $a10= "go.itab.*net/http.http2ContinuationFrame,net/http.http2Frame" fullword ascii
		 $a11= "go.itab.net/http.http2erringRoundTripper,net/http.RoundTripper" fullword ascii
		 $a12= "go.itab.net/http.http2noDialH2RoundTripper,net/http.RoundTripper" fullword ascii
		 $a13= "go.itab.*net/http.http2WindowUpdateFrame,net/http.http2Frame" fullword ascii
		 $a14= "go.itab.vendor/golang_org/x/net/http2/hpack.DecodingError,error" fullword ascii
		 $a15= "net/http.connectMethodKey,chan *net/http.persistConn>" fullword ascii
		 $a16= "net/http.http2FrameType,map[net/http.http2Flags]string>" fullword ascii
		 $a17= "net/http.(*Transport).(net/http.onceSetNextProtoDefaults)-fm" fullword ascii
		 $a18= "type..eq.[61]vendor/golang_org/x/net/http2/hpack.HeaderField" fullword ascii
		 $a19= "type..hash.[61]vendor/golang_org/x/net/http2/hpack.HeaderField" fullword ascii
		 $a20= "/usr/lib/go-1.8/src/crypto/internal/cipherhw/cipherhw_amd64.go" fullword ascii
		 $a21= "/usr/lib/go-1.8/src/internal/syscall/unix/getrandom_linux.go" fullword ascii
		 $a22= "/usr/lib/go-1.8/src/vendor/golang_org/x/crypto/curve25519/doc.go" fullword ascii
		 $a23= "/usr/lib/go-1.8/src/vendor/golang_org/x/net/http2/hpack/hpack.go" fullword ascii
		 $a24= "/usr/lib/go-1.8/src/vendor/golang_org/x/net/idna/punycode.go" fullword ascii
		 $a25= "/usr/lib/go-1.8/src/vendor/golang_org/x/text/width/tables.go" fullword ascii
		 $a26= "/usr/lib/go-1.8/src/vendor/golang_org/x/text/width/transform.go" fullword ascii
		 $a27= "vendor/golang_org/x/crypto/chacha20poly1305.chacha20Constants" fullword ascii
		 $a28= "*vendor/golang_org/x/crypto/chacha20poly1305.chacha20poly1305" fullword ascii
		 $a29= "vendor/golang_org/x/crypto/chacha20poly1305.chacha20poly1305" fullword ascii
		 $a30= "vendor/golang_org/x/crypto/chacha20poly1305.chacha20Poly1305Open" fullword ascii
		 $a31= "vendor/golang_org/x/crypto/chacha20poly1305.chacha20Poly1305Seal" fullword ascii
		 $a32= "vendor/golang_org/x/crypto/curve25519.ladderstep.args_stackmap" fullword ascii
		 $a33= "vendor/golang_org/x/net/http2/hpack.constantTimeStringCompare" fullword ascii
		 $a34= "vendor/golang_org/x/net/http2/hpack.(*Decoder).parseFieldIndexed" fullword ascii
		 $a35= "vendor/golang_org/x/net/http2/hpack.(*Decoder).parseFieldLiteral" fullword ascii
		 $a36= "vendor/golang_org/x/net/http2/hpack.(*dynamicTable).setMaxSize" fullword ascii
		 $a37= "vendor/golang_org/x/net/http2/hpack.(*InvalidIndexError).Error" fullword ascii
		 $a38= "vendor/golang_org/x/net/lex/httplex.headerValueContainsToken" fullword ascii
		 $a39= "vendor/golang_org/x/net/lex/httplex.HeaderValuesContainsToken" fullword ascii
		 $a40= "vendor/golang_org/x/text/unicode/norm.(*nfcTrie).lookupString" fullword ascii
		 $a41= "vendor/golang_org/x/text/unicode/norm.(*nfcTrie).lookupValue" fullword ascii
		 $a42= "vendor/golang_org/x/text/unicode/norm.(*nfkcTrie).lookupString" fullword ascii
		 $a43= "vendor/golang_org/x/text/unicode/norm.(*nfkcTrie).lookupValue" fullword ascii
		 $a44= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).compose" fullword ascii
		 $a45= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).doFlush" fullword ascii
		 $a46= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).flushCopy" fullword ascii
		 $a47= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).insertCGJ" fullword ascii
		 $a48= "vendor/golang_org/x/text/unicode/norm.(*reorderBuffer).runeAt" fullword ascii
		 $a49= "vendor/golang_org/x/text/unicode/norm.(*sparseBlocks).lookup" fullword ascii

		 $hex1= {246131303d2022676f}
		 $hex2= {246131313d2022676f}
		 $hex3= {246131323d2022676f}
		 $hex4= {246131333d2022676f}
		 $hex5= {246131343d2022676f}
		 $hex6= {246131353d20226e65}
		 $hex7= {246131363d20226e65}
		 $hex8= {246131373d20226e65}
		 $hex9= {246131383d20227479}
		 $hex10= {246131393d20227479}
		 $hex11= {2461313d2022617070}
		 $hex12= {246132303d20222f75}
		 $hex13= {246132313d20222f75}
		 $hex14= {246132323d20222f75}
		 $hex15= {246132333d20222f75}
		 $hex16= {246132343d20222f75}
		 $hex17= {246132353d20222f75}
		 $hex18= {246132363d20222f75}
		 $hex19= {246132373d20227665}
		 $hex20= {246132383d20222a76}
		 $hex21= {246132393d20227665}
		 $hex22= {2461323d202266756e}
		 $hex23= {246133303d20227665}
		 $hex24= {246133313d20227665}
		 $hex25= {246133323d20227665}
		 $hex26= {246133333d20227665}
		 $hex27= {246133343d20227665}
		 $hex28= {246133353d20227665}
		 $hex29= {246133363d20227665}
		 $hex30= {246133373d20227665}
		 $hex31= {246133383d20227665}
		 $hex32= {246133393d20227665}
		 $hex33= {2461333d2022676f2e}
		 $hex34= {246134303d20227665}
		 $hex35= {246134313d20227665}
		 $hex36= {246134323d20227665}
		 $hex37= {246134333d20227665}
		 $hex38= {246134343d20227665}
		 $hex39= {246134353d20227665}
		 $hex40= {246134363d20227665}
		 $hex41= {246134373d20227665}
		 $hex42= {246134383d20227665}
		 $hex43= {246134393d20227665}
		 $hex44= {2461343d2022676f2e}
		 $hex45= {2461353d2022676f2e}
		 $hex46= {2461363d2022676f2e}
		 $hex47= {2461373d2022676f2e}
		 $hex48= {2461383d2022676f2e}
		 $hex49= {2461393d2022676f2e}
		 $hex50= {2473313d2022212325}

	condition:
		33 of them
}
