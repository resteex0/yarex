
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_BotenaGo 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_BotenaGo {
	meta: 
		 description= "vx_underground2_BotenaGo Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-53-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "29cb03edd8b97afe1d3d95c0fc6fa249"

	strings:

	
 		 $a1= "go.itab.*internal/reflectlite.rtype,internal/reflectlite.Type" fullword ascii
		 $a2= "type..eq.vendor/golang.org/x/net/dns/dnsmessage.ResourceHeader" fullword ascii
		 $a3= "/usr/lib/golang/src/runtime/internal/sys/intrinsics_common.go" fullword ascii
		 $a4= "vendor/golang.org/x/net/dns/dnsmessage.(*AResource).GoString" fullword ascii
		 $a5= "vendor/golang.org/x/net/dns/dnsmessage.(*Builder).startCheck" fullword ascii
		 $a6= "vendor/golang.org/x/net/dns/dnsmessage.(*Builder).StartQuestions" fullword ascii
		 $a7= "vendor/golang.org/x/net/dns/dnsmessage.errTooManyAdditionals" fullword ascii
		 $a8= "vendor/golang.org/x/net/dns/dnsmessage.errTooManyAuthorities" fullword ascii
		 $a9= "vendor/golang.org/x/net/dns/dnsmessage.(*Name).unpackCompressed" fullword ascii
		 $a10= "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).AnswerHeader" fullword ascii
		 $a11= "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).checkAdvance" fullword ascii
		 $a12= "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).resourceHeader" fullword ascii
		 $a13= "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).SkipQuestion" fullword ascii
		 $a14= "vendor/golang.org/x/net/dns/dnsmessage.(*Parser).skipResource" fullword ascii
		 $a15= "vendor/golang.org/x/net/dns/dnsmessage.(*ResourceHeader).unpack" fullword ascii

		 $hex1= {246131303d20227665}
		 $hex2= {246131313d20227665}
		 $hex3= {246131323d20227665}
		 $hex4= {246131333d20227665}
		 $hex5= {246131343d20227665}
		 $hex6= {246131353d20227665}
		 $hex7= {2461313d2022676f2e}
		 $hex8= {2461323d2022747970}
		 $hex9= {2461333d20222f7573}
		 $hex10= {2461343d202276656e}
		 $hex11= {2461353d202276656e}
		 $hex12= {2461363d202276656e}
		 $hex13= {2461373d202276656e}
		 $hex14= {2461383d202276656e}
		 $hex15= {2461393d202276656e}

	condition:
		10 of them
}
