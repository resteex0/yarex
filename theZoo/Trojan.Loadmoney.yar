
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Loadmoney 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Loadmoney {
	meta: 
		 description= "Trojan_Loadmoney Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-30-43" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "6c42954257ef80cc72266400236ea63c"

	strings:

	
 		 $a1= "0(((Q(((Q(((Q(((Q(((Q(((Q(((Q(((Q(((Q(((Q" fullword ascii
		 $a2= "#http://crl.thawte.com/ThawtePCA.crl0" fullword ascii
		 $a3= "*http://cs-g2-crl.thawte.com/ThawteCSG2.crl0" fullword ascii
		 $a4= "InitializeCriticalSection" fullword ascii
		 $a5= "JJJ6FFF6EEE6EEE6EEE6EEE6EEE6EEE6EEE6EEE6EEE6DDD6III6AAA*" fullword ascii
		 $a6= "__mingwthr_remove_key_dtor" fullword ascii
		 $a7= "qppppppppppppppppppppppppppppppppq" fullword ascii
		 $a8= "SetUnhandledExceptionFilter" fullword ascii

		 $hex1= {2461313d2022302828}
		 $hex2= {2461323d2022236874}
		 $hex3= {2461333d20222a6874}
		 $hex4= {2461343d2022496e69}
		 $hex5= {2461353d20224a4a4a}
		 $hex6= {2461363d20225f5f6d}
		 $hex7= {2461373d2022717070}
		 $hex8= {2461383d2022536574}

	condition:
		1 of them
}
