
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_WM_Npad_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_WM_Npad_A {
	meta: 
		 description= "theZoo_WM_Npad_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-37-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "23d06213fe8c8e879261f4b630810b2b"
		 hash2= "37c36a83e92e891b997c11be555bb340"
		 hash3= "d61298291ae55b2596b961db659b1add"
		 hash4= "ecd53cc45d19c02f5782e096b2590d6d"

	strings:

	
 		 $s1= "DocumentSummaryInformation" fullword wide
		 $a1= "mQBtAzKH0rYAAAEDAL0VC29QvNER+LBp+ov1OBce8lrLwli8aHNQYq6aFA+cyVOq" fullword ascii
		 $a2= "xc61IDBsi/37AaNmV1/eczN8sX2UAMVCTnLxHtMsWHky67Ct0/9NcMBtu283vaWo" fullword ascii

		 $hex1= {2461313d20226d5142}
		 $hex2= {2461323d2022786336}
		 $hex3= {2473313d2022446f63}

	condition:
		2 of them
}
