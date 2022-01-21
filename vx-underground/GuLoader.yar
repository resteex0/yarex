
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_GuLoader 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_GuLoader {
	meta: 
		 description= "vx_underground2_GuLoader Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-59-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "25f7735ff71a70abf4bb508d2711f50b"
		 hash2= "597eff6540780213008d384ca831852a"
		 hash3= "b7cdda847140697b7bb7866b06d2a225"
		 hash4= "c6066a473750ed5ad023d20ce532c8c8"

	strings:

	
 		 $s1= "bJwKrGImpGgg9mRQCArwzZIt8" fullword wide
		 $s2= "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
		 $s3= "Microsoft.Container.DataSpaces" fullword wide
		 $s4= "Microsoft.Container.EncryptionTransform" fullword wide
		 $s5= "StrongEncryptionDataSpace" fullword wide
		 $s6= "StrongEncryptionTransform" fullword wide

		 $hex1= {2473313d2022624a77}
		 $hex2= {2473323d20227b4646}
		 $hex3= {2473333d20224d6963}
		 $hex4= {2473343d20224d6963}
		 $hex5= {2473353d2022537472}
		 $hex6= {2473363d2022537472}

	condition:
		4 of them
}
