
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_WannaCry 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_WannaCry {
	meta: 
		 description= "Ransomware_WannaCry Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-29-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "84c82835a5d21bbcf75a61706d8ab549"

	strings:

	
 		 $s1= "6.1.7601.17514 (win7sp1_rtm.101119-1850)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "Microsoft Corporation" fullword wide
		 $s4= "Microsoft Corporation. All rights reserved." fullword wide
		 $s5= "Operating System" fullword wide
		 $s6= "OriginalFilename" fullword wide
		 $s7= "VS_VERSION_INFO" fullword wide
		 $a1= "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE" fullword ascii
		 $a2= "??0exception@@QAE@ABQBD@Z" fullword ascii
		 $a3= "??0exception@@QAE@ABV0@@Z" fullword ascii
		 $a4= "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" fullword ascii
		 $a5= "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" fullword ascii
		 $a6= "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" fullword ascii
		 $a7= "4$8,9-6'.6$:#?*1hHpXeA~SrZlN" fullword ascii
		 $a8= ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE" fullword ascii
		 $a9= "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE" fullword ascii
		 $a10= "GlobalMsWinZonesCacheCounterMutexA" fullword ascii
		 $a11= "InitializeCriticalSection" fullword ascii

		 $hex1= {246131303d2022476c}
		 $hex2= {246131313d2022496e}
		 $hex3= {2461313d202224382c}
		 $hex4= {2461323d20223f3f30}
		 $hex5= {2461333d20223f3f30}
		 $hex6= {2461343d2022313135}
		 $hex7= {2461353d2022313274}
		 $hex8= {2461363d2022313341}
		 $hex9= {2461373d2022342438}
		 $hex10= {2461383d20222c3424}
		 $hex11= {2461393d2022382c34}
		 $hex12= {2473313d2022362e31}
		 $hex13= {2473323d202246696c}
		 $hex14= {2473333d20224d6963}
		 $hex15= {2473343d20224d6963}
		 $hex16= {2473353d20224f7065}
		 $hex17= {2473363d20224f7269}
		 $hex18= {2473373d202256535f}

	condition:
		2 of them
}
