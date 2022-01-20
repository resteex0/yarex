
/*
   YARA Rule Set
   Author: resteex
   Identifier: VBS_LoveLetter 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_VBS_LoveLetter {
	meta: 
		 description= "VBS_LoveLetter Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "072b90a954bb9349a8871fa749165596"
		 hash2= "7812042921729e8f20dc3950ea52534a"
		 hash3= "836a5abd025d60a7aa8550679dd556c9"
		 hash4= "e8f103dc1620e8b310c244d38ad24dd7"

	strings:

	
 		 $a1= "dim fso,dirsystem,dirwin,dirtemp,eq,ctr,file,vbscopy,dow" fullword ascii
		 $a2= "dim x,a,ctrlists,ctrentries,malead,b,regedit,regv,regad" fullword ascii
		 $a3= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunMSKernel32" fullword ascii
		 $a4= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunWIN-BUGSFIX" fullword ascii
		 $a5= "http://vil.nai.com/villib/dispVirus.asp?virus_k=98617 " fullword ascii
		 $a6= "http://www.cert.org/advisories/CA-2000-04/nai.dat " fullword ascii
		 $a7= "http://www.cert.org/tech_tips/malicious_code_FAQ.html#steps " fullword ascii
		 $a8= "http://www.f-secure.com/download-purchase/updates.html " fullword ascii
		 $a9= "http://www.pspl.com/virus_info/worms/loveletter.htm " fullword ascii
		 $a10= "http://www.sophos.com/virusinfo/analyses/trojloveleta.html " fullword ascii
		 $a11= "http://www.sophos.com/virusinfo/analyses/vbsloveleta.html " fullword ascii

		 $hex1= {246131303d20226874}
		 $hex2= {246131313d20226874}
		 $hex3= {2461313d202264696d}
		 $hex4= {2461323d202264696d}
		 $hex5= {2461333d2022484b4c}
		 $hex6= {2461343d2022484b4c}
		 $hex7= {2461353d2022687474}
		 $hex8= {2461363d2022687474}
		 $hex9= {2461373d2022687474}
		 $hex10= {2461383d2022687474}
		 $hex11= {2461393d2022687474}

	condition:
		7 of them
}
