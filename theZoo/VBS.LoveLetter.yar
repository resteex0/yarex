
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
		 date = "2022-01-10_19-30-56" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "072b90a954bb9349a8871fa749165596"
		 hash2= "7812042921729e8f20dc3950ea52534a"
		 hash3= "836a5abd025d60a7aa8550679dd556c9"
		 hash4= "e8f103dc1620e8b310c244d38ad24dd7"

	strings:

	
 		 $a1= "--------------------------------------------------------------------------------" fullword ascii
		 $a2= "att.attributes=att.attributes+2" fullword ascii
		 $a3= "bname=fso.GetBaseName(f1.path)" fullword ascii
		 $a4= "ext=fso.GetExtensionName(f1.path)" fullword ascii
		 $a5= "header-stop-viruses.gifPK" fullword ascii
		 $a6= "HKCUSoftwareMicrosoftWAB*" fullword ascii
		 $a7= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunMSKernel32" fullword ascii
		 $a8= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunServicesWin32DLL" fullword ascii
		 $a9= "HKLMSoftwareMicrosoftWindowsCurrentVersionRunWIN-BUGSFIX" fullword ascii
		 $a10= "investor_relations.gifGIF89a" fullword ascii
		 $a11= "lines(n)=chr(34)+lines(n)+chr(34)" fullword ascii
		 $a12= "lines=Split(c.ReadAll,vbcrlf)" fullword ascii
		 $a13= "malead=a.AddressEntries(x)" fullword ascii
		 $a14= "male.Recipients.Add(malead)" fullword ascii
		 $a15= "regget=regedit.RegRead(value)" fullword ascii

		 $hex1= {246131303d2022696e}
		 $hex2= {246131313d20226c69}
		 $hex3= {246131323d20226c69}
		 $hex4= {246131333d20226d61}
		 $hex5= {246131343d20226d61}
		 $hex6= {246131353d20227265}
		 $hex7= {2461313d20222d2d2d}
		 $hex8= {2461323d2022617474}
		 $hex9= {2461333d2022626e61}
		 $hex10= {2461343d2022657874}
		 $hex11= {2461353d2022686561}
		 $hex12= {2461363d2022484b43}
		 $hex13= {2461373d2022484b4c}
		 $hex14= {2461383d2022484b4c}
		 $hex15= {2461393d2022484b4c}

	condition:
		1 of them
}
