
/*
   YARA Rule Set
   Author: resteex
   Identifier: CubaRansomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CubaRansomware {
	meta: 
		 description= "CubaRansomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_00-28-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3fe1a3aaca999a5db936843c9bdfea14"
		 hash2= "4c32ef0836a0af7025e97c6253054bca"
		 hash3= "72a60d799ae9e4f0a3443a2f96fb4896"
		 hash4= "75b55bb34dac9d02740b9ad6b6820360"
		 hash5= "7b6f996cc1ad4b5e131e7bf9b1c33253"
		 hash6= "99c7cad7032ec5add3a21582a64bb149"
		 hash7= "ba83831700a73661f99d38d7505b5646"
		 hash8= "c0451fd7921342e0d2fbf682091d4280"
		 hash9= "d907be57b5ef2af8a8b45d5f87aa4773"
		 hash10= "ee2f71faced3f5b5b202c7576f0f52b9"

	strings:

	
 		 $s1= "Aapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s2= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s3= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s4= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s5= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s6= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s7= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s8= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s9= "Microsoft.Exchange.Store.Worker.exe" fullword wide
		 $s10= "_SA_{262E99C9-6160-4871-ACEC-4E61736B6F21}" fullword wide
		 $s11= "SoftwareMicrosoftWindows NTCurrentVersionServerServerLevels" fullword wide
		 $s12= "U_i=V`j>Wak?Xbl@YcmAZdnB[eoCfpD]gq" fullword wide
		 $a1= "SoftwareMicrosoftWindows NTCurrentVersionServerServerLevels" fullword ascii

		 $hex1= {2461313d2022536f66}
		 $hex2= {247331303d20225f53}
		 $hex3= {247331313d2022536f}
		 $hex4= {247331323d2022555f}
		 $hex5= {2473313d2022416170}
		 $hex6= {2473323d2022617069}
		 $hex7= {2473333d2022617069}
		 $hex8= {2473343d2022617069}
		 $hex9= {2473353d2022617069}
		 $hex10= {2473363d2022617069}
		 $hex11= {2473373d2022657874}
		 $hex12= {2473383d2022657874}
		 $hex13= {2473393d20224d6963}

	condition:
		1 of them
}
