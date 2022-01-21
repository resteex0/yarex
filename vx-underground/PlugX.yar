
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_PlugX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_PlugX {
	meta: 
		 description= "vx_underground2_PlugX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-36" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "142c996adaea6de8ed611b36234dd22f"
		 hash2= "142dd8beb167fbe9c20f4a0764e74477"
		 hash3= "1686e7089dbd4c533744372f78b3928d"
		 hash4= "1778bfb4bb39e09c2849499c1a7cfe0a"
		 hash5= "2395693481ea36feb66dac46da374eef"
		 hash6= "2be7e7d330347976bfabc54cdda71a37"
		 hash7= "2df77d71a5cfaf228d57690772a8342b"
		 hash8= "2e0262bb45fa553cc3929b4cc32e7581"
		 hash9= "34759f8055257be08e02a4ddca74d3ec"
		 hash10= "38e35c5f140f802c70c974edadbbf63c"
		 hash11= "3a70a7af3bd6fc92f76efaa6a14f3bf4"
		 hash12= "3c7e67fe058d59624bcac401bd071fa1"
		 hash13= "460b26fcc28f25e1ed00dc04680f6311"
		 hash14= "4c184b9f897999b4daa4fbe2b023292e"
		 hash15= "4ce325995895f1511f1f3abc15cf2124"
		 hash16= "52c1150cd63b124cac7f8fef5e569849"
		 hash17= "52d116f11dd9117ffd3f067a28acbfb2"
		 hash18= "55075529bf97185ca7f72c719988ac11"
		 hash19= "677c925ff35a226a2c9a562a69f0fd8f"
		 hash20= "6a09c8d0b5497e4fa9bb4f62c8c77ffd"
		 hash21= "6b1b0d01279c4e976eb69cbb1d264a83"
		 hash22= "7048add2873b08a9693a60135f978686"
		 hash23= "7160b0d2d5d1e565adc53f6731a202f4"
		 hash24= "74301837c857f1f38348da87dd2b18b7"
		 hash25= "78a9897344d756701d4674c7f559610a"
		 hash26= "8173ed653ad5d78027363185e354c5a8"
		 hash27= "83d92d7f69b054e8d2508d2f10a1a195"
		 hash28= "9056cf50f74bc4f695d178c80ad19275"
		 hash29= "9aceefb76c2e227c651ef6a035461b5c"
		 hash30= "a1c0c364e02b3b1e0e7b8ce89b611b53"
		 hash31= "a30262bf36b3023ef717b6e23e21bd30"
		 hash32= "b2275c113143c6a3f2dbe92599642ad0"
		 hash33= "b44d492a5d772ae964d2e791507cbd24"
		 hash34= "bd7fa7161c471df73865b8bc20eb8439"
		 hash35= "c824cb1c177c548c533879840bd8851c"
		 hash36= "cb0f926b00981dbc2d1b92e91760e017"
		 hash37= "d055518ad14f3d6c40aa6ced6a2d05f2"
		 hash38= "d0c5410140c15c8d148437f0f7eabcf7"
		 hash39= "d376f29dc8a1c6fd4b8849c9d57e3e03"
		 hash40= "d4375582ff56ea9d15f0b0a012f35648"
		 hash41= "d8b17a6f71621259d8e8e84d590d1864"
		 hash42= "e11283c8b67e008cfb5abcaca355d2f8"
		 hash43= "e2eddf6e7233ab52ad29d8f63b1727cd"
		 hash44= "e5a4c395d3de47fb4efc3c39b0e96bd6"
		 hash45= "ecaafedebdfa5d8ea3fc302a39da52cf"
		 hash46= "eeb631127f1b9fb3d13d209d8e675634"
		 hash47= "efc847ac17603a4c83d4b4a816bf75c7"
		 hash48= "f4572c1ab751929fc2dd88b344fe8f7e"

	strings:

	
 		 $s1= "CryptProtectMemory failed" fullword wide
		 $s2= "CryptUnprotectMemory failed" fullword wide
		 $s3= "C:WindowsSystem32sysprepCRYPTBASE.dll" fullword wide
		 $s4= "C:WindowsSystem32sysprepsysprep.exe" fullword wide
		 $s5= "DocumentSummaryInformation" fullword wide
		 $s6= "SeCreateSymbolicLinkPrivilege" fullword wide
		 $s7= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s8= "tC:WindowsSystem32sysprep" fullword wide
		 $s9= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s10= "Win7Elevate proof-of-concept" fullword wide
		 $a1= "http://www.moi.gov.mm/mmpdd/sites/default/files/field/moigov.exe" fullword ascii

		 $hex1= {2461313d2022687474}
		 $hex2= {247331303d20225769}
		 $hex3= {2473313d2022437279}
		 $hex4= {2473323d2022437279}
		 $hex5= {2473333d2022433a57}
		 $hex6= {2473343d2022433a57}
		 $hex7= {2473353d2022446f63}
		 $hex8= {2473363d2022536543}
		 $hex9= {2473373d2022536f66}
		 $hex10= {2473383d202274433a}
		 $hex11= {2473393d20225f5f74}

	condition:
		7 of them
}
