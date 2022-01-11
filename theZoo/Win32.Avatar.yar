
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Avatar 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Avatar {
	meta: 
		 description= "Win32_Avatar Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-48" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "32d6644c5ea66e390070d3dc3401e54b"

	strings:

	
 		 $s1= "KernelObjects%SCondition`0000000000000" fullword wide
		 $s2= "%suxtheme.dll;%scryptbase.dll" fullword wide
		 $a1= "Global{%s}`000000000000000000000000000000001" fullword ascii
		 $a2= "Global{%s}`000000000000000000000000000000002" fullword ascii
		 $a3= "Global{%s}`000000000000000000000000000000003" fullword ascii
		 $a4= "Global{%s}`000000000000000000000000000000004" fullword ascii
		 $a5= "Global{%s}`000000000000000000000000000000005" fullword ascii
		 $a6= "Global{%s}`000000000000000000000000000000006" fullword ascii
		 $a7= "Global{%s}`000000000000000000000000000000007" fullword ascii
		 $a8= "Global{%s}`000000000000000000000000000000008" fullword ascii
		 $a9= "Global{%s}`000000000000000000000000000000009" fullword ascii
		 $a10= "Global{%s}`000000000000000000000000000000010" fullword ascii
		 $a11= "Global{%s}`000000000000000000000000000000011" fullword ascii
		 $a12= "Global{%s}`000000000000000000000000000000012" fullword ascii
		 $a13= "Global{%s}`000000000000000000000000000000013" fullword ascii
		 $a14= "Global{%s}`000000000000000000000000000000014" fullword ascii
		 $a15= "Global{%s}`000000000000000000000000000000015" fullword ascii
		 $a16= "Global{%s}`000000000000000000000000000000016" fullword ascii
		 $a17= "Global{%s}`000000000000000000000000000000017" fullword ascii

		 $hex1= {246131303d2022476c}
		 $hex2= {246131313d2022476c}
		 $hex3= {246131323d2022476c}
		 $hex4= {246131333d2022476c}
		 $hex5= {246131343d2022476c}
		 $hex6= {246131353d2022476c}
		 $hex7= {246131363d2022476c}
		 $hex8= {246131373d2022476c}
		 $hex9= {2461313d2022476c6f}
		 $hex10= {2461323d2022476c6f}
		 $hex11= {2461333d2022476c6f}
		 $hex12= {2461343d2022476c6f}
		 $hex13= {2461353d2022476c6f}
		 $hex14= {2461363d2022476c6f}
		 $hex15= {2461373d2022476c6f}
		 $hex16= {2461383d2022476c6f}
		 $hex17= {2461393d2022476c6f}
		 $hex18= {2473313d20224b6572}
		 $hex19= {2473323d2022257375}

	condition:
		2 of them
}
