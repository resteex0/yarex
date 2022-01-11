
/*
   YARA Rule Set
   Author: resteex
   Identifier: Form_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Form_A {
	meta: 
		 description= "Form_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-26-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "5beb07a7017462830243f1a17b2e830e"
		 hash2= "6ba9389c1a77eef2f2bb4f0f19a44235"

	strings:

	
 		 $a1= "------------------------------------------------" fullword ascii
		 $a2= "%3ld%,7ld%6c%,7ld%6c%,7ld%6c" fullword ascii
		 $a3= "%-8c%,8ld%7c%,8ld%7c%,8ld%7c" fullword ascii
		 $a4= "%-8m%,8ld%7c%,8ld%7c%,8ld%7c" fullword ascii
		 $a5= "%-8m%,8ld%7c%,8ld%7c%,8ld%7cL" fullword ascii
		 $a6= ".COM.EXE.BAT-Y?VBAPWRHSvDANEDSGC" fullword ascii
		 $a7= "COUNTRY=044,,C:DOSCOUNTRY.SYS" fullword ascii
		 $a8= "COUNTRY=44,437,C:DOSCOUNTRY.SYS" fullword ascii
		 $a9= "DEVICEHIGH=c:lcsaspiaspi33d.sys" fullword ascii
		 $a10= "DEVICEHIGH=C:WINDOWSIFSHLP.SYS" fullword ascii
		 $a11= "/L:region1[,minsize1][;region2[,minsize2]]..." fullword ascii
		 $a12= "MZHvG`H`H`HjHvGjHjHjHjH^G" fullword ascii

		 $hex1= {246131303d20224445}
		 $hex2= {246131313d20222f4c}
		 $hex3= {246131323d20224d5a}
		 $hex4= {2461313d20222d2d2d}
		 $hex5= {2461323d202225336c}
		 $hex6= {2461333d2022252d38}
		 $hex7= {2461343d2022252d38}
		 $hex8= {2461353d2022252d38}
		 $hex9= {2461363d20222e434f}
		 $hex10= {2461373d2022434f55}
		 $hex11= {2461383d2022434f55}
		 $hex12= {2461393d2022444556}

	condition:
		1 of them
}
