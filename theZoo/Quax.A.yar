
/*
   YARA Rule Set
   Author: resteex
   Identifier: Quax_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Quax_A {
	meta: 
		 description= "Quax_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-25" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "50a572e94c69b0644576519b182f67dd"
		 hash2= "ba02f4502d6ca67ea5033aebce28a36d"

	strings:

	
 		 $a1= "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" fullword ascii
		 $a2= "!%)-159=AEJBFJNRVZ^beMQUY]`" fullword ascii
		 $a3= "#'+/37;?CGKOSW[_cgkosw{~A" fullword ascii
		 $a4= "579;=?ACEGIKMOQSUWY[]_acef" fullword ascii
		 $a5= "579;=?ACEGIKMOQSUWY[]__cef" fullword ascii
		 $a6= "/=/>/?/@/A/B/C/D/E/F/G/H/I/J/" fullword ascii
		 $a7= "^/_/`/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/" fullword ascii
		 $a8= "-=->-?-@-A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-" fullword ascii
		 $a9= "@BDFHJLNPRUXYP^`bdfhjlnpruXg" fullword ascii
		 $a10= "defghijklmnopqrstuvwxyz{|}~" fullword ascii
		 $a11= "L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z/[//" fullword ascii

		 $hex1= {246131303d20226465}
		 $hex2= {246131313d20224c2f}
		 $hex3= {2461313d2022404040}
		 $hex4= {2461323d2022212529}
		 $hex5= {2461333d202223272b}
		 $hex6= {2461343d2022353739}
		 $hex7= {2461353d2022353739}
		 $hex8= {2461363d20222f3d2f}
		 $hex9= {2461373d20225e2f5f}
		 $hex10= {2461383d20222d3d2d}
		 $hex11= {2461393d2022404244}

	condition:
		1 of them
}
