
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_ZeusVM 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_ZeusVM {
	meta: 
		 description= "Win32_ZeusVM Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-35-22" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "34875dcb19479c5df2b059cc967b76e7"
		 hash2= "8a0c95be8a40ae5419f7d97bb3e91b2b"

	strings:

	
 		 $s1= "Adobe Photoshop" fullword wide
		 $s2= "Adobe Photoshop CS4" fullword wide
		 $s3= "LICENSEDLG RENAMEDLG" fullword wide
		 $s4= "Rihanna-Millionen-verschwendet" fullword wide
		 $a1= "!22222222222222222222222222222222222222222222222222" fullword ascii
		 $a2= "%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz" fullword ascii
		 $a3= "&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz" fullword ascii
		 $a4= "aaaaaaaaaaaaaaaaaaaaf~leQmux" fullword ascii
		 $a5= "''''''''''''''''''DaJKHPam" fullword ascii
		 $a6= "JJJJJJJJJJJJJJJJJJJaieQRamu" fullword ascii

		 $hex1= {2461313d2022213232}
		 $hex2= {2461323d2022252627}
		 $hex3= {2461333d2022262728}
		 $hex4= {2461343d2022616161}
		 $hex5= {2461353d2022272727}
		 $hex6= {2461363d20224a4a4a}
		 $hex7= {2473313d202241646f}
		 $hex8= {2473323d202241646f}
		 $hex9= {2473333d20224c4943}
		 $hex10= {2473343d2022526968}

	condition:
		1 of them
}
