
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_HLLP_Hantaner_A 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_HLLP_Hantaner_A {
	meta: 
		 description= "W32_HLLP_Hantaner_A Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-08" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "22a5ba6d742cc41d150068e1f18f92d6"
		 hash2= "7b4c5557e985327361f8e2ca302e20ac"

	strings:

	
 		 $s1= ".A_files' is a directory" fullword wide
		 $s2= "iled: return from extract=%d" fullword wide
		 $s3= "InstallShield Self-extracting Exe" fullword wide
		 $s4= "!InstallShield Self-extracting EXE6Could not find enough disk space for extracting files.&Extract fa" fullword wide
		 $s5= "Please enter the password required to extract the attached files." fullword wide
		 $s6= "Please wait while InstallShield extracts the files which will install this application" fullword wide
		 $s7= "strings: Warning: 'theZoo/malware/Binaries/W32.HLLP.Hantaner.A/W32.HLLP.Hantaner.A/W32_HLLP_Hantaner" fullword wide
		 $a1= "4:4I4>55`5d5h5l5p5t5x5|5" fullword ascii
		 $a2= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a3= "/ SOFTWAREBorlandDelphiRTL" fullword ascii
		 $a4= "sStringToTrim=sStringToTrim.substring(0,sStringToTrim.length-1);" fullword ascii
		 $a5= "sStringToTrim=sStringToTrim.substring(1,sStringToTrim.length);" fullword ascii

		 $hex1= {2461313d2022343a34}
		 $hex2= {2461323d20224a616e}
		 $hex3= {2461333d20222f2053}
		 $hex4= {2461343d2022735374}
		 $hex5= {2461353d2022735374}
		 $hex6= {2473313d20222e415f}
		 $hex7= {2473323d2022696c65}
		 $hex8= {2473333d2022496e73}
		 $hex9= {2473343d202221496e}
		 $hex10= {2473353d2022506c65}
		 $hex11= {2473363d2022506c65}
		 $hex12= {2473373d2022737472}

	condition:
		1 of them
}
