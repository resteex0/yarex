
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
		 date = "2022-01-20_04-44-02" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "22a5ba6d742cc41d150068e1f18f92d6"
		 hash2= "7b4c5557e985327361f8e2ca302e20ac"

	strings:

	
 		 $a1= "document.ratethispage.virus_name.value= virus_name;" fullword ascii
		 $a2= "while(''+sStringToTrim.charAt(sStringToTrim.length-1)==' ')" fullword ascii

		 $hex1= {2461313d2022646f63}
		 $hex2= {2461323d2022776869}

	condition:
		1 of them
}
