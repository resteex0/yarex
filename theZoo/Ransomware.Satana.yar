
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Satana 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Satana {
	meta: 
		 description= "Ransomware_Satana Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-17" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "108756f41d114eb93e136ba2feb838d0"
		 hash2= "46bfd4f1d581d7c0121d2b19a005d3df"

	strings:

	
 		 $a1= "}Z]@]$UX]N79Gp]4USZ[G@]W4y[PQqZUV0XQ6KgQ@uG4GQF@rXUS6G0%ADx[Sy" fullword ascii

		 $hex1= {2461313d20227d5a5d}

	condition:
		0 of them
}
