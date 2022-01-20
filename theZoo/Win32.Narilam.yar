
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Narilam 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Narilam {
	meta: 
		 description= "Win32_Narilam Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-44-37" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8e63c306e95843eccab53dad31b3a98b"

	strings:

	
 		 $a1= "fnNEXT_DAY fnSYSDATE fnCONVERT fnTO_CHAR fnTO_DATE" fullword ascii
		 $a2= "ftReference ftDataSet ftOraBlob ftOraClob ftVariant" fullword ascii
		 $a3= "SystemCurrentControlSetControlKeyboard Layouts%.8x" fullword ascii
		 $a4= "T9X99`9d9h9l9|9" fullword ascii

		 $hex1= {2461313d2022666e4e}
		 $hex2= {2461323d2022667452}
		 $hex3= {2461333d2022537973}
		 $hex4= {2461343d2022543958}

	condition:
		2 of them
}
