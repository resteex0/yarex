
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Emotet 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Emotet {
	meta: 
		 description= "Win32_Emotet Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-12" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "8baa9b809b591a11af423824f4d9726a"

	strings:

	
 		 $s1= "5665778782565768827838" fullword wide
		 $s2= "57576736879580478257258376974939" fullword wide
		 $s3= "@*AC:Documents and Settings" fullword wide
		 $s4= "ar, southwest of Pag, southeast of Lo" fullword wide
		 $s5= "ecoration-color, and text-decoration-style, but this is currently." fullword wide
		 $s6= "FileDescription" fullword wide
		 $s7= "inj and just east of Silba" fullword wide
		 $s8= "Note: In CSS3, the text-decoration property is a shorthand property for text-decoration-line, text-d" fullword wide
		 $s9= "Olib (pronounced [??lib]; Italian: Ulbo) is an island in northern Dalmatia, located northwest of Zad" fullword wide
		 $s10= "OriginalFilename" fullword wide
		 $s11= "Remounter (2)RemounterVeladonACCOJ.vbp" fullword wide
		 $s12= "VS_VERSION_INFO" fullword wide
		 $a1= ",/.-++,()'*'-$#!1:>=?97=66:51=4?" fullword ascii
		 $a2= "3**455555555555555555555555555554678(" fullword ascii
		 $a3= ",,74``Q```````````````````Q67,+," fullword ascii
		 $a4= "_`aaabaaaaaaaaaaaaaaaaaabbaaaPA++c]de" fullword ascii
		 $a5= "EVENT_SINK_QueryInterface" fullword ascii
		 $a6= "'FCB-G>????????????????????????????>HIJKLD" fullword ascii
		 $a7= "ghi++7`PjPPPPPPPPPPPPPPPPPPPPPPP`-,," fullword ascii
		 $a8= "h+-+,()'*'+$#!1:>=997=66:57=4?" fullword ascii
		 $a9= ",++I*55`jjQ45545545555455*-O++,+" fullword ascii
		 $a10= "IJKHNNIMLBOBHAFDT_[XZRXSS_PTXQZijkhnnimlbobhafdt" fullword ascii
		 $a11= "JIHKMMJNOALAKBEGWX[Y_Q[PPSW[RYjihkmmjnA" fullword ascii
		 $a12= "JIHKMMJNOALAKBEGWX[Y_Q[PPSW[RYjihkmmjnoalakbegw|x{y" fullword ascii
		 $a13= "+++++,,J.qrIA-7--777I_O,+++" fullword ascii
		 $a14= "LONMKKLHIGJGMDCAQZ^]_YW]VVZUQ]T_lonmkklhigjgmdfasy" fullword ascii
		 $a15= "LONMLKLLIGLGKHOGWZ^YSVVVZ]R^P[jiloiiohiglakleg" fullword ascii
		 $a16= "NOGJGMDCAWZ^]_YW]PVZUQ]T_jonmkklhigjgmdcaqz~}" fullword ascii
		 $a17= "NOPGHGGHHHHHHHHHHHHHHHHHHHHHHGHHHQ+RL!S" fullword ascii
		 $a18= ":RQXabbaYPj`456*-7IO,,+>y" fullword ascii
		 $a19= "VeGW^Z[Y_S_SQrC[SXieyhmmjGl`|pk`fds|~{}vqlq" fullword ascii
		 $a20= "WWWWWWWWWWWWWWWWWWWWXXWWXYI" fullword ascii

		 $hex1= {246131303d2022494a}
		 $hex2= {246131313d20224a49}
		 $hex3= {246131323d20224a49}
		 $hex4= {246131333d20222b2b}
		 $hex5= {246131343d20224c4f}
		 $hex6= {246131353d20224c4f}
		 $hex7= {246131363d20224e4f}
		 $hex8= {246131373d20224e4f}
		 $hex9= {246131383d20223a52}
		 $hex10= {246131393d20225665}
		 $hex11= {2461313d20222c2f2e}
		 $hex12= {246132303d20225757}
		 $hex13= {2461323d2022332a2a}
		 $hex14= {2461333d20222c2c37}
		 $hex15= {2461343d20225f6061}
		 $hex16= {2461353d2022455645}
		 $hex17= {2461363d2022274643}
		 $hex18= {2461373d2022676869}
		 $hex19= {2461383d2022682b2d}
		 $hex20= {2461393d20222c2b2b}
		 $hex21= {247331303d20224f72}
		 $hex22= {247331313d20225265}
		 $hex23= {247331323d20225653}
		 $hex24= {2473313d2022353636}
		 $hex25= {2473323d2022353735}
		 $hex26= {2473333d2022402a41}
		 $hex27= {2473343d202261722c}
		 $hex28= {2473353d202265636f}
		 $hex29= {2473363d202246696c}
		 $hex30= {2473373d2022696e6a}
		 $hex31= {2473383d20224e6f74}
		 $hex32= {2473393d20224f6c69}

	condition:
		4 of them
}
