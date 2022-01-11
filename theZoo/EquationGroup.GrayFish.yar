
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_GrayFish 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_GrayFish {
	meta: 
		 description= "EquationGroup_GrayFish Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-56" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "9b1ca66aab784dc5f1dfe635d8f8a904"

	strings:

	
 		 $s1= "''2]ZEh*2@''izGWE~]''D)/mC+u$''}EG2chcw*''CE~gcFhYSm''tT22]~*9]2hEc~''sD" fullword wide
		 $s2= "''2]ZEh*2@''izGWE~]''h@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h" fullword wide
		 $s3= "BsDADm$}u))ms''D@h*]iN[''" fullword wide
		 $s4= "cnFormSyncExFBC" fullword wide
		 $s5= "Copyright (C) Microsoft Corp. 1981-2001" fullword wide
		 $s6= "FileDescription" fullword wide
		 $s7= "Microsoft Corporation" fullword wide
		 $s8= "Microsoft(R) Windows (R) 2000 Operating System" fullword wide
		 $s9= "OriginalFilename" fullword wide
		 $s10= "S]*Fc2XY+hhcGEz*]h" fullword wide
		 $s11= "sGh@h*]i2cc*sG''h@h*]iN[''g2EK]2h''sh" fullword wide
		 $s12= "tB''CRS%)CD''D@h*]iN[''" fullword wide
		 $s13= "tB''CRS%)CD''D@h*]iN[''%2EK]2h''" fullword wide
		 $s14= "(+:tt%t|O? |[N?+V[.? ::[?%oxO/N.N8V./?.+x$t/+%," fullword wide
		 $s15= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''" fullword wide
		 $s16= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''}DS%Du9" fullword wide
		 $s17= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''D]2KEG]h''}hSgD2K" fullword wide
		 $s18= "''u]ZEh*2@''}zGWE~]''D@h*]i''tT22]~*tc~*2cpD]*''tc~*2cp''D]hhEc~Y}z~zZ]2''}]iDTnD@h" fullword wide
		 $s19= "(V[$OV%%N?/: +? x/O? |.8?[|+$OVO.|8+t?$:oN$$x8," fullword wide
		 $s20= "VS_VERSION_INFO" fullword wide
		 $s21= "Windows Configuration Services" fullword wide
		 $a1= "01C482BA-BD31-4874-A08B-A93EA5BCE511" fullword ascii
		 $a2= "{%04X%04X-%04X-%04X-%04X-%04X%04X%04X}" fullword ascii
		 $a3= ")Dm@I]Y?YQ]*9]2hEc~$5_>YwzEpT2]" fullword ascii
		 $a4= "ExpandEnvironmentStringsW" fullword ascii
		 $a5= "InitializeSecurityDescriptor" fullword ascii
		 $a6= "Q]*Sz*EK]+IE/T~G*Ec~hY?YwzEpT2]Y*cYpczgY~*gppagppYicgTp]" fullword ascii
		 $a7= "Q]*Sz*EK]+IE/T~G*Ec~hY?YwzEpT2]Y*cYZ]*YI2cGYzgg2]hhYwc2Yu*pS*D*z*Thmc%ch$22c2" fullword ascii
		 $a8= "S*Sc*Ew@tWz~Z]%E2]G*c2@/Ep]" fullword ascii
		 $a9= "S*^T]2@D@incpEG6E~X)nl]G*" fullword ascii
		 $a10= "u*pQ]*tciI2]hhEc~Cc2XDIzG]DEj]" fullword ascii

		 $hex1= {246131303d2022752a}
		 $hex2= {2461313d2022303143}
		 $hex3= {2461323d20227b2530}
		 $hex4= {2461333d202229446d}
		 $hex5= {2461343d2022457870}
		 $hex6= {2461353d2022496e69}
		 $hex7= {2461363d2022515d2a}
		 $hex8= {2461373d2022515d2a}
		 $hex9= {2461383d2022532a53}
		 $hex10= {2461393d2022532a5e}
		 $hex11= {247331303d2022535d}
		 $hex12= {247331313d20227347}
		 $hex13= {247331323d20227442}
		 $hex14= {247331333d20227442}
		 $hex15= {247331343d2022282b}
		 $hex16= {247331353d20222727}
		 $hex17= {247331363d20222727}
		 $hex18= {247331373d20222727}
		 $hex19= {247331383d20222727}
		 $hex20= {247331393d20222856}
		 $hex21= {2473313d2022272732}
		 $hex22= {247332303d20225653}
		 $hex23= {247332313d20225769}
		 $hex24= {2473323d2022272732}
		 $hex25= {2473333d2022427344}
		 $hex26= {2473343d2022636e46}
		 $hex27= {2473353d2022436f70}
		 $hex28= {2473363d202246696c}
		 $hex29= {2473373d20224d6963}
		 $hex30= {2473383d20224d6963}
		 $hex31= {2473393d20224f7269}

	condition:
		3 of them
}
