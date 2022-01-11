
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_EquationLaser 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_EquationLaser {
	meta: 
		 description= "EquationGroup_EquationLaser Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "752af597e6d9fd70396accc0b9013dbe"

	strings:

	
 		 $s1= "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "lsasrv32.dll and lsass.exe" fullword wide
		 $s4= "Microsoft Corporation" fullword wide
		 $s5= "Microsoft Corporation. All rights reserved." fullword wide
		 $s6= "Operating System" fullword wide
		 $s7= "OriginalFilename" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide
		 $a1= "FindCloseChangeNotification" fullword ascii
		 $a2= "FindFirstChangeNotificationA" fullword ascii
		 $a3= "FindNextChangeNotification" fullword ascii
		 $a4= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {2461313d202246696e}
		 $hex2= {2461323d202246696e}
		 $hex3= {2461333d202246696e}
		 $hex4= {2461343d2022577269}
		 $hex5= {2473313d2022352e32}
		 $hex6= {2473323d202246696c}
		 $hex7= {2473333d20226c7361}
		 $hex8= {2473343d20224d6963}
		 $hex9= {2473353d20224d6963}
		 $hex10= {2473363d20224f7065}
		 $hex11= {2473373d20224f7269}
		 $hex12= {2473383d202256535f}

	condition:
		1 of them
}
