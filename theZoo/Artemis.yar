
/*
   YARA Rule Set
   Author: resteex
   Identifier: Artemis 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Artemis {
	meta: 
		 description= "Artemis Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "caff801a280d42dbd1ad6b1266d3c43a"

	strings:

	
 		 $s1= "{1E453EA8-BB42-419D-8067-D2477A36B761}" fullword wide
		 $s2= "2014 Decision Support Software LLC" fullword wide
		 $s3= "ActivationDepartment@FedRetireSoftware.com" fullword wide
		 $s4= "CSRS-FERS Benefits Calculator and Retirement Analyzer" fullword wide
		 $s5= "{D449BC32-6D28-4AF0-BB00-AB3391EF0F9A}" fullword wide
		 $s6= "Decision Support Software LLC" fullword wide
		 $s7= "FileDescription" fullword wide
		 $s8= "http://www.FedRetireSoftware.com" fullword wide
		 $s9= "Installer for CSRS-FERS Benefits Calculator and Retirement Analy" fullword wide
		 $s10= "OriginalFilename" fullword wide
		 $s11= "StringFileInfo%04x%04xArguments" fullword wide
		 $s12= "VarFileInfoTranslation" fullword wide
		 $s13= "VS_VERSION_INFO" fullword wide
		 $s14= "WinNT (x86) Unicode Lib Rel" fullword wide
		 $a1= "D:DevTin9InstallDirvc80-win32uLoader.pdb" fullword ascii

		 $hex1= {2461313d2022443a44}
		 $hex2= {247331303d20224f72}
		 $hex3= {247331313d20225374}
		 $hex4= {247331323d20225661}
		 $hex5= {247331333d20225653}
		 $hex6= {247331343d20225769}
		 $hex7= {2473313d20227b3145}
		 $hex8= {2473323d2022323031}
		 $hex9= {2473333d2022416374}
		 $hex10= {2473343d2022435352}
		 $hex11= {2473353d20227b4434}
		 $hex12= {2473363d2022446563}
		 $hex13= {2473373d202246696c}
		 $hex14= {2473383d2022687474}
		 $hex15= {2473393d2022496e73}

	condition:
		1 of them
}
