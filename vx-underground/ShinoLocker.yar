
/*
   YARA Rule Set
   Author: resteex
   Identifier: ShinoLocker 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_ShinoLocker {
	meta: 
		 description= "ShinoLocker Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-44" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "cfada30d54f8a6ebedf7b7edd3c57b4f"

	strings:

	
 		 $s1= "ShinoLockerMain.Resources" fullword wide
		 $s2= "WinForms_RecursiveFormCreate" fullword wide
		 $s3= "WinForms_SeeInnerException" fullword wide

		 $hex1= {2473313d2022536869}
		 $hex2= {2473323d202257696e}
		 $hex3= {2473333d202257696e}

	condition:
		2 of them
}
