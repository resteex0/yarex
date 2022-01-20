
/*
   YARA Rule Set
   Author: resteex
   Identifier: DearCry_Ransomware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_DearCry_Ransomware {
	meta: 
		 description= "DearCry_Ransomware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-02-40" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0e55ead3b8fd305d9a54f78c7b56741a"

	strings:

	
 		 $a1= "C6UsAhk/dI4/5HwbfZBAiMySXNB3DxVB2hOrjDjIeVAkFjQgZ19B+KQFWkSo1ube" fullword ascii
		 $a2= "CJQSg6Moblo2NVF50AK3cIG2/lVh82ebgedXsbVJpjVMc03aTPWV4sNWjTO3o+aX" fullword ascii
		 $a3= "VdHjwdv74evE/ur9Lv9HM+89iZdzEpVPO+AjOTtsQgFNtmVecC2vmw9m60dgyR/1" fullword ascii

		 $hex1= {2461313d2022433655}
		 $hex2= {2461323d2022434a51}
		 $hex3= {2461333d2022566448}

	condition:
		1 of them
}
