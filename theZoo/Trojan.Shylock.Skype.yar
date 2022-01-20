
/*
   YARA Rule Set
   Author: resteex
   Identifier: Trojan_Shylock_Skype 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Trojan_Shylock_Skype {
	meta: 
		 description= "Trojan_Shylock_Skype Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_04-43-52" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8fbeb78b06985c3188562e2f1b82d57d"

	strings:

	
 		 $s1= "/tool/skype.php?action=%s" fullword wide

		 $hex1= {2473313d20222f746f}

	condition:
		0 of them
}
