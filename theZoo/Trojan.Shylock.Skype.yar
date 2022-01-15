
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
		 date = "2022-01-14_20-54-12" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8fbeb78b06985c3188562e2f1b82d57d"

	strings:

	
 		 $s1= "!$).056;>ACENQV_`eimuz" fullword wide
		 $s2= "blockInMessages" fullword wide
		 $s3= "blockOutMessages" fullword wide
		 $s4= "PARTNER_DISPNAME" fullword wide
		 $s5= "session=%s&user=%s&fids=" fullword wide
		 $s6= "Skype%smain.db" fullword wide
		 $s7= "TAccessibleCheckListBox" fullword wide
		 $s8= "TConversationForm" fullword wide
		 $s9= "TNavigableButton" fullword wide
		 $s10= "/tool/skype.php?action=%s" fullword wide
		 $s11= "user=%s|%s|%s&fnames=" fullword wide

		 $hex1= {247331303d20222f74}
		 $hex2= {247331313d20227573}
		 $hex3= {2473313d2022212429}
		 $hex4= {2473323d2022626c6f}
		 $hex5= {2473333d2022626c6f}
		 $hex6= {2473343d2022504152}
		 $hex7= {2473353d2022736573}
		 $hex8= {2473363d2022536b79}
		 $hex9= {2473373d2022544163}
		 $hex10= {2473383d202254436f}
		 $hex11= {2473393d2022544e61}

	condition:
		1 of them
}
