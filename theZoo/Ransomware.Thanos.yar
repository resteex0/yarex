
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Thanos 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Thanos {
	meta: 
		 description= "Ransomware_Thanos Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03b76a5130d0df8134a6bdea7fe97bcd"
		 hash2= "be60e389a0108b2871dff12dfbb542ac"
		 hash3= "d6d956267a268c9dcf48445629d2803e"
		 hash4= "e01e11dca5e8b08fc8231b1cb6e2048c"

	strings:

	
 		 $s1= "3747bdbf-0ef0-42d8-9234-70d68801f407" fullword wide
		 $s2= "aHR0cCBhbmFseXplciBzdGFuZC1hbG9uZQ==" fullword wide
		 $s3= "c3RvcCBCYWNrdXBFeGVjQWdlbnRBY2NlbGVyYXRvciAveQ==" fullword wide
		 $s4= "c3RvcCBCYWNrdXBFeGVjQWdlbnRCcm93c2VyIC95" fullword wide
		 $s5= "c3RvcCBCYWNrdXBFeGVjRGl2ZWNpTWVkaWFTZXJ2aWNlIC95" fullword wide
		 $s6= "c3RvcCBCYWNrdXBFeGVjTWFuYWdlbWVudFNlcnZpY2UgL3k=" fullword wide
		 $s7= "c3RvcCBCYWNrdXBFeGVjUlBDU2VydmljZSAveQ==" fullword wide
		 $s8= "c3RvcCBCYWNrdXBFeGVjVlNTUHJvdmlkZXIgL3k=" fullword wide
		 $s9= "c3RvcCBRQkNGTW9uaXRvclNlcnZpY2UgL3k=" fullword wide
		 $s10= "c3RvcCBWZWVhbURlcGxveW1lbnRTZXJ2aWNlIC95" fullword wide
		 $s11= "c3RvcCBWZWVhbVRyYW5zcG9ydFN2YyAveQ==" fullword wide
		 $s12= "mac>([a-f0-9]{2}-?){6})" fullword wide
		 $s13= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPg==" fullword wide
		 $s14= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword wide
		 $s15= "Q2xpZW50IFVuaXF1ZSBJZGVudGlmaWVyIEtleTog" fullword wide
		 $s16= "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ=" fullword wide
		 $s17= "SignatureDisableUpdateOnStartupWithoutEngine" fullword wide
		 $s18= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s19= "SOFTWAREMicrosoftWindows DefenderFeatures" fullword wide
		 $s20= "SOFTWAREPoliciesMicrosoftWindows Defender" fullword wide
		 $s21= "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" fullword wide
		 $s22= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword wide
		 $s23= "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA==" fullword wide
		 $s24= "Y29uZmlnIFNRTFdyaXRlciBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s25= "Y29uZmlnIFNRTFRFTEVNRVRSWSBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s26= "Y29uZmlnIFNzdHBTdmMgc3RhcnQ9IGRpc2FibGVk" fullword wide
		 $a1= "mac>([a-f0-9]{2}-?){6})" fullword ascii
		 $a2= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword ascii
		 $a3= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword ascii
		 $a4= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword ascii

		 $hex1= {2461313d20226d6163}
		 $hex2= {2461323d2022504841}
		 $hex3= {2461333d2022536f66}
		 $hex4= {2461343d2022546e56}
		 $hex5= {247331303d20226333}
		 $hex6= {247331313d20226333}
		 $hex7= {247331323d20226d61}
		 $hex8= {247331333d20225048}
		 $hex9= {247331343d20225048}
		 $hex10= {247331353d20225132}
		 $hex11= {247331363d20225247}
		 $hex12= {247331373d20225369}
		 $hex13= {247331383d2022536f}
		 $hex14= {247331393d2022534f}
		 $hex15= {2473313d2022333734}
		 $hex16= {247332303d2022534f}
		 $hex17= {247332313d2022546e}
		 $hex18= {247332323d2022546e}
		 $hex19= {247332333d20225547}
		 $hex20= {247332343d20225932}
		 $hex21= {247332353d20225932}
		 $hex22= {247332363d20225932}
		 $hex23= {2473323d2022614852}
		 $hex24= {2473333d2022633352}
		 $hex25= {2473343d2022633352}
		 $hex26= {2473353d2022633352}
		 $hex27= {2473363d2022633352}
		 $hex28= {2473373d2022633352}
		 $hex29= {2473383d2022633352}
		 $hex30= {2473393d2022633352}

	condition:
		3 of them
}
