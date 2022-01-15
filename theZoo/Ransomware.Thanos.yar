
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
		 date = "2022-01-14_22-51-25" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "03b76a5130d0df8134a6bdea7fe97bcd"
		 hash2= "be60e389a0108b2871dff12dfbb542ac"
		 hash3= "d6d956267a268c9dcf48445629d2803e"
		 hash4= "e01e11dca5e8b08fc8231b1cb6e2048c"

	strings:

	
 		 $s1= "3747bdbf-0ef0-42d8-9234-70d68801f407" fullword wide
		 $s2= "aHR0cCBhbmFseXplciBzdGFuZC1hbG9uZQ==" fullword wide
		 $s3= "aHR0cDovL2ljYW5oYXppcC5jb20=" fullword wide
		 $s4= "c3lzaW50ZXJuYWxzIHRjcHZpZXc=" fullword wide
		 $s5= "c3RvcCBBY3JvbmlzQWdlbnQgL3k=" fullword wide
		 $s6= "c3RvcCBCTVIgQm9vdCBTZXJ2aWNlIC95" fullword wide
		 $s7= "c3RvcCBCYWNrdXBFeGVjQWdlbnRBY2NlbGVyYXRvciAveQ==" fullword wide
		 $s8= "c3RvcCBCYWNrdXBFeGVjQWdlbnRCcm93c2VyIC95" fullword wide
		 $s9= "c3RvcCBCYWNrdXBFeGVjRGl2ZWNpTWVkaWFTZXJ2aWNlIC95" fullword wide
		 $s10= "c3RvcCBCYWNrdXBFeGVjTWFuYWdlbWVudFNlcnZpY2UgL3k=" fullword wide
		 $s11= "c3RvcCBCYWNrdXBFeGVjUlBDU2VydmljZSAveQ==" fullword wide
		 $s12= "c3RvcCBCYWNrdXBFeGVjVlNTUHJvdmlkZXIgL3k=" fullword wide
		 $s13= "c3RvcCBDQUFSQ1VwZGF0ZVN2YyAveQ==" fullword wide
		 $s14= "c3RvcCBDQVNBRDJEV2ViU3ZjIC95" fullword wide
		 $s15= "c3RvcCBQRFZGU1NlcnZpY2UgL3k=" fullword wide
		 $s16= "c3RvcCBRQklEUFNlcnZpY2UgL3k=" fullword wide
		 $s17= "c3RvcCBRQkNGTW9uaXRvclNlcnZpY2UgL3k=" fullword wide
		 $s18= "c3RvcCBRQkZDU2VydmljZSAveQ==" fullword wide
		 $s19= "c3RvcCBWZWVhbU5GU1N2YyAveQ==" fullword wide
		 $s20= "c3RvcCBWZWVhbURlcGxveW1lbnRTZXJ2aWNlIC95" fullword wide
		 $s21= "c3RvcCBWZWVhbVRyYW5zcG9ydFN2YyAveQ==" fullword wide
		 $s22= "DisableBehaviorMonitoring" fullword wide
		 $s23= "DisableIntrusionPreventionSystem" fullword wide
		 $s24= "DisableOnAccessProtection" fullword wide
		 $s25= "DisableRealtimeMonitoring" fullword wide
		 $s26= "DisableScanOnRealtimeEnable" fullword wide
		 $s27= "Get-MpPreference -verbose" fullword wide
		 $s28= "HOW_TO_DECYPHER_FILES.hta" fullword wide
		 $s29= "HOW_TO_DECYPHER_FILES.txt" fullword wide
		 $s30= "mac>([a-f0-9]{2}-?){6})" fullword wide
		 $s31= "ModerateThreatDefaultAction" fullword wide
		 $s32= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPg==" fullword wide
		 $s33= "PHAgc3R5bGU9InRleHQtYWxpZ246IGNlbnRlcjsiPktleSBJZGVudGlmaWVyOiA=" fullword wide
		 $s34= "PWWPh5jww0vweJe 4pFhUfFs2GJ1B5U" fullword wide
		 $s35= "Q2xpZW50IFVuaXF1ZSBJZGVudGlmaWVyIEtleTog" fullword wide
		 $s36= "RGF0ZSBvZiBlbmNyeXB0aW9uOiA=" fullword wide
		 $s37= "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ=" fullword wide
		 $s38= "RW5hYmxlTGlua2VkQ29ubmVjdGlvbnM=" fullword wide
		 $s39= "SevereThreatDefaultAction" fullword wide
		 $s40= "SignatureDisableUpdateOnStartupWithoutEngine" fullword wide
		 $s41= "SoftwareMicrosoftWindowsCurrentVersionPoliciesSystem" fullword wide
		 $s42= "SOFTWAREMicrosoftWindows DefenderFeatures" fullword wide
		 $s43= "SOFTWAREPoliciesMicrosoftWindows Defender" fullword wide
		 $s44= "SUVXYXRjaCBQcm9mZXNzaW9uYWw=" fullword wide
		 $s45= "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" fullword wide
		 $s46= "TnVtYmVyIG9mIGZpbGVzIHRoYXQgd2VyZSBwcm9jZXNzZWQgaXM6IA==" fullword wide
		 $s47= "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA==" fullword wide
		 $s48= "UkRHIFBhY2tlciBEZXRlY3Rvcg==" fullword wide
		 $s49= "Y29uZmlnIFNRTFdyaXRlciBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s50= "Y29uZmlnIFNRTFRFTEVNRVRSWSBzdGFydD0gZGlzYWJsZWQ=" fullword wide
		 $s51= "Y29uZmlnIFNzdHBTdmMgc3RhcnQ9IGRpc2FibGVk" fullword wide
		 $s52= "YOkBRITTKNBYLVa qNEQn0mbG2wNoNm" fullword wide
		 $s53= "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" fullword wide
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
		 $hex7= {247331323d20226333}
		 $hex8= {247331333d20226333}
		 $hex9= {247331343d20226333}
		 $hex10= {247331353d20226333}
		 $hex11= {247331363d20226333}
		 $hex12= {247331373d20226333}
		 $hex13= {247331383d20226333}
		 $hex14= {247331393d20226333}
		 $hex15= {2473313d2022333734}
		 $hex16= {247332303d20226333}
		 $hex17= {247332313d20226333}
		 $hex18= {247332323d20224469}
		 $hex19= {247332333d20224469}
		 $hex20= {247332343d20224469}
		 $hex21= {247332353d20224469}
		 $hex22= {247332363d20224469}
		 $hex23= {247332373d20224765}
		 $hex24= {247332383d2022484f}
		 $hex25= {247332393d2022484f}
		 $hex26= {2473323d2022614852}
		 $hex27= {247333303d20226d61}
		 $hex28= {247333313d20224d6f}
		 $hex29= {247333323d20225048}
		 $hex30= {247333333d20225048}
		 $hex31= {247333343d20225057}
		 $hex32= {247333353d20225132}
		 $hex33= {247333363d20225247}
		 $hex34= {247333373d20225247}
		 $hex35= {247333383d20225257}
		 $hex36= {247333393d20225365}
		 $hex37= {2473333d2022614852}
		 $hex38= {247334303d20225369}
		 $hex39= {247334313d2022536f}
		 $hex40= {247334323d2022534f}
		 $hex41= {247334333d2022534f}
		 $hex42= {247334343d20225355}
		 $hex43= {247334353d2022546e}
		 $hex44= {247334363d2022546e}
		 $hex45= {247334373d20225547}
		 $hex46= {247334383d2022556b}
		 $hex47= {247334393d20225932}
		 $hex48= {2473343d202263336c}
		 $hex49= {247335303d20225932}
		 $hex50= {247335313d20225932}
		 $hex51= {247335323d2022594f}
		 $hex52= {247335333d20225a57}
		 $hex53= {2473353d2022633352}
		 $hex54= {2473363d2022633352}
		 $hex55= {2473373d2022633352}
		 $hex56= {2473383d2022633352}
		 $hex57= {2473393d2022633352}

	condition:
		38 of them
}
