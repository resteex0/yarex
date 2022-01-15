
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Petya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Petya {
	meta: 
		 description= "Ransomware_Petya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_19-53-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "a92f13f3a1b3b39833d3cc336301b713"
		 hash2= "af2379cc4d607a45ac44d62135fb7015"

	strings:

	
 		 $s1= "[%02d/%02d/%02d %02d:%02d:%02d.%03d]" fullword wide
		 $s2= "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" fullword wide
		 $s3= "{A0C1F415-D2CE-4ddc-9B48-14E56FD55162}" fullword wide
		 $s4= "{C4F406E5-F024-4e3f-89A7-D5AB7663C3CD}" fullword wide
		 $s5= "{C68009EA-1163-4498-8E93-D5C4E317D8CE}" fullword wide
		 $s6= "CSoftwareGoogle%wsUsageStatsDaily" fullword wide
		 $s7= "{D19BAF17-7C87-467E-8D63-6C4B1C836373}" fullword wide
		 $s8= "[GetCrashPipeName][GetProcessUser failed][0x%08x]" fullword wide
		 $s9= "HKCUSoftwareGoogleUpdateClientState" fullword wide
		 $s10= "HKLMSoftwareGoogleUpdateClientState" fullword wide
		 $s11= "HKLMSoftwareGoogleUpdateClientStateMedium" fullword wide
		 $s12= "HKLMSoftwareMicrosoftWindows NTCurrentVersionNetworkCards" fullword wide
		 $s13= "HKLMSoftwarePoliciesGoogleUpdate" fullword wide
		 $s14= "[OpenCustomInfoFile failed][0x%08x]" fullword wide
		 $s15= "[StartCrashReporter failed][0x%08x]" fullword wide
		 $s16= "[StartCrashUploader() failed][0x%08x]" fullword wide
		 $s17= "[StartProcessWithNoExceptionHandler][%s]" fullword wide
		 $s18= "SYSTEMCurrentControlSetControlSession Manager" fullword wide
		 $a1= "HKLMSoftwareMicrosoftWindows NTCurrentVersionNetworkCards" fullword ascii

		 $hex1= {2461313d2022484b4c}
		 $hex2= {247331303d2022484b}
		 $hex3= {247331313d2022484b}
		 $hex4= {247331323d2022484b}
		 $hex5= {247331333d2022484b}
		 $hex6= {247331343d20225b4f}
		 $hex7= {247331353d20225b53}
		 $hex8= {247331363d20225b53}
		 $hex9= {247331373d20225b53}
		 $hex10= {247331383d20225359}
		 $hex11= {2473313d20225b2530}
		 $hex12= {2473323d2022253038}
		 $hex13= {2473333d20227b4130}
		 $hex14= {2473343d20227b4334}
		 $hex15= {2473353d20227b4336}
		 $hex16= {2473363d202243536f}
		 $hex17= {2473373d20227b4431}
		 $hex18= {2473383d20225b4765}
		 $hex19= {2473393d2022484b43}

	condition:
		2 of them
}
