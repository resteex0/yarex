
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Backdoor_MSIL_Tyupkin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Backdoor_MSIL_Tyupkin {
	meta: 
		 description= "theZoo_Backdoor_MSIL_Tyupkin Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-34-46" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "162ad6dbd50f3be407f49f65b938512a"
		 hash2= "250b77dfbb1b666e95b3bcda082de287"
		 hash3= "32d5cca418b81e002bb3fdd8e4062bc9"
		 hash4= "69be938abe7f28615d933d5ce155057c"
		 hash5= "700e91a24f5cadd0cb7507f0d0077b26"
		 hash6= "af945758905e0615a10fe23070998b9b"

	strings:

	
 		 $s1= "C:windowssystem32configswin.sys" fullword wide
		 $s2= "C:windowssystem32driversswin.sys" fullword wide
		 $s3= "C:WINXPPROsystem32configswin.sys" fullword wide
		 $s4= "C:WINXPPROsystem32driversswin.sys" fullword wide
		 $s5= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s6= "SYSTEMControlSet001Servicesscsrvc" fullword wide
		 $s7= "SYSTEMControlSet002Servicesscsrvc" fullword wide
		 $s8= "SYSTEMControlSet003Servicesscsrvc" fullword wide
		 $s9= "SYSTEMCurrentControlSetServicesscsrvc" fullword wide
		 $a1= "??_C@_0CA@OBGMHHAA@LookupPrivilegeValue?5error?3?5?$CFu?6?$AA@" fullword ascii
		 $a2= "??_C@_0CB@PKDAHPHM@Nr?4?5of?5cash?5unit?5structures?5is?3?5@" fullword ascii
		 $a3= "??_C@_0CD@EPKHPJIF@?6Error?5deleting?5file?$CB?5Error?5code@" fullword ascii
		 $a4= "??_C@_0CH@EIFBFEEI@?6THE?5SUPPORTED?5KEYS?5FLAG?5IS?$CIdeci@" fullword ascii
		 $a5= "??_C@_0CH@LKCEJHGP@?6THE?5SUPPORTED?5KEYS?5FLAG?5IS?$CIhex?$CJ@" fullword ascii
		 $a6= "??_C@_0DA@EDAFIAHK@Money?5dispensed?$CB?5You?5can?5now?5tak@" fullword ascii
		 $a7= "char> >" fullword ascii
		 $a8= "char> >.sentry.{ctor}" fullword ascii
		 $a9= "char> >.sentry.{dtor}" fullword ascii
		 $a10= "char> >.__vbaseDtor" fullword ascii
		 $a11= "CrtImplementationDetails>@@$$Q2HA" fullword ascii
		 $a12= "CrtImplementationDetails>.DefaultDomain.NeedsInitialization" fullword ascii
		 $a13= "CrtImplementationDetails>.LanguageSupport.InitializePerProcess" fullword ascii
		 $a14= "CrtImplementationDetails>.LanguageSupport.InitializeVtables" fullword ascii
		 $a15= "CrtImplementationDetails>.LanguageSupport.UninitializeAppDomain" fullword ascii

		 $hex1= {246131303d20226368}
		 $hex2= {246131313d20224372}
		 $hex3= {246131323d20224372}
		 $hex4= {246131333d20224372}
		 $hex5= {246131343d20224372}
		 $hex6= {246131353d20224372}
		 $hex7= {2461313d20223f3f5f}
		 $hex8= {2461323d20223f3f5f}
		 $hex9= {2461333d20223f3f5f}
		 $hex10= {2461343d20223f3f5f}
		 $hex11= {2461353d20223f3f5f}
		 $hex12= {2461363d20223f3f5f}
		 $hex13= {2461373d2022636861}
		 $hex14= {2461383d2022636861}
		 $hex15= {2461393d2022636861}
		 $hex16= {2473313d2022433a77}
		 $hex17= {2473323d2022433a77}
		 $hex18= {2473333d2022433a57}
		 $hex19= {2473343d2022433a57}
		 $hex20= {2473353d2022536f66}
		 $hex21= {2473363d2022535953}
		 $hex22= {2473373d2022535953}
		 $hex23= {2473383d2022535953}
		 $hex24= {2473393d2022535953}

	condition:
		16 of them
}
