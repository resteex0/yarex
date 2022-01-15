
/*
   YARA Rule Set
   Author: resteex
   Identifier: FakeDivX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_FakeDivX {
	meta: 
		 description= "FakeDivX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-04-05" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "00bdd194328c2fe873260970da585d84"
		 hash2= "052ae7410594c5c0522afd89eccb85a7"
		 hash3= "0a960df88c2d27d0d4cc27544011fbb0"
		 hash4= "0e27df7a010338d554dba932b94cb11e"
		 hash5= "10c32d95367bb9ab2928390ff8689a26"
		 hash6= "19e31123c1ccc072c257347bba220f0e"
		 hash7= "1f18b45b25dd50adf163d91481c851cf"
		 hash8= "39b59bda3c65989b9288f10789779e96"
		 hash9= "3ad96ccf8e7c5089b80232529ffe8f62"
		 hash10= "3dff37ee5d6e3a1bc6f37c58ac748821"
		 hash11= "48bcc188a4d6a2c70ee495a7742b68b8"
		 hash12= "4aacf36cafbd8db3558f523ddc8c90e5"
		 hash13= "4ce289a8e3b4dd374221d2b56f921f6d"
		 hash14= "4e0bff23a95e8d02800fecbac184cd5f"
		 hash15= "540f19ff5350e08eff2c5c4bada1f01f"
		 hash16= "56aaea2b443ea8c9cea248e64d645305"
		 hash17= "704c5b12247826cf111b1a0fc3678766"
		 hash18= "7c4d4e56f1a9ceb096df49da42cc00ed"
		 hash19= "7d14dcfd00f364c788ba51c6c2fc6bdd"
		 hash20= "8db8c55983125113e472d7dd6a47bd43"
		 hash21= "9325e2dddded560c2e7a214eb920f9ea"
		 hash22= "9577c1b005673e1406da41fb07e914bb"
		 hash23= "9698be7d8551cb89a95ce285c84c46b1"
		 hash24= "a6e52ca88a4cd80eb39989090d246631"
		 hash25= "aa7dc576d1fe71f18374f9b4ae6869fa"
		 hash26= "ab0d8f81b65e5288dd6004f2f20280fd"
		 hash27= "adc9cafbd4e2aa91e4aa75e10a948213"
		 hash28= "b2a381fbc544fe69250ad287b55f435b"
		 hash29= "b60ca81cec260d44025c2b0374364272"
		 hash30= "be8c528a6bff6668093e9aabe0634197"
		 hash31= "c0f3501b63935add01a6b4aa458a01b7"
		 hash32= "c5fb893b401152e625565605d85a6b7d"
		 hash33= "ddfac94608f8b6c0acfadc7a36323fe6"
		 hash34= "e1bda5b01d1ad8c0f48177cd6398b15f"
		 hash35= "e3f8456d5188fd03f202bfe112d3353d"

	strings:

	
 		 $s1= "5.1.2600.5512 (xpsp.080413-2108)" fullword wide
		 $s2= "abcdwxyzstuvrqponmijklefghABCDWXYZSTUVMNOPQRIJKLEFGH9876543210+/" fullword wide
		 $s3= "CChromeBrandInstaller::InstallBrand_CleanFiles(%s): %s" fullword wide
		 $s4= "CChromeBrandInstaller::InstallBrand_CopyFiles(%s): %s" fullword wide
		 $s5= "CFireFoxInstaller::RunFFCommand: (profile=%s,user=%s)" fullword wide
		 $s6= "CGlobalContext::ExecuteCommand: %s" fullword wide
		 $s7= "CGlobalContext::ExecuteCommand: %s(%s)" fullword wide
		 $s8= "CGlobalContext::ExecuteCommands: %s" fullword wide
		 $s9= "CGlobalContext::ExpandINI: '%s'->'%s'" fullword wide
		 $s10= "Chrome.InstallViaRegistry" fullword wide
		 $s11= "Chrome.UninstallViaRegistry" fullword wide
		 $s12= "CIEPluginModule::AddCommonRGSReplacements: CLSID='%s'" fullword wide
		 $s13= "CIEPluginModule::AddCommonRGSReplacements: PluginShortName='%s'" fullword wide
		 $s14= "CIEPluginModule::AddCommonRGSReplacements: ProgID='%s'" fullword wide
		 $s15= "CIEPluginStorage::LogAccess: %s:%s:%s" fullword wide
		 $s16= "C:WindowsSystem32msiexec.exe" fullword wide
		 $s17= "DCChromeBrandInstaller::SetNodeValue: SetNodeValue(" fullword wide
		 $s18= "Internet Exploreriexplore.exe" fullword wide
		 $s19= "jsefileshellexpropertysheethandlers" fullword wide
		 $s20= "jsfileshellexpropertysheethandlers" fullword wide
		 $s21= "microsoft.freethreadedxmldom.1.0clsid" fullword wide
		 $s22= "mini::ini_section::find: %s=(new)NULL" fullword wide
		 $s23= "mini::ini_section::get: %s=NULL" fullword wide
		 $s24= "mini::ini_section::get: %s='%s'" fullword wide
		 $s25= "mini::ini_section::set_from_command_line: (lpCmdLine==NULL)" fullword wide
		 $s26= "mini::ini_section::set: %s=NULL" fullword wide
		 $s27= "mini::ini_section::set: %s='%s'" fullword wide
		 $s28= "Mozilla Firefoxfirefox.exe" fullword wide
		 $s29= "piffileshellexpropertysheethandlers" fullword wide
		 $s30= "protocolsname-space handlermk*" fullword wide
		 $s31= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword wide
		 $s32= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList" fullword wide
		 $s33= "SOFTWAREMozillaFirefoxExtensions" fullword wide
		 $s34= "SOFTWAREMozillaMozilla Firefox" fullword wide
		 $s35= "wchar_t>::base64_decode: Exception" fullword wide
		 $s36= "wchar_t>::base64_encode: Exception" fullword wide
		 $a1= "abcdwxyzstuvrqponmijklefghABCDWXYZSTUVMNOPQRIJKLEFGH9876543210+/" fullword ascii
		 $a2= "CChromeBrandInstaller::InstallBrand_CleanFiles(%s): %s" fullword ascii
		 $a3= "CChromeBrandInstaller::InstallBrand_CopyFiles(%s): %s" fullword ascii
		 $a4= "CFireFoxInstaller::RunFFCommand: (profile=%s,user=%s)" fullword ascii
		 $a5= "CIEPluginModule::AddCommonRGSReplacements: CLSID='%s'" fullword ascii
		 $a6= "CIEPluginModule::AddCommonRGSReplacements: PluginShortName='%s'" fullword ascii
		 $a7= "CIEPluginModule::AddCommonRGSReplacements: ProgID='%s'" fullword ascii
		 $a8= "DCChromeBrandInstaller::SetNodeValue: SetNodeValue(" fullword ascii
		 $a9= "mini::ini_section::set_from_command_line: (lpCmdLine==NULL)" fullword ascii
		 $a10= "SOFTWAREMicrosoftWindowsCurrentVersionUninstall" fullword ascii
		 $a11= "SOFTWAREMicrosoftWindows NTCurrentVersionProfileList" fullword ascii
		 $a12= "wchar_t>::base64_decode: Exception" fullword ascii
		 $a13= "wchar_t>::base64_encode: Exception" fullword ascii

		 $hex1= {246131303d2022534f}
		 $hex2= {246131313d2022534f}
		 $hex3= {246131323d20227763}
		 $hex4= {246131333d20227763}
		 $hex5= {2461313d2022616263}
		 $hex6= {2461323d2022434368}
		 $hex7= {2461333d2022434368}
		 $hex8= {2461343d2022434669}
		 $hex9= {2461353d2022434945}
		 $hex10= {2461363d2022434945}
		 $hex11= {2461373d2022434945}
		 $hex12= {2461383d2022444343}
		 $hex13= {2461393d20226d696e}
		 $hex14= {247331303d20224368}
		 $hex15= {247331313d20224368}
		 $hex16= {247331323d20224349}
		 $hex17= {247331333d20224349}
		 $hex18= {247331343d20224349}
		 $hex19= {247331353d20224349}
		 $hex20= {247331363d2022433a}
		 $hex21= {247331373d20224443}
		 $hex22= {247331383d2022496e}
		 $hex23= {247331393d20226a73}
		 $hex24= {2473313d2022352e31}
		 $hex25= {247332303d20226a73}
		 $hex26= {247332313d20226d69}
		 $hex27= {247332323d20226d69}
		 $hex28= {247332333d20226d69}
		 $hex29= {247332343d20226d69}
		 $hex30= {247332353d20226d69}
		 $hex31= {247332363d20226d69}
		 $hex32= {247332373d20226d69}
		 $hex33= {247332383d20224d6f}
		 $hex34= {247332393d20227069}
		 $hex35= {2473323d2022616263}
		 $hex36= {247333303d20227072}
		 $hex37= {247333313d2022534f}
		 $hex38= {247333323d2022534f}
		 $hex39= {247333333d2022534f}
		 $hex40= {247333343d2022534f}
		 $hex41= {247333353d20227763}
		 $hex42= {247333363d20227763}
		 $hex43= {2473333d2022434368}
		 $hex44= {2473343d2022434368}
		 $hex45= {2473353d2022434669}
		 $hex46= {2473363d202243476c}
		 $hex47= {2473373d202243476c}
		 $hex48= {2473383d202243476c}
		 $hex49= {2473393d202243476c}

	condition:
		32 of them
}
