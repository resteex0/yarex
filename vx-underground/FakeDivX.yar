
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_FakeDivX 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_FakeDivX {
	meta: 
		 description= "vx_underground2_FakeDivX Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-56-10" 
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

		 $hex1= {247331303d20224368}
		 $hex2= {247331313d20224368}
		 $hex3= {247331323d20224349}
		 $hex4= {247331333d20224349}
		 $hex5= {247331343d20224349}
		 $hex6= {247331353d20224349}
		 $hex7= {247331363d2022433a}
		 $hex8= {247331373d20224443}
		 $hex9= {247331383d2022496e}
		 $hex10= {247331393d20226a73}
		 $hex11= {2473313d2022352e31}
		 $hex12= {247332303d20226a73}
		 $hex13= {247332313d20226d69}
		 $hex14= {247332323d20226d69}
		 $hex15= {247332333d20226d69}
		 $hex16= {247332343d20226d69}
		 $hex17= {247332353d20226d69}
		 $hex18= {247332363d20226d69}
		 $hex19= {247332373d20226d69}
		 $hex20= {247332383d20224d6f}
		 $hex21= {247332393d20227069}
		 $hex22= {2473323d2022616263}
		 $hex23= {247333303d20227072}
		 $hex24= {247333313d2022534f}
		 $hex25= {247333323d2022534f}
		 $hex26= {247333333d2022534f}
		 $hex27= {247333343d2022534f}
		 $hex28= {247333353d20227763}
		 $hex29= {247333363d20227763}
		 $hex30= {2473333d2022434368}
		 $hex31= {2473343d2022434368}
		 $hex32= {2473353d2022434669}
		 $hex33= {2473363d202243476c}
		 $hex34= {2473373d202243476c}
		 $hex35= {2473383d202243476c}
		 $hex36= {2473393d202243476c}

	condition:
		24 of them
}
