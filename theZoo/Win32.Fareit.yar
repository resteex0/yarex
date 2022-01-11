
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Fareit 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Fareit {
	meta: 
		 description= "Win32_Fareit Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-32-29" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15540d149889539308135fa12bedbcbf"
		 hash2= "1d34d800aa3320dc17a5786f8eec16ee"
		 hash3= "301210d5557d9ba34f401d3ef7a7276f"
		 hash4= "60c01a897dd8d60d3fea002ed3a4b764"
		 hash5= "67e4f5301851646b10a95f65a0b3bacb"
		 hash6= "8953398de47344e9c2727565af8d6f31"
		 hash7= "d883dc7acc192019f220409ee2cadd64"
		 hash8= "df5a394ad60512767d375647dbb82994"
		 hash9= "f1e546fe9d51dc96eb766ec61269edfb"
		 hash10= "f77db63cbed98391027f2525c14e161f"

	strings:

	
 		 $s1= "2002-2008 Sateira Software" fullword wide
		 $s2= "2005-2009 Uwe Sieber" fullword wide
		 $s3= "All rights reserved." fullword wide
		 $s4= "/b> button to select the destination4fold" fullword wide
		 $s5= "Cannot create folder %s" fullword wide
		 $s6= "Cannot create %s" fullword wide
		 $s7= "Confirm file replace" fullword wide
		 $s8= "CRC failed in %s" fullword wide
		 $s9= "DCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
		 $s10= "&Destination folder" fullword wide
		 $s11= "&Enter password for the encrypted file:" fullword wide
		 $s12= "er from the folders tree. It can be also entered" fullword wide
		 $s13= "ErroraErrors encountered while performing the operation" fullword wide
		 $s14= "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
		 $s15= "Extracting from %s" fullword wide
		 $s16= "Extraction progress" fullword wide
		 $s17= "File close error" fullword wide
		 $s18= "FileDescription" fullword wide
		 $s19= "folder is not accessiblelSome files could not be created." fullword wide
		 $s20= "hhRAR3MG6E9VR0bQSQ5" fullword wide
		 $s21= "Installation progress" fullword wide
		 $s22= "jmsctls_progress32" fullword wide
		 $s23= "LegalTrademarks" fullword wide
		 $s24= "li>If the destination folder does not exist, it will be2created automaticall" fullword wide
		 $s25= "Look at the information window for more details" fullword wide
		 $s26= "msctls_progress32" fullword wide
		 $s27= "Next volume is required" fullword wide
		 $s28= "Not enough memory" fullword wide
		 $s29= "OriginalFilename" fullword wide
		 $s30= "Packed data CRC failed in %s" fullword wide
		 $s31= "Please download a fresh copy and retry the installation All files" fullword wide
		 $s32= "ProgramFilesDir" fullword wide
		 $s33= "RarHtmlClassName" fullword wide
		 $s34= "Read error in the file %s" fullword wide
		 $s35= "RemoveDrive.exe" fullword wide
		 $s36= "RemoveDrive (Win32) - Prepares drives for safe removal" fullword wide
		 $s37= "REPLACEFILEDLG RENAMEDLG" fullword wide
		 $s38= "Sateira Software" fullword wide
		 $s39= "Select destination folder" fullword wide
		 $s40= "SeRestorePrivilege" fullword wide
		 $s41= "SeSecurityPrivilege" fullword wide
		 $s42= "SoftwareMicrosoftWindowsCurrentVersion" fullword wide
		 $s43= "SoftwareWinRAR SFX" fullword wide
		 $s44= "The archive comment is corrupt" fullword wide
		 $s45= "The archive header is corrupt" fullword wide
		 $s46= "The archive is corrupt" fullword wide
		 $s47= "The following file already exists" fullword wide
		 $s48= "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
		 $s49= "__tmp_rar_sfx_access_check_%u" fullword wide
		 $s50= "Unexpected end of archive" fullword wide
		 $s51= "Unknown method in %s" fullword wide
		 $s52= "Uwe Sieber - www.uwe-sieber.de" fullword wide
		 $s53= "VS_VERSION_INFO" fullword wide
		 $s54= "WinRAR self-extracting archive" fullword wide
		 $s55= "winrarsfxmappingfile.tmp" fullword wide
		 $s56= "Works on Windows 2000, XP and higher only" fullword wide
		 $s57= "Would you like to replace the existing file" fullword wide
		 $s58= "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
		 $s59= "You need to have the following volume to continue extraction:" fullword wide
		 $a1= "aaaaaaaaaaaaaaaaaaaaf~leQmux" fullword ascii
		 $a2= "''''''''''''''''''DaJKHPam" fullword ascii
		 $a3= "d:ProjectsWinRARSFXbuildsfxrar32Releasesfxrar.pdb" fullword ascii
		 $a4= "ExpandEnvironmentStringsA" fullword ascii
		 $a5= "ExpandEnvironmentStringsW" fullword ascii
		 $a6= "http://nsis.sf.net/NSIS_Error" fullword ascii
		 $a7= "InitializeCriticalSection" fullword ascii
		 $a8= "JJJJJJJJJJJJJJJJJJJaieQRamu" fullword ascii
		 $a9= "SHGetSpecialFolderLocation" fullword ascii
		 $a10= "SoftwareMicrosoftWindowsCurrentVersion" fullword ascii
		 $a11= "WritePrivateProfileStringA" fullword ascii

		 $hex1= {246131303d2022536f}
		 $hex2= {246131313d20225772}
		 $hex3= {2461313d2022616161}
		 $hex4= {2461323d2022272727}
		 $hex5= {2461333d2022643a50}
		 $hex6= {2461343d2022457870}
		 $hex7= {2461353d2022457870}
		 $hex8= {2461363d2022687474}
		 $hex9= {2461373d2022496e69}
		 $hex10= {2461383d20224a4a4a}
		 $hex11= {2461393d2022534847}
		 $hex12= {247331303d20222644}
		 $hex13= {247331313d20222645}
		 $hex14= {247331323d20226572}
		 $hex15= {247331333d20224572}
		 $hex16= {247331343d20224578}
		 $hex17= {247331353d20224578}
		 $hex18= {247331363d20224578}
		 $hex19= {247331373d20224669}
		 $hex20= {247331383d20224669}
		 $hex21= {247331393d2022666f}
		 $hex22= {2473313d2022323030}
		 $hex23= {247332303d20226868}
		 $hex24= {247332313d2022496e}
		 $hex25= {247332323d20226a6d}
		 $hex26= {247332333d20224c65}
		 $hex27= {247332343d20226c69}
		 $hex28= {247332353d20224c6f}
		 $hex29= {247332363d20226d73}
		 $hex30= {247332373d20224e65}
		 $hex31= {247332383d20224e6f}
		 $hex32= {247332393d20224f72}
		 $hex33= {2473323d2022323030}
		 $hex34= {247333303d20225061}
		 $hex35= {247333313d2022506c}
		 $hex36= {247333323d20225072}
		 $hex37= {247333333d20225261}
		 $hex38= {247333343d20225265}
		 $hex39= {247333353d20225265}
		 $hex40= {247333363d20225265}
		 $hex41= {247333373d20225245}
		 $hex42= {247333383d20225361}
		 $hex43= {247333393d20225365}
		 $hex44= {2473333d2022416c6c}
		 $hex45= {247334303d20225365}
		 $hex46= {247334313d20225365}
		 $hex47= {247334323d2022536f}
		 $hex48= {247334333d2022536f}
		 $hex49= {247334343d20225468}
		 $hex50= {247334353d20225468}
		 $hex51= {247334363d20225468}
		 $hex52= {247334373d20225468}
		 $hex53= {247334383d20225468}
		 $hex54= {247334393d20225f5f}
		 $hex55= {2473343d20222f623e}
		 $hex56= {247335303d2022556e}
		 $hex57= {247335313d2022556e}
		 $hex58= {247335323d20225577}
		 $hex59= {247335333d20225653}
		 $hex60= {247335343d20225769}
		 $hex61= {247335353d20227769}
		 $hex62= {247335363d2022576f}
		 $hex63= {247335373d2022576f}
		 $hex64= {247335383d20225772}
		 $hex65= {247335393d2022596f}
		 $hex66= {2473353d202243616e}
		 $hex67= {2473363d202243616e}
		 $hex68= {2473373d2022436f6e}
		 $hex69= {2473383d2022435243}
		 $hex70= {2473393d2022444352}

	condition:
		8 of them
}
