
/*
   YARA Rule Set
   Author: resteex
   Identifier: EquationGroup_DoubleFantasy 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_EquationGroup_DoubleFantasy {
	meta: 
		 description= "EquationGroup_DoubleFantasy Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-52" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "2a12630ff976ba0994143ca93fecd17f"

	strings:

	
 		 $s1= "!#%')+-/13579;=?ACEGIKMOQSUWY[]_acegikmoq" fullword wide
		 $s2= "@DHLPTX`dhlpv|" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "OriginalFilename" fullword wide
		 $s5= "VS_VERSION_INFO" fullword wide
		 $a1= "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[]^_`abcdefghijklmnopq" fullword ascii
		 $a2= "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		 $a3= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a4= "actxprxy.DllGetClassObject" fullword ascii
		 $a5= "actxprxy.DllRegisterServer" fullword ascii
		 $a6= "actxprxy.DllUnregisterServer" fullword ascii
		 $a7= "Cyyyyyyyyyyyyyyyyyyyyyyyyyyxyyyxyyyyyyyyyyy L" fullword ascii
		 $a8= "ExpandEnvironmentStringsA" fullword ascii
		 $a9= "InitializeSecurityDescriptor" fullword ascii
		 $a10= "LdrQueryImageFileExecutionOptions" fullword ascii
		 $a11= "NNIJK=88T;N?KTHIH;T8H?ITIH:K@HAJ;:8H" fullword ascii
		 $a12= "oszhk}ny`qU_NSOSZH`kURXSKO" fullword ascii
		 $a13= "oszhk}ny`qU_NSOSZH`kURXSKO`" fullword ascii
		 $a14= "oSZHK]NY`qU_NSOSZH`kURXSKO`" fullword ascii
		 $a15= "oszhk}ny`qU_NSOSZH`uRHYNRYH" fullword ascii
		 $a16= "PsDereferencePrimaryToken" fullword ascii
		 $a17= "RegisterServiceCtrlHandlerW" fullword ascii
		 $a18= "RtlImageDirectoryEntryToData" fullword ascii
		 $a19= "SetSecurityDescriptorDacl" fullword ascii
		 $a20= "SetSecurityDescriptorGroup" fullword ascii
		 $a21= "SetSecurityDescriptorOwner" fullword ascii
		 $a22= "SetUnhandledExceptionFilter" fullword ascii
		 $a23= "SRHNSPoYH`oYNJU_YO`h_LUL`l]N]QYHYNO`kUROS_W" fullword ascii
		 $a24= "SRHNSPoYH`oYNJU_YO`jDx`jny{ohn" fullword ascii
		 $a25= "SRHNSP`oYOOUSRq]R][YN`wRSKRxppO" fullword ascii
		 $a26= "SRJYNHoHNUR[oY_INUHExYO_NULHSNhSoY_INUHExYO_NULHSN}" fullword ascii
		 $a27= "StartServiceCtrlDispatcherW" fullword ascii
		 $a28= "xyz}iph`oSZHK]NY`qU_NSOSZH`kURXSKO`" fullword ascii
		 $a29= "yyKIJWHLIWKJHWNJyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" fullword ascii
		 $a30= "yyyyyyyyyyyyyIIAWIIKWIIHWIIMyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" fullword ascii
		 $a31= "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyIIAWIIKWIIHWIIMyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" fullword ascii
		 $a32= "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyxyyyyyyyyyyyxyyy" fullword ascii
		 $a33= "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyP" fullword ascii
		 $a34= "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" fullword ascii

		 $hex1= {246131303d20224c64}
		 $hex2= {246131313d20224e4e}
		 $hex3= {246131323d20226f73}
		 $hex4= {246131333d20226f73}
		 $hex5= {246131343d20226f53}
		 $hex6= {246131353d20226f73}
		 $hex7= {246131363d20225073}
		 $hex8= {246131373d20225265}
		 $hex9= {246131383d20225274}
		 $hex10= {246131393d20225365}
		 $hex11= {2461313d20227c2424}
		 $hex12= {246132303d20225365}
		 $hex13= {246132313d20225365}
		 $hex14= {246132323d20225365}
		 $hex15= {246132333d20225352}
		 $hex16= {246132343d20225352}
		 $hex17= {246132353d20225352}
		 $hex18= {246132363d20225352}
		 $hex19= {246132373d20225374}
		 $hex20= {246132383d20227879}
		 $hex21= {246132393d20227979}
		 $hex22= {2461323d2022246161}
		 $hex23= {246133303d20227979}
		 $hex24= {246133313d20227979}
		 $hex25= {246133323d20227979}
		 $hex26= {246133333d20227979}
		 $hex27= {246133343d20227979}
		 $hex28= {2461333d2022414243}
		 $hex29= {2461343d2022616374}
		 $hex30= {2461353d2022616374}
		 $hex31= {2461363d2022616374}
		 $hex32= {2461373d2022437979}
		 $hex33= {2461383d2022457870}
		 $hex34= {2461393d2022496e69}
		 $hex35= {2473313d2022212325}
		 $hex36= {2473323d2022404448}
		 $hex37= {2473333d202246696c}
		 $hex38= {2473343d20224f7269}
		 $hex39= {2473353d202256535f}

	condition:
		4 of them
}
