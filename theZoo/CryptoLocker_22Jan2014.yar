
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_22Jan2014 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_22Jan2014 {
	meta: 
		 description= "CryptoLocker_22Jan2014 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-45" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "0246bb54723bd4a49444aa4ca254845a"
		 hash2= "829dde7015c32d7d77d8128665390dab"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "COR_ENABLE_PROFILING" fullword wide
		 $s3= "Debugger detected (Managed)" fullword wide
		 $s4= "FileDescription" fullword wide
		 $s5= "Microsoft Windows Auto Update" fullword wide
		 $s6= "Microsoft Windows Auto Update.exe" fullword wide
		 $s7= "OriginalFilename" fullword wide
		 $s8= "Profiler detected" fullword wide
		 $s9= "VS_VERSION_INFO" fullword wide
		 $a1= "$cfefd6f2-f8aa-45fa-bab9-3522be66bf82" fullword ascii
		 $a2= "3System.Resources.Tools.StronglyTypedResourceBuilder" fullword ascii
		 $a3= "AssemblyConfigurationAttribute" fullword ascii
		 $a4= "AssemblyCopyrightAttribute" fullword ascii
		 $a5= "AssemblyDescriptionAttribute" fullword ascii
		 $a6= "AssemblyFileVersionAttribute" fullword ascii
		 $a7= "AssemblyTrademarkAttribute" fullword ascii
		 $a8= "CompilationRelaxationsAttribute" fullword ascii
		 $a9= "CompilerGeneratedAttribute" fullword ascii
		 $a10= "DebuggerNonUserCodeAttribute" fullword ascii
		 $a11= "GetManifestResourceStream" fullword ascii
		 $a12= "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" fullword ascii
		 $a13= "LinkLabelLinkClickedEventArgs" fullword ascii
		 $a14= "LinkLabelLinkClickedEventHandler" fullword ascii
		 $a15= "NtQueryInformationProcess" fullword ascii
		 $a16= "RuntimeCompatibilityAttribute" fullword ascii
		 $a17= "SetCompatibleTextRenderingDefault" fullword ascii
		 $a18= "set_MarqueeAnimationSpeed" fullword ascii
		 $a19= "set_UseCompatibleStateImageBehavior" fullword ascii
		 $a20= "set_UseVisualStyleBackColor" fullword ascii
		 $a21= "SHA1CryptoServiceProvider" fullword ascii
		 $a22= "System.Collections.Generic" fullword ascii
		 $a23= "System.Runtime.CompilerServices" fullword ascii
		 $a24= "System.Runtime.InteropServices" fullword ascii
		 $a25= "System.Security.Cryptography" fullword ascii
		 $a26= "System.Text.RegularExpressions" fullword ascii

		 $hex1= {246131303d20224465}
		 $hex2= {246131313d20224765}
		 $hex3= {246131323d20224b4d}
		 $hex4= {246131333d20224c69}
		 $hex5= {246131343d20224c69}
		 $hex6= {246131353d20224e74}
		 $hex7= {246131363d20225275}
		 $hex8= {246131373d20225365}
		 $hex9= {246131383d20227365}
		 $hex10= {246131393d20227365}
		 $hex11= {2461313d2022246366}
		 $hex12= {246132303d20227365}
		 $hex13= {246132313d20225348}
		 $hex14= {246132323d20225379}
		 $hex15= {246132333d20225379}
		 $hex16= {246132343d20225379}
		 $hex17= {246132353d20225379}
		 $hex18= {246132363d20225379}
		 $hex19= {2461323d2022335379}
		 $hex20= {2461333d2022417373}
		 $hex21= {2461343d2022417373}
		 $hex22= {2461353d2022417373}
		 $hex23= {2461363d2022417373}
		 $hex24= {2461373d2022417373}
		 $hex25= {2461383d2022436f6d}
		 $hex26= {2461393d2022436f6d}
		 $hex27= {2473313d2022417373}
		 $hex28= {2473323d2022434f52}
		 $hex29= {2473333d2022446562}
		 $hex30= {2473343d202246696c}
		 $hex31= {2473353d20224d6963}
		 $hex32= {2473363d20224d6963}
		 $hex33= {2473373d20224f7269}
		 $hex34= {2473383d202250726f}
		 $hex35= {2473393d202256535f}

	condition:
		4 of them
}
