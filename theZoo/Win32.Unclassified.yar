
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Unclassified 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Unclassified {
	meta: 
		 description= "Win32_Unclassified Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-34-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1c234a8879840da21f197b2608a164c9"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "System.Reflection.Assembly" fullword wide
		 $s5= "System.Security.Cryptography.RijndaelManaged" fullword wide
		 $s6= "System.Security.Cryptography.SymmetricAlgorithm" fullword wide
		 $s7= "TransformFinalBlock" fullword wide
		 $s8= "VS_VERSION_INFO" fullword wide
		 $a1= "AssemblyCopyrightAttribute" fullword ascii
		 $a2= "AssemblyDescriptionAttribute" fullword ascii
		 $a3= "AssemblyFileVersionAttribute" fullword ascii
		 $a4= "CompilationRelaxationsAttribute" fullword ascii
		 $a5= "Microsoft.VisualBasic.CompilerServices" fullword ascii
		 $a6= "N7N(N@N0N)N^N^NyN,N9N0N]NLN" fullword ascii
		 $a7= "NFN!NtNTNmN2N'N?NLN:NxN_NjN]N;N" fullword ascii
		 $a8= "N.NMNiNvNpNhNkN&NSN8NBN{NcN=N" fullword ascii
		 $a9= "NzN(N?NfN(NeNuN^N`NWN0N:NSN" fullword ascii
		 $a10= "RuntimeCompatibilityAttribute" fullword ascii
		 $a11= "System.Runtime.CompilerServices" fullword ascii
		 $a12= "UnverifiableCodeAttribute" fullword ascii

		 $hex1= {246131303d20225275}
		 $hex2= {246131313d20225379}
		 $hex3= {246131323d2022556e}
		 $hex4= {2461313d2022417373}
		 $hex5= {2461323d2022417373}
		 $hex6= {2461333d2022417373}
		 $hex7= {2461343d2022436f6d}
		 $hex8= {2461353d20224d6963}
		 $hex9= {2461363d20224e374e}
		 $hex10= {2461373d20224e464e}
		 $hex11= {2461383d20224e2e4e}
		 $hex12= {2461393d20224e7a4e}
		 $hex13= {2473313d2022417373}
		 $hex14= {2473323d202246696c}
		 $hex15= {2473333d20224f7269}
		 $hex16= {2473343d2022537973}
		 $hex17= {2473353d2022537973}
		 $hex18= {2473363d2022537973}
		 $hex19= {2473373d2022547261}
		 $hex20= {2473383d202256535f}

	condition:
		2 of them
}
