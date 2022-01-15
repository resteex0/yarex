
/*
   YARA Rule Set
   Author: resteex
   Identifier: NjRat 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_NjRat {
	meta: 
		 description= "NjRat Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-15-54" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "09983f8a77b8aec0f5fb58adccf88a38"
		 hash2= "11b79281a25da1b798574f667c56898b"
		 hash3= "1d3baedd747f6f9bf92c81eb9f63b34b"
		 hash4= "2013385034e5c8dfbbe47958fd821ca0"
		 hash5= "2164c555f9f23dca54e76b94b1747480"
		 hash6= "24cc5b811a7f9591e7f2cb9a818be104"
		 hash7= "29daad42dafffab5e0f1f96d620e7392"
		 hash8= "2bf859ea02ae3340cd66eb5e46b1a704"
		 hash9= "2cdbbe5045bed2031a1fc77c3e30e719"
		 hash10= "3ad5fded9d7fdf1c2f6102f4874b2d52"
		 hash11= "3b99f596b36ece7b6add78e3b14a3b17"
		 hash12= "4168543695513f767ba44997ebd71431"
		 hash13= "5fcb5282da1a2a0f053051c8da1686ef"
		 hash14= "60f1b8980d109a556922d5000ae02010"
		 hash15= "63781fe1932e612c6c29225d25515111"
		 hash16= "6941cce26c58b37968c191d366cba43e"
		 hash17= "79dce17498e1997264346b162b09bde8"
		 hash18= "7c42d2426c51318f5947a92bf23e1686"
		 hash19= "7e34abdd10c5c763291e69a886452849"
		 hash20= "92ee1fb5df21d8cfafa2b02b6a25bd3b"
		 hash21= "a669c0da6309a930af16381b18ba2f9d"
		 hash22= "a6da3b63981e345e1c3cd58c6e3dc7fc"
		 hash23= "a98b4c99f64315aac9dd992593830f35"
		 hash24= "b0a43598ad5a48a9c244f9d52135dcbd"
		 hash25= "c6597320431c3e82d1bfc796396c7953"
		 hash26= "d0aa862e7e3d80ed48ab0bfe0eb3dec8"
		 hash27= "e1471b169d6b4049d757bb705877d329"
		 hash28= "e3612d6ee0006451547cf0fc8e1bd116"
		 hash29= "e419475aef86f5fd60955c438d46209d"
		 hash30= "f4777ed999fd8352227e750ac0e1b85d"
		 hash31= "f6b4a2be06fc3ba4bb02d1bcbea328fe"
		 hash32= "fb671c8735461809534813b818d193f4"
		 hash33= "fc96a7e27b1d3dab715b2732d5c86f80"

	strings:

	
 		 $s1= "2KrZhNi62YrZhSDYtNiu2LXZig==" fullword wide
		 $s2= "414ea57b-9d96-4762-b9af-449cf3eaf5c3" fullword wide
		 $s3= "4d8ac9ca-9328-4cc0-b51d-d4eea7a8ad1c" fullword wide
		 $s4= "4GUdy50hHTSocuOHIF.4AJkkAJmdLHZu7rBEj" fullword wide
		 $s5= "9.00.8112.16421 (WIN7_IE9_RTM.110308-0330)" fullword wide
		 $s6= "bade819c-56b8-454e-972a-378c5701a384" fullword wide
		 $s7= "bc8d93de-7382-4e64-98ee-de472c07611e" fullword wide
		 $s8= "C:UsersuserDesktopServer.exe" fullword wide
		 $s9= "eWhD7eqExAsqeKbX2B.eIWHO27RSiPKUCZjOj" fullword wide
		 $s10= "EXTRACTOPT FILESIZES FINISHMSG" fullword wide
		 $s11= "OneDrive.Properties.Resources" fullword wide
		 $s12= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s13= "SOFTWAREMicrosoftWindows NTCurrentVersion" fullword wide
		 $s14= "System.Reflection.Assembly" fullword wide
		 $s15= "VXyQgrmiDEOxZCcHKL.ZqUBUmaPhLPhgb0YRB" fullword wide
		 $s16= "WinForms_RecursiveFormCreate" fullword wide
		 $s17= "WinForms_SeeInnerException" fullword wide
		 $s18= "www.upload.ee/image/2298158/koli.swf" fullword wide
		 $s19= "www.upload.ee/image/2299952/facey.swf" fullword wide
		 $s20= "www.upload.ee/image/2971847/scare4.swf" fullword wide
		 $s21= "Y)!Y61Y)9YFAYKQYKYYKaYKiYKqYKyYF" fullword wide
		 $s22= "Y)!Y61YAAYAIYAQYAYYAaYFiYAqYAyYF" fullword wide

		 $hex1= {247331303d20224558}
		 $hex2= {247331313d20224f6e}
		 $hex3= {247331323d2022536f}
		 $hex4= {247331333d2022534f}
		 $hex5= {247331343d20225379}
		 $hex6= {247331353d20225658}
		 $hex7= {247331363d20225769}
		 $hex8= {247331373d20225769}
		 $hex9= {247331383d20227777}
		 $hex10= {247331393d20227777}
		 $hex11= {2473313d2022324b72}
		 $hex12= {247332303d20227777}
		 $hex13= {247332313d20225929}
		 $hex14= {247332323d20225929}
		 $hex15= {2473323d2022343134}
		 $hex16= {2473333d2022346438}
		 $hex17= {2473343d2022344755}
		 $hex18= {2473353d2022392e30}
		 $hex19= {2473363d2022626164}
		 $hex20= {2473373d2022626338}
		 $hex21= {2473383d2022433a55}
		 $hex22= {2473393d2022655768}

	condition:
		14 of them
}
