
/*
   YARA Rule Set
   Author: resteex
   Identifier: Sanya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Sanya {
	meta: 
		 description= "Sanya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-15_00-18-38" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "3c51b2e7f4ae40ede74cdc4d1b60a68d"
		 hash2= "526ec99a8667a2286b9b6da1f4c70511"
		 hash3= "80a2d547f293da222a4365d1fb14e6de"
		 hash4= "85acfee86fd742ac5b6e347cd860324b"
		 hash5= "9d9d7ff558f9083d7d9281cac5d5d403"
		 hash6= "ae094056a41854ab04409c6f791194df"
		 hash7= "c21e299905613e5cd5d79432934e47e3"
		 hash8= "f15ef7b1c22aa23fa5de99980501b2dc"

	strings:

	
 		 $s1= "Control PanelDesktopResourceLocale" fullword wide
		 $s2= ".DEFAULTControl PanelInternational" fullword wide
		 $s3= "/FORCENOCLOSEAPPLICATIONS" fullword wide
		 $s4= "http://www.apache.org/licenses/LICENSE-2.0" fullword wide
		 $s5= "/RESTARTEXITCODE=exit code" fullword wide
		 $s6= "SoftwareBorlandDelphiLocales" fullword wide
		 $s7= "SoftwareCodeGearLocales" fullword wide
		 $s8= "SoftwareEmbarcaderoLocales" fullword wide
		 $s9= "Wow64DisableWow64FsRedirection" fullword wide
		 $s10= "Wow64RevertWow64FsRedirection" fullword wide

		 $hex1= {247331303d2022576f}
		 $hex2= {2473313d2022436f6e}
		 $hex3= {2473323d20222e4445}
		 $hex4= {2473333d20222f464f}
		 $hex5= {2473343d2022687474}
		 $hex6= {2473353d20222f5245}
		 $hex7= {2473363d2022536f66}
		 $hex8= {2473373d2022536f66}
		 $hex9= {2473383d2022536f66}
		 $hex10= {2473393d2022576f77}

	condition:
		6 of them
}
