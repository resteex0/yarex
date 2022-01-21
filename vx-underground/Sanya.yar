
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Sanya 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Sanya {
	meta: 
		 description= "vx_underground2_Sanya Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-09" 
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
		 $a1= "blib-dynload/_multiprocessing.cpython-39-x86_64-linux-gnu.so" fullword ascii
		 $a2= "System.Classes.TFieldsCache.TFields>" fullword ascii
		 $a3= "System.Integer,System.Classes.IInterfaceList>.TItem" fullword ascii
		 $a4= "System.Pointer,System.Rtti.TRttiObject>$>E" fullword ascii
		 $a5= "System.Pointer,System.Rtti.TRttiObject>.TItemArray" fullword ascii
		 $a6= "System.Rtti.TMethodImplementation.TParamLoc>.arrayofT" fullword ascii
		 $a7= "System.Rtti.TMethodImplementation.TParamLoc>.TEmptyFunc" fullword ascii
		 $a8= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator" fullword ascii
		 $a9= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator5" fullword ascii
		 $a10= "System.string,System.Cardinal>.TPairEnumerator;" fullword ascii
		 $a11= "System.string,System.Cardinal>.TPairEnumeratorHzH" fullword ascii
		 $a12= "System.string,System.Cardinal>.TValueCollection;" fullword ascii
		 $a13= "System.string,System.Cardinal>.TValueCollection0xH" fullword ascii
		 $a14= "System.string,System.Cardinal>.TValueEnumerator;" fullword ascii
		 $a15= "System.string,System.Cardinal>.TValueEnumeratorPvH" fullword ascii
		 $a16= "System.string,System.Classes.TPersistentClass>9" fullword ascii
		 $a17= "System.string,System.TypInfo.PTypeInfo>.TItemArray" fullword ascii
		 $a18= "System.TClass,System.Classes.TFieldsCache.TFields>" fullword ascii
		 $a19= "System.TClass,System.Classes.TFieldsCache.TFields>9" fullword ascii
		 $a20= "System.TypInfo.PTypeInfo,System.string>.TItemArray" fullword ascii

		 $hex1= {246131303d20225379}
		 $hex2= {246131313d20225379}
		 $hex3= {246131323d20225379}
		 $hex4= {246131333d20225379}
		 $hex5= {246131343d20225379}
		 $hex6= {246131353d20225379}
		 $hex7= {246131363d20225379}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20225379}
		 $hex10= {246131393d20225379}
		 $hex11= {2461313d2022626c69}
		 $hex12= {246132303d20225379}
		 $hex13= {2461323d2022537973}
		 $hex14= {2461333d2022537973}
		 $hex15= {2461343d2022537973}
		 $hex16= {2461353d2022537973}
		 $hex17= {2461363d2022537973}
		 $hex18= {2461373d2022537973}
		 $hex19= {2461383d2022537973}
		 $hex20= {2461393d2022537973}
		 $hex21= {247331303d2022576f}
		 $hex22= {2473313d2022436f6e}
		 $hex23= {2473323d20222e4445}
		 $hex24= {2473333d20222f464f}
		 $hex25= {2473343d2022687474}
		 $hex26= {2473353d20222f5245}
		 $hex27= {2473363d2022536f66}
		 $hex28= {2473373d2022536f66}
		 $hex29= {2473383d2022536f66}
		 $hex30= {2473393d2022576f77}

	condition:
		20 of them
}
