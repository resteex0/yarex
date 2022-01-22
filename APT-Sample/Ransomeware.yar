
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Ransomeware 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Ransomeware {
	meta: 
		 description= "APT_Sample_Ransomeware Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-22_17-57-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0805cb0e64e34711530c95e58e38c11f"
		 hash2= "27a75b8bdbaaf7ebe18bca7aadd0a4dd"
		 hash3= "2828d886337d31c03d7c3fa477b16c87"
		 hash4= "30fe2f9a048d7a734c8d9233f64810ba"
		 hash5= "58b39bb94660958b6180588109c34f51"
		 hash6= "5a131b48f147586afa20b0a1a00a1533"
		 hash7= "71b6a493388e7d0b40c83ce903bc6b04"
		 hash8= "7f87db33980c0099739de40d1b725500"
		 hash9= "8b05fdda95adfd8ee925b0f0c773c777"
		 hash10= "97df21cfb5d664e1666f45e555feb372"
		 hash11= "9f3ea1850f9d879de8a36dc778dfffba"
		 hash12= "a93bd199d34d21cc9102600c6ce782cf"
		 hash13= "ad11e4ce54e0c37b77fc47efe6f6ddd1"
		 hash14= "f42d29367786af1b8919a9d0cbedfd3f"

	strings:

	
 		 $s1= "(2-low,3-user,4-admin,5-system,6-protected_system)" fullword wide
		 $s2= "90928fd1250435589cc0150849bc0cff" fullword wide
		 $s3= "bffe72ccbadadc8c3fb178799681755c" fullword wide
		 $s4= "CRPDOTNET3.Properties.Resources" fullword wide
		 $s5= "djysyfasfgjhkashfi8atwtfegs" fullword wide
		 $s6= "GetDelegateForFunctionPointer" fullword wide
		 $s7= "InitializeConditionVariable" fullword wide
		 $s8= "jei4tgvrcqbwaunkerki7fywetuyg" fullword wide
		 $s9= "jsbggye984s76t5gwnekfqwurrtwiesyfg" fullword wide
		 $s10= "Lenovo.LSC.AlertsChangedNotification" fullword wide
		 $s11= "LKNMOMPMVUWUXU[ZZ^]_]cbdbjikili" fullword wide
		 $s12= "SoftwareBorlandDelphiLocales" fullword wide
		 $s13= "SoftwareCodeGearLocales" fullword wide
		 $s14= "SoftwareEmbarcaderoLocales" fullword wide
		 $s15= "SoftwareMicrosoftWindowsCurrentVersionExplorerShell Folders" fullword wide
		 $s16= "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide
		 $s17= "wowsmith123456@posteo.net." fullword wide
		 $a1= "System.Integer,System.Classes.IInterfaceList>.TItem" fullword ascii
		 $a2= "System.Pointer,System.Rtti.TRttiObject>.TItemArray" fullword ascii
		 $a3= "System.Rtti.TMethodImplementation.TParamLoc>" fullword ascii
		 $a4= "System.Rtti.TMethodImplementation.TParamLoc>0!@" fullword ascii
		 $a5= "System.Rtti.TMethodImplementation.TParamLoc>.arrayofT" fullword ascii
		 $a6= "System.Rtti.TMethodImplementation.TParamLoc>d" fullword ascii
		 $a7= "System.Rtti.TMethodImplementation.TParamLoc>g" fullword ascii
		 $a8= "System.Rtti.TMethodImplementation.TParamLoc>hLC" fullword ascii
		 $a9= "System.Rtti.TMethodImplementation.TParamLoc>pLC" fullword ascii
		 $a10= "System.Rtti.TMethodImplementation.TParamLoc>PXC" fullword ascii
		 $a11= "System.Rtti.TMethodImplementation.TParamLoc>.TEmptyFunc" fullword ascii
		 $a12= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator" fullword ascii
		 $a13= "System.Rtti.TMethodImplementation.TParamLoc>.TEnumerator5" fullword ascii
		 $a14= "System.string,System.Classes.TPersistentClass>0>H" fullword ascii
		 $a15= "System.string,System.Classes.TPersistentClass>8>H" fullword ascii
		 $a16= "System.string,System.Classes.TPersistentClass>9" fullword ascii
		 $a17= "System.string,System.TypInfo.PTypeInfo>.TItemArray" fullword ascii
		 $a18= "System.TypInfo.PTypeInfo,System.string>.TItemArray" fullword ascii

		 $hex1= {246131303d20225379}
		 $hex2= {246131313d20225379}
		 $hex3= {246131323d20225379}
		 $hex4= {246131333d20225379}
		 $hex5= {246131343d20225379}
		 $hex6= {246131353d20225379}
		 $hex7= {246131363d20225379}
		 $hex8= {246131373d20225379}
		 $hex9= {246131383d20225379}
		 $hex10= {2461313d2022537973}
		 $hex11= {2461323d2022537973}
		 $hex12= {2461333d2022537973}
		 $hex13= {2461343d2022537973}
		 $hex14= {2461353d2022537973}
		 $hex15= {2461363d2022537973}
		 $hex16= {2461373d2022537973}
		 $hex17= {2461383d2022537973}
		 $hex18= {2461393d2022537973}
		 $hex19= {247331303d20224c65}
		 $hex20= {247331313d20224c4b}
		 $hex21= {247331323d2022536f}
		 $hex22= {247331333d2022536f}
		 $hex23= {247331343d2022536f}
		 $hex24= {247331353d2022536f}
		 $hex25= {247331363d20225379}
		 $hex26= {247331373d2022776f}
		 $hex27= {2473313d202228322d}
		 $hex28= {2473323d2022393039}
		 $hex29= {2473333d2022626666}
		 $hex30= {2473343d2022435250}
		 $hex31= {2473353d2022646a79}
		 $hex32= {2473363d2022476574}
		 $hex33= {2473373d2022496e69}
		 $hex34= {2473383d20226a6569}
		 $hex35= {2473393d20226a7362}

	condition:
		23 of them
}
