
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
		 date = "2022-03-27_08-15-29" 
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

		 $hex1= {28??32??2d??6c??6f??77??2c??33??2d??75??73??65??72??2c??34??2d??61??64??6d??69??6e??2c??35??2d??73??79??73??74??65??6d??}
		 $hex2= {39??30??39??32??38??66??64??31??32??35??30??34??33??35??35??38??39??63??63??30??31??35??30??38??34??39??62??63??30??63??}
		 $hex3= {43??52??50??44??4f??54??4e??45??54??33??2e??50??72??6f??70??65??72??74??69??65??73??2e??52??65??73??6f??75??72??63??65??}
		 $hex4= {47??65??74??44??65??6c??65??67??61??74??65??46??6f??72??46??75??6e??63??74??69??6f??6e??50??6f??69??6e??74??65??72??0a??}
		 $hex5= {49??6e??69??74??69??61??6c??69??7a??65??43??6f??6e??64??69??74??69??6f??6e??56??61??72??69??61??62??6c??65??0a??}
		 $hex6= {4c??4b??4e??4d??4f??4d??50??4d??56??55??57??55??58??55??5b??5a??5a??5e??5d??5f??5d??63??62??64??62??6a??69??6b??69??6c??}
		 $hex7= {4c??65??6e??6f??76??6f??2e??4c??53??43??2e??41??6c??65??72??74??73??43??68??61??6e??67??65??64??4e??6f??74??69??66??69??}
		 $hex8= {53??6f??66??74??77??61??72??65??42??6f??72??6c??61??6e??64??44??65??6c??70??68??69??4c??6f??63??61??6c??65??73??0a??}
		 $hex9= {53??6f??66??74??77??61??72??65??43??6f??64??65??47??65??61??72??4c??6f??63??61??6c??65??73??0a??}
		 $hex10= {53??6f??66??74??77??61??72??65??45??6d??62??61??72??63??61??64??65??72??6f??4c??6f??63??61??6c??65??73??0a??}
		 $hex11= {53??6f??66??74??77??61??72??65??4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??43??75??72??72??65??6e??}
		 $hex12= {53??79??73??74??65??6d??2e??49??6e??74??65??67??65??72??2c??53??79??73??74??65??6d??2e??43??6c??61??73??73??65??73??2e??}
		 $hex13= {53??79??73??74??65??6d??2e??50??6f??69??6e??74??65??72??2c??53??79??73??74??65??6d??2e??52??74??74??69??2e??54??52??74??}
		 $hex14= {53??79??73??74??65??6d??2e??52??74??74??69??2e??54??4d??65??74??68??6f??64??49??6d??70??6c??65??6d??65??6e??74??61??74??}
		 $hex15= {53??79??73??74??65??6d??2e??53??65??63??75??72??69??74??79??2e??43??72??79??70??74??6f??67??72??61??70??68??79??2e??41??}
		 $hex16= {53??79??73??74??65??6d??2e??54??79??70??49??6e??66??6f??2e??50??54??79??70??65??49??6e??66??6f??2c??53??79??73??74??65??}
		 $hex17= {53??79??73??74??65??6d??2e??73??74??72??69??6e??67??2c??53??79??73??74??65??6d??2e??43??6c??61??73??73??65??73??2e??54??}
		 $hex18= {53??79??73??74??65??6d??2e??73??74??72??69??6e??67??2c??53??79??73??74??65??6d??2e??54??79??70??49??6e??66??6f??2e??50??}
		 $hex19= {62??66??66??65??37??32??63??63??62??61??64??61??64??63??38??63??33??66??62??31??37??38??37??39??39??36??38??31??37??35??}
		 $hex20= {64??6a??79??73??79??66??61??73??66??67??6a??68??6b??61??73??68??66??69??38??61??74??77??74??66??65??67??73??0a??}
		 $hex21= {6a??65??69??34??74??67??76??72??63??71??62??77??61??75??6e??6b??65??72??6b??69??37??66??79??77??65??74??75??79??67??0a??}
		 $hex22= {6a??73??62??67??67??79??65??39??38??34??73??37??36??74??35??67??77??6e??65??6b??66??71??77??75??72??72??74??77??69??65??}
		 $hex23= {77??6f??77??73??6d??69??74??68??31??32??33??34??35??36??40??70??6f??73??74??65??6f??2e??6e??65??74??2e??0a??}

	condition:
		32 of them
}
