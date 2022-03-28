
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_DPRK 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_DPRK {
	meta: 
		 description= "APT_Sample_DPRK Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_12-27-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "143cb4f16dcfc16a02812718acd32c8f"
		 hash2= "234b42fb42080176c6ffd240145f2c0c"
		 hash3= "3e36d7056812d0c1852e7b8f446b7e0f"
		 hash4= "4613f51087f01715bf9132c704aea2c2"
		 hash5= "4731cbaee7aca37b596e38690160a749"
		 hash6= "6a261443299788af1467142d5f538b2c"
		 hash7= "be6de8b0c3d1894eca18cdf8b6a37aa6"
		 hash8= "e3d03829cbec1a8cca56c6ae730ba9a8"
		 hash9= "eb9db98914207815d763e2e5cfbe96b9"

	strings:

	
 		 $s1= "#(-27;@EJOTY^chmrw|" fullword wide
		 $s2= "ABDCEFGHIJKLNMOPQRSTVUWXYZ" fullword wide
		 $s3= "[Accept Thread]" fullword wide
		 $s4= "Adobe Photoshop" fullword wide
		 $s5= "Assembly Version" fullword wide
		 $s6= "com.security01.android.fastapplock" fullword wide
		 $s7= "com.studioapplock.free.android" fullword wide
		 $s8= "com.umsikgonghap.health.gonghap" fullword wide
		 $s9= "ConsoleApp5.exe" fullword wide
		 $s10= "ConsoleApp5.Resources" fullword wide
		 $s11= "C:SoftwaresInstall" fullword wide
		 $s12= "C:SoftwaresInstallsoft" fullword wide
		 $s13= "C:WindowsSys64" fullword wide
		 $s14= "C:WindowsSys64intelservice.exe" fullword wide
		 $s15= "C:WindowsSys64updater.exe" fullword wide
		 $s16= "ExpandEnvironmentStrings" fullword wide
		 $s17= "FileDescription" fullword wide
		 $s18= "LegalTrademarks" fullword wide
		 $s19= "licence/key.dat" fullword wide
		 $s20= "licencelicence.dat" fullword wide

		 $hex1= {23??28??2d??32??37??3b??40??45??4a??4f??54??59??5e??63??68??6d??72??77??7c??0a??}
		 $hex2= {41??42??44??43??45??46??47??48??49??4a??4b??4c??4e??4d??4f??50??51??52??53??54??56??55??57??58??59??5a??0a??}
		 $hex3= {41??64??6f??62??65??20??50??68??6f??74??6f??73??68??6f??70??0a??}
		 $hex4= {41??73??73??65??6d??62??6c??79??20??56??65??72??73??69??6f??6e??0a??}
		 $hex5= {43??3a??53??6f??66??74??77??61??72??65??73??49??6e??73??74??61??6c??6c??0a??}
		 $hex6= {43??3a??53??6f??66??74??77??61??72??65??73??49??6e??73??74??61??6c??6c??73??6f??66??74??0a??}
		 $hex7= {43??3a??57??69??6e??64??6f??77??73??53??79??73??36??34??0a??}
		 $hex8= {43??3a??57??69??6e??64??6f??77??73??53??79??73??36??34??69??6e??74??65??6c??73??65??72??76??69??63??65??2e??65??78??65??}
		 $hex9= {43??3a??57??69??6e??64??6f??77??73??53??79??73??36??34??75??70??64??61??74??65??72??2e??65??78??65??0a??}
		 $hex10= {43??6f??6e??73??6f??6c??65??41??70??70??35??2e??52??65??73??6f??75??72??63??65??73??0a??}
		 $hex11= {43??6f??6e??73??6f??6c??65??41??70??70??35??2e??65??78??65??0a??}
		 $hex12= {45??78??70??61??6e??64??45??6e??76??69??72??6f??6e??6d??65??6e??74??53??74??72??69??6e??67??73??0a??}
		 $hex13= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex14= {4c??65??67??61??6c??54??72??61??64??65??6d??61??72??6b??73??0a??}
		 $hex15= {5b??41??63??63??65??70??74??20??54??68??72??65??61??64??5d??0a??}
		 $hex16= {63??6f??6d??2e??73??65??63??75??72??69??74??79??30??31??2e??61??6e??64??72??6f??69??64??2e??66??61??73??74??61??70??70??}
		 $hex17= {63??6f??6d??2e??73??74??75??64??69??6f??61??70??70??6c??6f??63??6b??2e??66??72??65??65??2e??61??6e??64??72??6f??69??64??}
		 $hex18= {63??6f??6d??2e??75??6d??73??69??6b??67??6f??6e??67??68??61??70??2e??68??65??61??6c??74??68??2e??67??6f??6e??67??68??61??}
		 $hex19= {6c??69??63??65??6e??63??65??2f??6b??65??79??2e??64??61??74??0a??}
		 $hex20= {6c??69??63??65??6e??63??65??6c??69??63??65??6e??63??65??2e??64??61??74??0a??}

	condition:
		22 of them
}