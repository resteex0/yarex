
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Turla 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Turla {
	meta: 
		 description= "APT_Sample_Turla Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_02-24-07" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "25ad1d40b05d9b6978d352b490e7b93f"
		 hash2= "2ced6205942be2349da93af07170bdfd"
		 hash3= "38ff4b9747c1e6462d8fc31d5455cca2"
		 hash4= "59b57bdabee2ce1fb566de51dd92ec94"
		 hash5= "7009af646c6c3e6abc0af744152ca968"
		 hash6= "a352f93e5f63bbf5cd0905c38f054d27"
		 hash7= "af8889f4705145d4390ee8d581f45436"
		 hash8= "d891c9374ccb2a4cae2274170e8644d8"
		 hash9= "ea874ac436223b30743fc9979eed5f2f"
		 hash10= "edfd33d319af1cce7baa1b15b52940e7"
		 hash11= "ff8c3f362d7c9b9a19cfa09b4b3cfc75"

	strings:

	
 		 $s1= "%02d:%02d:%04d %02d:%02d:%02d" fullword wide
		 $s2= "%04d%02d%02d.pdf" fullword wide
		 $s3= "1x1transparent.pngh" fullword wide
		 $s4= "6.01.7600.16385" fullword wide
		 $s5= "/Account_Name>" fullword wide
		 $s6= "AddToFlightGroup" fullword wide
		 $s7= "/AppendLog>" fullword wide
		 $s8= "application/xhtml+xml" fullword wide
		 $s9= "AppxManifest.xml" fullword wide
		 $s10= "Assembly Version" fullword wide
		 $s11= "bytecoinwallet.wallet" fullword wide
		 $s12= "C:6gCzH5r1.exe" fullword wide
		 $s13= "c_barcodescanner.inf" fullword wide
		 $s14= "c_biometric.inf" fullword wide
		 $s15= "c_cashdrawer.inf" fullword wide
		 $s16= "c_diskdrive.inf" fullword wide
		 $s17= "c_dot4print.inf" fullword wide
		 $s18= "c_extension.inf" fullword wide
		 $s19= "c_floppydisk.inf" fullword wide
		 $s20= "c_fsactivitymonitor.inf" fullword wide

		 $hex1= {25??30??32??64??3a??25??30??32??64??3a??25??30??34??64??20??25??30??32??64??3a??25??30??32??64??3a??25??30??32??64??0a??}
		 $hex2= {25??30??34??64??25??30??32??64??25??30??32??64??2e??70??64??66??0a??}
		 $hex3= {2f??41??63??63??6f??75??6e??74??5f??4e??61??6d??65??3e??0a??}
		 $hex4= {2f??41??70??70??65??6e??64??4c??6f??67??3e??0a??}
		 $hex5= {31??78??31??74??72??61??6e??73??70??61??72??65??6e??74??2e??70??6e??67??68??0a??}
		 $hex6= {36??2e??30??31??2e??37??36??30??30??2e??31??36??33??38??35??0a??}
		 $hex7= {41??64??64??54??6f??46??6c??69??67??68??74??47??72??6f??75??70??0a??}
		 $hex8= {41??70??70??78??4d??61??6e??69??66??65??73??74??2e??78??6d??6c??0a??}
		 $hex9= {41??73??73??65??6d??62??6c??79??20??56??65??72??73??69??6f??6e??0a??}
		 $hex10= {43??3a??36??67??43??7a??48??35??72??31??2e??65??78??65??0a??}
		 $hex11= {61??70??70??6c??69??63??61??74??69??6f??6e??2f??78??68??74??6d??6c??2b??78??6d??6c??0a??}
		 $hex12= {62??79??74??65??63??6f??69??6e??77??61??6c??6c??65??74??2e??77??61??6c??6c??65??74??0a??}
		 $hex13= {63??5f??62??61??72??63??6f??64??65??73??63??61??6e??6e??65??72??2e??69??6e??66??0a??}
		 $hex14= {63??5f??62??69??6f??6d??65??74??72??69??63??2e??69??6e??66??0a??}
		 $hex15= {63??5f??63??61??73??68??64??72??61??77??65??72??2e??69??6e??66??0a??}
		 $hex16= {63??5f??64??69??73??6b??64??72??69??76??65??2e??69??6e??66??0a??}
		 $hex17= {63??5f??64??6f??74??34??70??72??69??6e??74??2e??69??6e??66??0a??}
		 $hex18= {63??5f??65??78??74??65??6e??73??69??6f??6e??2e??69??6e??66??0a??}
		 $hex19= {63??5f??66??6c??6f??70??70??79??64??69??73??6b??2e??69??6e??66??0a??}
		 $hex20= {63??5f??66??73??61??63??74??69??76??69??74??79??6d??6f??6e??69??74??6f??72??2e??69??6e??66??0a??}

	condition:
		22 of them
}
