
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GreyEnergyAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GreyEnergyAPT {
	meta: 
		 description= "APT_Sample_GreyEnergyAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_08-13-55" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "1cb35f4340a37e75aff1f901629b59f3"
		 hash2= "446d226cedf08866dbe528868cba2007"
		 hash3= "7a7103a5fc1cf7c4b6eef1a6935554b7"
		 hash4= "815a60e33e51b713bd37431c98d34bc5"
		 hash5= "e3a2c3a025d1aee589026d09e2a0ca50"

	strings:

	
 		 $s1= "TPVCGateway [-q]{-install|-uninstall|-setup}" fullword wide

		 $hex1= {54??50??56??43??47??61??74??65??77??61??79??20??5b??2d??71??5d??7b??2d??69??6e??73??74??61??6c??6c??7c??2d??75??6e??69??}

	condition:
		1 of them
}
