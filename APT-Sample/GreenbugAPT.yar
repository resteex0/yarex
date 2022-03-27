
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_GreenbugAPT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_GreenbugAPT {
	meta: 
		 description= "APT_Sample_GreenbugAPT Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-27_12-27-48" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "39ae8ced52d5b7b93e79c8727b5dd51c"
		 hash2= "73b2cfc5590ca3f431c8482d27f8e268"
		 hash3= "891f5fd5d09ea31df9a83449eae1500c"
		 hash4= "e0175eecf8d31a6f32da076d22ecbdff"
		 hash5= "f5ef3b060fb476253f9a7638f82940d9"

	strings:

	
 		 $s1= "american english" fullword wide
		 $s2= "american-english" fullword wide
		 $s3= "chinese-hongkong" fullword wide
		 $s4= "chinese-simplified" fullword wide
		 $s5= "chinese-singapore" fullword wide
		 $s6= "chinese-traditional" fullword wide
		 $s7= "english-american" fullword wide
		 $s8= "english-caribbean" fullword wide
		 $s9= "english-jamaica" fullword wide
		 $s10= "english-south africa" fullword wide
		 $s11= "french-canadian" fullword wide
		 $s12= "french-luxembourg" fullword wide
		 $s13= "german-austrian" fullword wide
		 $s14= "german-lichtenstein" fullword wide
		 $s15= "german-luxembourg" fullword wide
		 $s16= "MicrosoftWindows" fullword wide
		 $s17= "MicrosoftWindowsCRMFiles" fullword wide
		 $s18= "MicrosoftWindowsTempFiles" fullword wide
		 $s19= "MicrosoftWindowsTempFiles" fullword wide
		 $s20= "MicrosoftWindowsTempFiles" fullword wide

		 $hex1= {4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??0a??}
		 $hex2= {4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??43??52??4d??46??69??6c??65??73??0a??}
		 $hex3= {4d??69??63??72??6f??73??6f??66??74??57??69??6e??64??6f??77??73??54??65??6d??70??46??69??6c??65??73??0a??}
		 $hex4= {61??6d??65??72??69??63??61??6e??20??65??6e??67??6c??69??73??68??0a??}
		 $hex5= {61??6d??65??72??69??63??61??6e??2d??65??6e??67??6c??69??73??68??0a??}
		 $hex6= {63??68??69??6e??65??73??65??2d??68??6f??6e??67??6b??6f??6e??67??0a??}
		 $hex7= {63??68??69??6e??65??73??65??2d??73??69??6d??70??6c??69??66??69??65??64??0a??}
		 $hex8= {63??68??69??6e??65??73??65??2d??73??69??6e??67??61??70??6f??72??65??0a??}
		 $hex9= {63??68??69??6e??65??73??65??2d??74??72??61??64??69??74??69??6f??6e??61??6c??0a??}
		 $hex10= {65??6e??67??6c??69??73??68??2d??61??6d??65??72??69??63??61??6e??0a??}
		 $hex11= {65??6e??67??6c??69??73??68??2d??63??61??72??69??62??62??65??61??6e??0a??}
		 $hex12= {65??6e??67??6c??69??73??68??2d??6a??61??6d??61??69??63??61??0a??}
		 $hex13= {65??6e??67??6c??69??73??68??2d??73??6f??75??74??68??20??61??66??72??69??63??61??0a??}
		 $hex14= {66??72??65??6e??63??68??2d??63??61??6e??61??64??69??61??6e??0a??}
		 $hex15= {66??72??65??6e??63??68??2d??6c??75??78??65??6d??62??6f??75??72??67??0a??}
		 $hex16= {67??65??72??6d??61??6e??2d??61??75??73??74??72??69??61??6e??0a??}
		 $hex17= {67??65??72??6d??61??6e??2d??6c??69??63??68??74??65??6e??73??74??65??69??6e??0a??}
		 $hex18= {67??65??72??6d??61??6e??2d??6c??75??78??65??6d??62??6f??75??72??67??0a??}

	condition:
		21 of them
}
