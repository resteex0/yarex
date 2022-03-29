
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_APT29 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_APT29 {
	meta: 
		 description= "APT_Sample_APT29 Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-47-41" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "004b55a66b3a86a1ce0a0b9b69b95976"
		 hash2= "3d3363598f87c78826c859077606e514"
		 hash3= "452ee2968ec82c7e30c21c828b330c17"
		 hash4= "887489b27f6e7053ec2702dc8ba51af7"
		 hash5= "ce227ae503e166b77bf46b6c8f5ee4da"
		 hash6= "f08ef840f59cbd4c4695e36ef3eaa9d7"

	strings:

	
 		 $s1= "FileDescription" fullword wide
		 $s2= "OriginalFilename" fullword wide
		 $s3= "VS_VERSION_INFO" fullword wide

		 $hex1= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex2= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex3= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		3 of them
}
