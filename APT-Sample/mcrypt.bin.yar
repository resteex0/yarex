
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Ransomeware_mcrypt_bin 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Ransomeware_mcrypt_bin {
	meta: 
		 description= "APT_Sample_Ransomeware_mcrypt_bin Group" 
		 author = "Resteex Generator" 
		 date = "2022-04-26_03-25-00" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "97df21cfb5d664e1666f45e555feb372"

	strings:

	
 		 $s1= "Assembly Version" fullword wide
		 $s2= "CRPDOTNET3.Properties.Resources" fullword wide
		 $s3= "FileDescription" fullword wide
		 $s4= "GetDelegateForFunctionPointer" fullword wide
		 $s5= "OriginalFilename" fullword wide
		 $s6= "VS_VERSION_INFO" fullword wide

		 $hex1= {41??73??73??65??6d??62??6c??79??20??56??65??72??73??69??6f??6e??0a??}
		 $hex2= {43??52??50??44??4f??54??4e??45??54??33??2e??50??72??6f??70??65??72??74??69??65??73??2e??52??65??73??6f??75??72??63??65??}
		 $hex3= {46??69??6c??65??44??65??73??63??72??69??70??74??69??6f??6e??0a??}
		 $hex4= {47??65??74??44??65??6c??65??67??61??74??65??46??6f??72??46??75??6e??63??74??69??6f??6e??50??6f??69??6e??74??65??72??0a??}
		 $hex5= {4f??72??69??67??69??6e??61??6c??46??69??6c??65??6e??61??6d??65??0a??}
		 $hex6= {56??53??5f??56??45??52??53??49??4f??4e??5f??49??4e??46??4f??0a??}

	condition:
		6 of them
}
