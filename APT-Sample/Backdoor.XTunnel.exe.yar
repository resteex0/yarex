
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Backdoor_XTunnel_exe 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Backdoor_XTunnel_exe {
	meta: 
		 description= "APT_Sample_Backdoor_XTunnel_exe Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-29_06-38-39" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "9e7053a4b6c9081220a694ec93211b4e"

	strings:

	
 		 $s1= "%)+/5;=CGIOSYaegkmq" fullword wide
		 $s2= "Accept-Encoding: gzip,deflate,sdch" fullword wide
		 $s3= "Cache-Control: max-age=0" fullword wide
		 $s4= "Connection: keep-alive" fullword wide
		 $s5= "LanmanWorkstation" fullword wide

		 $hex1= {25??29??2b??2f??35??3b??3d??43??47??49??4f??53??59??61??65??67??6b??6d??71??0a??}
		 $hex2= {41??63??63??65??70??74??2d??45??6e??63??6f??64??69??6e??67??3a??20??67??7a??69??70??2c??64??65??66??6c??61??74??65??2c??}
		 $hex3= {43??61??63??68??65??2d??43??6f??6e??74??72??6f??6c??3a??20??6d??61??78??2d??61??67??65??3d??30??0a??}
		 $hex4= {43??6f??6e??6e??65??63??74??69??6f??6e??3a??20??6b??65??65??70??2d??61??6c??69??76??65??0a??}
		 $hex5= {4c??61??6e??6d??61??6e??57??6f??72??6b??73??74??61??74??69??6f??6e??0a??}

	condition:
		5 of them
}
