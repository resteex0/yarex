
/*
   YARA Rule Set
   Author: resteex
   Identifier: Poweliks 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Poweliks {
	meta: 
		 description= "Poweliks Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-37-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0181850239cd26b8fb8b72afb0e95eac"
		 hash2= "02884b95d5c3fde46c8ecd6ca409abd4"
		 hash3= "4a7ca7f2ad4cd92aa224485b687f52d9"
		 hash4= "a7ae1d1645bdbdf40471b1a3dc2a95f6"
		 hash5= "aeb9f61412c640319b61e1687d0860e5"
		 hash6= "c042511df4ce1f0305fb0cb1b84780a9"
		 hash7= "d6725d6f8c84afcb2e7eabe4683e0512"

	strings:

	
 		 $s1= "e/quiet /norestart" fullword wide
		 $s2= "FileDescription" fullword wide
		 $s3= "OriginalFilename" fullword wide
		 $s4= "VS_VERSION_INFO" fullword wide
		 $s5= "%windir%system32rundll32.exe" fullword wide

		 $hex1= {2473313d2022652f71}
		 $hex2= {2473323d202246696c}
		 $hex3= {2473333d20224f7269}
		 $hex4= {2473343d202256535f}
		 $hex5= {2473353d2022257769}

	condition:
		1 of them
}
