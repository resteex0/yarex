
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_Phorpiex 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_Phorpiex {
	meta: 
		 description= "vx_underground2_Phorpiex Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-32" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a49900b4492f43b68331af062731f33"
		 hash2= "1f6e817f7722e3d830d1bfe27386c346"
		 hash3= "339cf597f2c1a184b393fcd2d7396079"
		 hash4= "532dbd62612ff358ab0278de291144b4"
		 hash5= "5bbd9bc7dafd0a6076ed450aa18afc0a"
		 hash6= "8e217c91e2dc1df76026f1177c1c6e4e"
		 hash7= "9857fb8f7630b354f482c3f6c65a3083"
		 hash8= "9fa3010c557db8477aec95587748dc82"
		 hash9= "a2f1c7def6b73a5bbbdfea5c01482d87"
		 hash10= "ade8d1af64fafc95075e8f95791960f8"
		 hash11= "ae3acfb74780b06e60c44e545597d5d4"
		 hash12= "b09d1bafa47c8c3f9a4707b24512e734"
		 hash13= "b53466259125d66deb6ef9d787fa1b13"
		 hash14= "b8773ca78a7a972aac9237895022b78e"
		 hash15= "bd5f71fcdba70236587930dddef0e59a"
		 hash16= "bfbde2f75d5dfcf956309091dc25a2c7"
		 hash17= "c532ac418f3e867907c2757a7ca56a53"
		 hash18= "e3fb1eb78c7e953d76de0b973e069d16"
		 hash19= "ec96bcc50ca8fa91821e820fdfe30915"
		 hash20= "ed40a3a099ae7106b15a9cb97e9cb8d3"
		 hash21= "f3d5e93d9ca3791de71a436f91f1fcd0"
		 hash22= "f60b2f25c72f60ce52d7c8abd3203e73"

	strings:

	
 		 $s1= "SoftwareMicrosoftWindowsCurrentVersionPoliciesExplorer" fullword wide
		 $s2= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s3= "urn:schemas-upnp-org:device:InternetGatewayDevice:1" fullword wide
		 $s4= "urn:schemas-upnp-org:device:WANConnectionDevice:1" fullword wide
		 $s5= "urn:schemas-upnp-org:device:WANDevice:1" fullword wide
		 $s6= "urn:schemas-upnp-org:service:WANIPConnection:1" fullword wide
		 $s7= "urn:schemas-upnp-org:service:WANPPPConnection:1" fullword wide
		 $s8= "%windir%system32cmd.exe" fullword wide

		 $hex1= {2473313d2022536f66}
		 $hex2= {2473323d2022536f66}
		 $hex3= {2473333d202275726e}
		 $hex4= {2473343d202275726e}
		 $hex5= {2473353d202275726e}
		 $hex6= {2473363d202275726e}
		 $hex7= {2473373d202275726e}
		 $hex8= {2473383d2022257769}

	condition:
		5 of them
}
