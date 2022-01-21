
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_PIVY 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_PIVY {
	meta: 
		 description= "vx_underground2_PIVY Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-13-33" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0cb6fd43d5d29ce891454a510ff38bd5"
		 hash2= "11eccf2c247dd4f9df730354b3e0947d"
		 hash3= "15a4fc049fdfdaeb1ea5b9da3cb458af"
		 hash4= "22672eeb15ab0d07a3dfe4d03c5f0990"
		 hash5= "239302a4d4e4e35a2b610ef61ab3ca68"
		 hash6= "241e30dd81588222c7f1ff92a53cc312"
		 hash7= "272901f9a01a79f2dec27b73936ceee0"
		 hash8= "277f3ada5fc43284b84b3b0e0e10a413"
		 hash9= "4a3358f092f47ce5bc8e33184e82dd06"
		 hash10= "59fe6d0922b82f540844d61df783027f"
		 hash11= "96bff6ef607bbe07c49357d0c58714a5"
		 hash12= "9dd6fb40a7ace992bedc283dee79f50b"
		 hash13= "b54f014cf491589998787e6b96a67e06"
		 hash14= "be06e2f28143abdbaf61819e1746dfbe"
		 hash15= "d2a4c1f91b2535cfe20c486fcdad907b"
		 hash16= "dac3c712616d0033d94c205e784253a7"
		 hash17= "e29f8b035288e659168cdb986858b9fa"
		 hash18= "eb0fc1be33fe9dfce42544e0a07ef04e"

	strings:

	
 		 $s1= "#bIESKCHRuSKKGT_oH@ITKGROIH" fullword wide
		 $s2= "+gBKOHOURTGRIT+gBKOHOURTGRIT" fullword wide
		 $s3= "g]DGGCmPXZM[[aFxZGKKM[[{MZ^MZ" fullword wide
		 $s4= "-lGK]EMF{]EEIZQaFNGZEIAGF" fullword wide
		 $s5= "mjldd.l~kdid#xikciomafng!{`mddkglm" fullword wide
		 $s6= "WMDM/DeviceFirmwareVersion" fullword wide
		 $s7= "WMDM/DeviceRevocationInfo" fullword wide
		 $s8= "WMDM/DeviceServiceProviderVendor" fullword wide
		 $s9= "WMDM/DeviceVendorExtension" fullword wide
		 $s10= "WMDM/FormatsSupportedAreOrdered" fullword wide
		 $s11= "WMDM/MediaClassSecondaryID" fullword wide
		 $s12= "WMDM/MediaOriginalBroadcastDateTime" fullword wide
		 $s13= "WMDM/MediaOriginalChannel" fullword wide
		 $s14= "WMDM/SupportedDeviceProperties" fullword wide
		 $s15= "WPD/PassthroughPropertyValues" fullword wide
		 $a1= "C:buildsourcerndevicedbbuilderrel32rndevicedbbuilder.pdb" fullword ascii

		 $hex1= {2461313d2022433a62}
		 $hex2= {247331303d2022574d}
		 $hex3= {247331313d2022574d}
		 $hex4= {247331323d2022574d}
		 $hex5= {247331333d2022574d}
		 $hex6= {247331343d2022574d}
		 $hex7= {247331353d20225750}
		 $hex8= {2473313d2022236249}
		 $hex9= {2473323d20222b6742}
		 $hex10= {2473333d2022675d44}
		 $hex11= {2473343d20222d6c47}
		 $hex12= {2473353d20226d6a6c}
		 $hex13= {2473363d2022574d44}
		 $hex14= {2473373d2022574d44}
		 $hex15= {2473383d2022574d44}
		 $hex16= {2473393d2022574d44}

	condition:
		10 of them
}
