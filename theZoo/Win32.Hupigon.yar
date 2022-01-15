
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Hupigon 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Hupigon {
	meta: 
		 description= "Win32_Hupigon Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_20-54-45" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "8f90057ab244bd8b612cd09f566eac0c"

	strings:

	
 		 $s1= "Access violation" fullword wide
		 $s2= "Already connected." fullword wide
		 $s3= "Application Workspace" fullword wide
		 $s4= "Assertion failed" fullword wide
		 $s5= "August September" fullword wide
		 $s6= "availableDataLenIn" fullword wide
		 $s7= "availableDataLenOut" fullword wide
		 $s8= "Button Highlight" fullword wide
		 $s9= "Connection refused." fullword wide
		 $s10= "Default Gray Text" fullword wide
		 $s11= "dst_BitsPerSample" fullword wide
		 $s12= "dst_NumChannels" fullword wide
		 $s13= "dst_SamplesPerSec" fullword wide
		 $s14= "Enhanced Metafiles" fullword wide
		 $s15= "formatTagImmunable" fullword wide
		 $s16= "Highlight Background" fullword wide
		 $s17= "Host unreachable." fullword wide
		 $s18= "Inactive Border" fullword wide
		 $s19= "Inactive Caption" fullword wide
		 $s20= "Invalid argument" fullword wide
		 $s21= "Invalid argument." fullword wide
		 $s22= "Invalid filename" fullword wide
		 $s23= "Invalid ImageList" fullword wide
		 $s24= "isFormatProvider" fullword wide
		 $s25= "Network unreachable." fullword wide
		 $s26= "onDataAvailable" fullword wide
		 $s27= "OriginalFilename" fullword wide
		 $s28= "packetsReceived" fullword wide
		 $s29= "pcm_BitsPerSample" fullword wide
		 $s30= "pcm_NumChannels" fullword wide
		 $s31= "pcm_SamplesPerSec" fullword wide
		 $s32= "Privileged instruction" fullword wide
		 $s33= "Tuesday Wednesday" fullword wide
		 $s34= "Variant overflow" fullword wide
		 $s35= "VS_VERSION_INFO" fullword wide
		 $s36= "waveNumChannels" fullword wide
		 $s37= "waveSamplesPerSec" fullword wide
		 $s38= "Window Background" fullword wide

		 $hex1= {247331303d20224465}
		 $hex2= {247331313d20226473}
		 $hex3= {247331323d20226473}
		 $hex4= {247331333d20226473}
		 $hex5= {247331343d2022456e}
		 $hex6= {247331353d2022666f}
		 $hex7= {247331363d20224869}
		 $hex8= {247331373d2022486f}
		 $hex9= {247331383d2022496e}
		 $hex10= {247331393d2022496e}
		 $hex11= {2473313d2022416363}
		 $hex12= {247332303d2022496e}
		 $hex13= {247332313d2022496e}
		 $hex14= {247332323d2022496e}
		 $hex15= {247332333d2022496e}
		 $hex16= {247332343d20226973}
		 $hex17= {247332353d20224e65}
		 $hex18= {247332363d20226f6e}
		 $hex19= {247332373d20224f72}
		 $hex20= {247332383d20227061}
		 $hex21= {247332393d20227063}
		 $hex22= {2473323d2022416c72}
		 $hex23= {247333303d20227063}
		 $hex24= {247333313d20227063}
		 $hex25= {247333323d20225072}
		 $hex26= {247333333d20225475}
		 $hex27= {247333343d20225661}
		 $hex28= {247333353d20225653}
		 $hex29= {247333363d20227761}
		 $hex30= {247333373d20227761}
		 $hex31= {247333383d20225769}
		 $hex32= {2473333d2022417070}
		 $hex33= {2473343d2022417373}
		 $hex34= {2473353d2022417567}
		 $hex35= {2473363d2022617661}
		 $hex36= {2473373d2022617661}
		 $hex37= {2473383d2022427574}
		 $hex38= {2473393d2022436f6e}

	condition:
		4 of them
}
