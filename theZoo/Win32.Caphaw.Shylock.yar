
/*
   YARA Rule Set
   Author: resteex
   Identifier: Win32_Caphaw_Shylock 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Win32_Caphaw_Shylock {
	meta: 
		 description= "Win32_Caphaw_Shylock Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-14_21-38-43" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "c98fe7df44cded5981af4ec565c29a2e"
		 hash2= "ca0403ea24fe2a7771b99cea55826c9b"
		 hash3= "e63fead91fe788dac57601d2c77713f9"

	strings:

	
 		 $s1= "??C:WindowsSystem32" fullword wide
		 $s2= "DosDevices%C:" fullword wide
		 $s3= "Drivernsiproxy" fullword wide
		 $s4= "Driverservise.sys" fullword wide
		 $s5= "??PhysicalDrive0" fullword wide
		 $s6= "??PhysicalDrive%d" fullword wide
		 $s7= "PsCreateSystemThread" fullword wide

		 $hex1= {2473313d20223f3f43}
		 $hex2= {2473323d2022446f73}
		 $hex3= {2473333d2022447269}
		 $hex4= {2473343d2022447269}
		 $hex5= {2473353d20223f3f50}
		 $hex6= {2473363d20223f3f50}
		 $hex7= {2473373d2022507343}

	condition:
		2 of them
}
