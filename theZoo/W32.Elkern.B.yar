
/*
   YARA Rule Set
   Author: resteex
   Identifier: W32_Elkern_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_W32_Elkern_B {
	meta: 
		 description= "W32_Elkern_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-31-06" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0a8a4950d9d71b448fde1f741608921e"
		 hash2= "15eb3a656f9e83138cdb4c3a16b6ab60"

	strings:

	
 		 $s1= "1Close the Paper holder and click the [OK] button." fullword wide
		 $s2= "5Please put the CALIBRATION SHEET on the glass plate." fullword wide
		 $s3= "9600 DPI / Single Pass" fullword wide
		 $s4= "9Please execute the calibration again. Click [OK] button." fullword wide
		 $s5= "Abort Scanning Error" fullword wide
		 $s6= "Abort Scan Successfully !!!" fullword wide
		 $s7= "Bad capabilities error." fullword wide
		 $s8= "Bad protocol error." fullword wide
		 $s9= "Bad value error.'DG DAT MSG is out of expected sequence." fullword wide
		 $s10= "Brightness/Contrast" fullword wide
		 $s11= "Calibration has failed." fullword wide
		 $s12= "Calibration has success." fullword wide
		 $s13= "Disk access (or write) error." fullword wide
		 $s14= "%d%% Scanning " fullword wide
		 $s15= ":Host application does not support" fullword wide
		 $s16= "Insufficient Memory.'Setting Area and Resolution is Too Big." fullword wide
		 $s17= "libration will be started." fullword wide
		 $s18= "MPlease put the document to scan on the glass plate and click the [OK] button." fullword wide
		 $s19= "No Scanning Data" fullword wide
		 $s20= "Not enough memory in DOS block.'Disk space is not enough for the image." fullword wide
		 $s21= "Now, it is ready to scan." fullword wide
		 $s22= "Open Device Drivers Failed" fullword wide
		 $s23= "Photograph Newspaper" fullword wide
		 $s24= "Please Wait a Moment" fullword wide
		 $s25= "Press ESC to Abort# : disk spaces not enough to scan !" fullword wide
		 $s26= "Read Scanned Data Error" fullword wide
		 $s27= "Resolution Automatic" fullword wide
		 $s28= "Scaling X-Scaling Y-Scaling" fullword wide
		 $s29= "Scan Area Too Small" fullword wide
		 $s30= "Scanner AstraSlim" fullword wide
		 $s31= "Scanner Error( )" fullword wide
		 $s32= "Scanner Not Ready (-000)" fullword wide
		 $s33= "Scan Test Failed !!!" fullword wide
		 $s34= "Scan Test Successfully !!!" fullword wide
		 $s35= "Set Scan Setting Error" fullword wide
		 $s36= "Shutdown AutoFrame" fullword wide
		 $s37= ")Source is connected to max possible apps.!An operation error just occurred." fullword wide
		 $s38= "this kind of Pixel Type." fullword wide
		 $s39= "Transferring Image..." fullword wide
		 $s40= "True Color 256 Color Greyscale" fullword wide
		 $s41= "TWAIN_32ABOR650C.EXE" fullword wide
		 $s42= "TWAIN_32HUI2650C.DLL" fullword wide
		 $s43= "TWAIN_32RES2650C.DLL" fullword wide
		 $s44= "Unknow error.DLow Memory Condition encountered, free up some memory and try again." fullword wide
		 $s45= "&Unknown Error value in condition code." fullword wide
		 $s46= "Version 2.01 Aug. 31, 2001" fullword wide
		 $s47= "Wto execute the calibration. If you want to quit the calibration, click [CANCEL] button.&Now, the ca" fullword wide
		 $s48= "Zoom Area Too Small" fullword wide
		 $a1= "GAIsProcessorFeaturePresent" fullword ascii
		 $a2= "InitializeCriticalSection" fullword ascii
		 $a3= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a4= "PhotometricInterpretation" fullword ascii
		 $a5= "SetupDiDestroyDeviceInfoList" fullword ascii
		 $a6= "SetupDiEnumDeviceInterfaces" fullword ascii
		 $a7= "SetupDiGetDeviceInterfaceDetailA" fullword ascii

		 $hex1= {2461313d2022474149}
		 $hex2= {2461323d2022496e69}
		 $hex3= {2461333d20224a616e}
		 $hex4= {2461343d202250686f}
		 $hex5= {2461353d2022536574}
		 $hex6= {2461363d2022536574}
		 $hex7= {2461373d2022536574}
		 $hex8= {247331303d20224272}
		 $hex9= {247331313d20224361}
		 $hex10= {247331323d20224361}
		 $hex11= {247331333d20224469}
		 $hex12= {247331343d20222564}
		 $hex13= {247331353d20223a48}
		 $hex14= {247331363d2022496e}
		 $hex15= {247331373d20226c69}
		 $hex16= {247331383d20224d50}
		 $hex17= {247331393d20224e6f}
		 $hex18= {2473313d202231436c}
		 $hex19= {247332303d20224e6f}
		 $hex20= {247332313d20224e6f}
		 $hex21= {247332323d20224f70}
		 $hex22= {247332333d20225068}
		 $hex23= {247332343d2022506c}
		 $hex24= {247332353d20225072}
		 $hex25= {247332363d20225265}
		 $hex26= {247332373d20225265}
		 $hex27= {247332383d20225363}
		 $hex28= {247332393d20225363}
		 $hex29= {2473323d202235506c}
		 $hex30= {247333303d20225363}
		 $hex31= {247333313d20225363}
		 $hex32= {247333323d20225363}
		 $hex33= {247333333d20225363}
		 $hex34= {247333343d20225363}
		 $hex35= {247333353d20225365}
		 $hex36= {247333363d20225368}
		 $hex37= {247333373d20222953}
		 $hex38= {247333383d20227468}
		 $hex39= {247333393d20225472}
		 $hex40= {2473333d2022393630}
		 $hex41= {247334303d20225472}
		 $hex42= {247334313d20225457}
		 $hex43= {247334323d20225457}
		 $hex44= {247334333d20225457}
		 $hex45= {247334343d2022556e}
		 $hex46= {247334353d20222655}
		 $hex47= {247334363d20225665}
		 $hex48= {247334373d20225774}
		 $hex49= {247334383d20225a6f}
		 $hex50= {2473343d202239506c}
		 $hex51= {2473353d202241626f}
		 $hex52= {2473363d202241626f}
		 $hex53= {2473373d2022426164}
		 $hex54= {2473383d2022426164}
		 $hex55= {2473393d2022426164}

	condition:
		6 of them
}
