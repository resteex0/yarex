
/*
   YARA Rule Set
   Author: resteex
   Identifier: CryptoLocker_10Sep2013 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_CryptoLocker_10Sep2013 {
	meta: 
		 description= "CryptoLocker_10Sep2013 Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-25-42" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "04fb36199787f2e3e2135611a38321eb"

	strings:

	
 		 $s1= "184.164.136.134" fullword wide
		 $s2= "Are you sure you entered your payment information correctly?" fullword wide
		 $s3= "Bitcoin (most cheap option)" fullword wide
		 $s4= "button - this will delete the software from this computer." fullword wide
		 $s5= "Choose a convenient payment method:" fullword wide
		 $s6= "Connection: Close" fullword wide
		 $s7= "Copy Bitcoin address" fullword wide
		 $s8= "Do not disconnect from the Internet or turn off the computer!" fullword wide
		 $s9= "Enter the card number and press " fullword wide
		 $s10= "Enter the code of the card, select card currency, and press " fullword wide
		 $s11= "Enter the coupon code and click " fullword wide
		 $s12= "Enter the transaction ID and press " fullword wide
		 $s13= "Files decryption" fullword wide
		 $s14= "Files will be decrypted automatically after payment activation." fullword wide
		 $s15= "ime to destroy the private key in half!" fullword wide
		 $s16= "Make sure that all important files have been decrypted! If part of the files had not been decrypted " fullword wide
		 $s17= "Make sure that you enter the payment information correctly! Each incorrect attempt will reduce the t" fullword wide
		 $s18= "Microsoft Enhanced Cryptographic Provider v1.0" fullword wide
		 $s19= "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide
		 $s20= "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)" fullword wide
		 $s21= "MoneyPak (USA only)" fullword wide
		 $s22= "- move them to the desktop and click " fullword wide
		 $s23= "msctls_progress32" fullword wide
		 $s24= "Open in Bitcoin client" fullword wide
		 $s25= "Otherwise, press " fullword wide
		 $s26= "Payment for private key" fullword wide
		 $s27= "Payment method: %s" fullword wide
		 $s28= "Payments are processed manually, therefore, the expectation of activation may take up to 48 hours." fullword wide
		 $s29= "Please try again later, or restart your computer." fullword wide
		 $s30= "Private key will be destroyed on" fullword wide
		 $s31= "Search and decryption of the found files completed." fullword wide
		 $s32= "Search and recovery of encrypted files!" fullword wide
		 $s33= "SoftwareCryptoLocker" fullword wide
		 $s34= "SoftwareCryptoLockerFiles" fullword wide
		 $s35= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s36= "The list of encrypted files" fullword wide
		 $s37= "The private key destruction is suspended for the time of payment processing." fullword wide
		 $s38= "This software will be deleted after files decryption, make sure that all important files are decrypt" fullword wide
		 $s39= "Time until the private key destruction is reduced." fullword wide
		 $s40= "%u : %02u : %02u" fullword wide
		 $s41= "Unknown error occurred." fullword wide
		 $s42= "Waiting for payment activation" fullword wide
		 $s43= "You entered the wrong payment information." fullword wide
		 $s44= "Your payment information is activated!" fullword wide
		 $s45= "Your personal files are encrypted!" fullword wide
		 $a1= "0@0D0H0L0P0T0X00`0d0h0l0p0t0x0|0" fullword ascii
		 $a2= "6-656;6A6J6P6V66`6e6k6t6z6" fullword ascii
		 $a3= "ExpandEnvironmentStringsW" fullword ascii
		 $a4= "GdipCreateBitmapFromStream" fullword ascii
		 $a5= "GdipCreateFontFromLogfontA" fullword ascii
		 $a6= "GdipCreateHBITMAPFromBitmap" fullword ascii
		 $a7= "GdipSetStringFormatHotkeyPrefix" fullword ascii
		 $a8= "GdipSetStringFormatLineAlign" fullword ascii
		 $a9= "GetFileInformationByHandleEx" fullword ascii
		 $a10= "GetUserPreferredUILanguages" fullword ascii
		 $a11= ":%:H:N:7;?;E;K;T;Z;`;f;j;o;u;~;" fullword ascii
		 $a12= "InitializeCriticalSection" fullword ascii
		 $a13= "MsgWaitForMultipleObjects" fullword ascii
		 $a14= "PLTE;;;GB9RJ7^Q5jX2v`0GGGTTT```lllxxx" fullword ascii
		 $a15= "SetFileInformationByHandle" fullword ascii

		 $hex1= {246131303d20224765}
		 $hex2= {246131313d20223a25}
		 $hex3= {246131323d2022496e}
		 $hex4= {246131333d20224d73}
		 $hex5= {246131343d2022504c}
		 $hex6= {246131353d20225365}
		 $hex7= {2461313d2022304030}
		 $hex8= {2461323d2022362d36}
		 $hex9= {2461333d2022457870}
		 $hex10= {2461343d2022476469}
		 $hex11= {2461353d2022476469}
		 $hex12= {2461363d2022476469}
		 $hex13= {2461373d2022476469}
		 $hex14= {2461383d2022476469}
		 $hex15= {2461393d2022476574}
		 $hex16= {247331303d2022456e}
		 $hex17= {247331313d2022456e}
		 $hex18= {247331323d2022456e}
		 $hex19= {247331333d20224669}
		 $hex20= {247331343d20224669}
		 $hex21= {247331353d2022696d}
		 $hex22= {247331363d20224d61}
		 $hex23= {247331373d20224d61}
		 $hex24= {247331383d20224d69}
		 $hex25= {247331393d20224d69}
		 $hex26= {2473313d2022313834}
		 $hex27= {247332303d20224d69}
		 $hex28= {247332313d20224d6f}
		 $hex29= {247332323d20222d20}
		 $hex30= {247332333d20226d73}
		 $hex31= {247332343d20224f70}
		 $hex32= {247332353d20224f74}
		 $hex33= {247332363d20225061}
		 $hex34= {247332373d20225061}
		 $hex35= {247332383d20225061}
		 $hex36= {247332393d2022506c}
		 $hex37= {2473323d2022417265}
		 $hex38= {247333303d20225072}
		 $hex39= {247333313d20225365}
		 $hex40= {247333323d20225365}
		 $hex41= {247333333d2022536f}
		 $hex42= {247333343d2022536f}
		 $hex43= {247333353d2022536f}
		 $hex44= {247333363d20225468}
		 $hex45= {247333373d20225468}
		 $hex46= {247333383d20225468}
		 $hex47= {247333393d20225469}
		 $hex48= {2473333d2022426974}
		 $hex49= {247334303d20222575}
		 $hex50= {247334313d2022556e}
		 $hex51= {247334323d20225761}
		 $hex52= {247334333d2022596f}
		 $hex53= {247334343d2022596f}
		 $hex54= {247334353d2022596f}
		 $hex55= {2473343d2022627574}
		 $hex56= {2473353d202243686f}
		 $hex57= {2473363d2022436f6e}
		 $hex58= {2473373d2022436f70}
		 $hex59= {2473383d2022446f20}
		 $hex60= {2473393d2022456e74}

	condition:
		7 of them
}
