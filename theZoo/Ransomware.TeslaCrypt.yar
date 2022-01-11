
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_TeslaCrypt 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_TeslaCrypt {
	meta: 
		 description= "Ransomware_TeslaCrypt Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-29-17" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "209a288c68207d57e0ce6e60ebf60729"
		 hash2= "6d3d62a4cff19b4f2cc7ce9027c33be8"
		 hash3= "6e080aa085293bb9fbdcc9015337d309"

	strings:

	
 		 $s1= "34r6hq26q2h4jkzj.onion " fullword wide
		 $s2= "after a time period specified in this window." fullword wide
		 $s3= "After instalation,run the browser and enter address " fullword wide
		 $s4= "All files Decrypted" fullword wide
		 $s5= "and follow the instruction." fullword wide
		 $s6= "and you can personally verify this." fullword wide
		 $s7= "Any attempt to remove or corrupt this software will result " fullword wide
		 $s8= "Click to copy Bitcoin address to clipboard" fullword wide
		 $s9= "Click to Free Decryption on site" fullword wide
		 $s10= "CLSID_AsyncReader" fullword wide
		 $s11= "CLSID_AsyncReader2" fullword wide
		 $s12= "Control PanelDesktop" fullword wide
		 $s13= "Copyright (C) 2015" fullword wide
		 $s14= "CryptoLocker.lnk" fullword wide
		 $s15= "CryptoLocker-v3" fullword wide
		 $s16= "Decrypt all files" fullword wide
		 $s17= "Decryption key:" fullword wide
		 $s18= "Decryption key and Verification key is wrong" fullword wide
		 $s19= "!!!Decrypt your files!!!" fullword wide
		 $s20= ")disclaimer_accepted = 1" fullword wide
		 $s21= "Encryption was produced using a unique public key RSA-2048 generated " fullword wide
		 $s22= "Enter Decryption key here" fullword wide
		 $s23= "Enter Decrypt key" fullword wide
		 $s24= "Enter Decrypt Key" fullword wide
		 $s25= "Enter Verification key here" fullword wide
		 $s26= "FileDescription" fullword wide
		 $s27= "Follow the instruction on the web-site. We remind you that the" fullword wide
		 $s28= "for this computer. To decrypt files you need to obtain the " fullword wide
		 $s29= "HELP_TO_DECRYPT_YOUR_FILES.bmp" fullword wide
		 $s30= "HELP_TO_DECRYPT_YOUR_FILES.txt" fullword wide
		 $s31= "https://34r6hq26q2h4jkzj.tor2web.fi" fullword wide
		 $s32= "https://34r6hq26q2h4jkzj.tor2web.org" fullword wide
		 $s33= "https://7tno4hib47vlep5o.tor2web.blutmagie.de" fullword wide
		 $s34= "https://7tno4hib47vlep5o.tor2web.fi" fullword wide
		 $s35= "https://7tno4hib47vlep5o.tor2web.org" fullword wide
		 $s36= "https://www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $s37= "if https://34r6hq26q2h4jkzj.tor2web.org is not opening, please follow the steps: " fullword wide
		 $s38= "in immediate elimination of the private key by the server." fullword wide
		 $s39= "In order to decrypt the files open your personal page on site " fullword wide
		 $s40= "Intel Hardware Cryptographic Service Provider" fullword wide
		 $s41= "is located on a secret server in the Internet; the server will eliminate the key " fullword wide
		 $s42= "LanmanWorkstation" fullword wide
		 $s43= "Once this has been done, nobody will ever be able to restore files..." fullword wide
		 $s44= "OriginalFilename" fullword wide
		 $s45= "Show encrypted files" fullword wide
		 $s46= "SoftwareMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s47= "%ssystem32cmd.exe" fullword wide
		 $s48= "the more chances are left to recover the files. " fullword wide
		 $s49= "The only copy of the private key, which will allow you to decrypt your files, " fullword wide
		 $s50= "Use your Bitcoin address to" fullword wide
		 $s51= "Verification key:" fullword wide
		 $s52= "VS_VERSION_INFO" fullword wide
		 $s53= "w+ ,ccs=UTF-16LE" fullword wide
		 $s54= "www.torproject.org/projects/torbrowser.html.en" fullword wide
		 $s55= "You must install this browser" fullword wide
		 $s56= "Your files have been safely encrypted on this PC: photos,videos, documents,etc. " fullword wide
		 $s57= "Your payment is not received !!!" fullword wide
		 $s58= "Your payment received, Now decrypt all files " fullword wide
		 $s59= "Your personal files are encrypted!" fullword wide
		 $s60= "Your private key will be " fullword wide
		 $a1= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" fullword ascii
		 $a2= "7tno4hib47vlep5o.tor2web.blutmagie.de" fullword ascii
		 $a3= "7tno4hib47vlep5o.tor2web.fi" fullword ascii
		 $a4= "7tno4hib47vlep5o.tor2web.org" fullword ascii
		 $a5= "abcdefghijklmnopqrstuvwxyz" fullword ascii
		 $a6= "ABCDEFGHIJKLMNOPQRSTUVWXYZ" fullword ascii
		 $a7= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii
		 $a8= "GAIsProcessorFeaturePresent" fullword ascii
		 $a9= "GetUserObjectInformationA" fullword ascii
		 $a10= "https://blockchain.info/address/%s" fullword ascii
		 $a11= "InitializeCriticalSection" fullword ascii
		 $a12= "InitializeCriticalSectionAndSpinCount" fullword ascii
		 $a13= "JanFebMarAprMayJunJulAugSepOctNovDec" fullword ascii
		 $a14= "LookupIconIdFromDirectoryEx" fullword ascii
		 $a15= "SetUnhandledExceptionFilter" fullword ascii
		 $a16= "Subject=Crypted&key=%s&addr=%s&files=%lld&size=%lld&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=" fullword ascii
		 $a17= "Subject=Payment&recovery_key=%s&addr=%s&files=%d&size=%d&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d" fullword ascii
		 $a18= "Subject=Ping&key=%s&addr=%s&files=%d&size=%d&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d" fullword ascii

		 $hex1= {246131303d20226874}
		 $hex2= {246131313d2022496e}
		 $hex3= {246131323d2022496e}
		 $hex4= {246131333d20224a61}
		 $hex5= {246131343d20224c6f}
		 $hex6= {246131353d20225365}
		 $hex7= {246131363d20225375}
		 $hex8= {246131373d20225375}
		 $hex9= {246131383d20225375}
		 $hex10= {2461313d2022313233}
		 $hex11= {2461323d202237746e}
		 $hex12= {2461333d202237746e}
		 $hex13= {2461343d202237746e}
		 $hex14= {2461353d2022616263}
		 $hex15= {2461363d2022414243}
		 $hex16= {2461373d2022414243}
		 $hex17= {2461383d2022474149}
		 $hex18= {2461393d2022476574}
		 $hex19= {247331303d2022434c}
		 $hex20= {247331313d2022434c}
		 $hex21= {247331323d2022436f}
		 $hex22= {247331333d2022436f}
		 $hex23= {247331343d20224372}
		 $hex24= {247331353d20224372}
		 $hex25= {247331363d20224465}
		 $hex26= {247331373d20224465}
		 $hex27= {247331383d20224465}
		 $hex28= {247331393d20222121}
		 $hex29= {2473313d2022333472}
		 $hex30= {247332303d20222964}
		 $hex31= {247332313d2022456e}
		 $hex32= {247332323d2022456e}
		 $hex33= {247332333d2022456e}
		 $hex34= {247332343d2022456e}
		 $hex35= {247332353d2022456e}
		 $hex36= {247332363d20224669}
		 $hex37= {247332373d2022466f}
		 $hex38= {247332383d2022666f}
		 $hex39= {247332393d20224845}
		 $hex40= {2473323d2022616674}
		 $hex41= {247333303d20224845}
		 $hex42= {247333313d20226874}
		 $hex43= {247333323d20226874}
		 $hex44= {247333333d20226874}
		 $hex45= {247333343d20226874}
		 $hex46= {247333353d20226874}
		 $hex47= {247333363d20226874}
		 $hex48= {247333373d20226966}
		 $hex49= {247333383d2022696e}
		 $hex50= {247333393d2022496e}
		 $hex51= {2473333d2022416674}
		 $hex52= {247334303d2022496e}
		 $hex53= {247334313d20226973}
		 $hex54= {247334323d20224c61}
		 $hex55= {247334333d20224f6e}
		 $hex56= {247334343d20224f72}
		 $hex57= {247334353d20225368}
		 $hex58= {247334363d2022536f}
		 $hex59= {247334373d20222573}
		 $hex60= {247334383d20227468}
		 $hex61= {247334393d20225468}
		 $hex62= {2473343d2022416c6c}
		 $hex63= {247335303d20225573}
		 $hex64= {247335313d20225665}
		 $hex65= {247335323d20225653}
		 $hex66= {247335333d2022772b}
		 $hex67= {247335343d20227777}
		 $hex68= {247335353d2022596f}
		 $hex69= {247335363d2022596f}
		 $hex70= {247335373d2022596f}
		 $hex71= {247335383d2022596f}
		 $hex72= {247335393d2022596f}
		 $hex73= {2473353d2022616e64}
		 $hex74= {247336303d2022596f}
		 $hex75= {2473363d2022616e64}
		 $hex76= {2473373d2022416e79}
		 $hex77= {2473383d2022436c69}
		 $hex78= {2473393d2022436c69}

	condition:
		9 of them
}
