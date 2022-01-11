
/*
   YARA Rule Set
   Author: resteex
   Identifier: Ransomware_Jigsaw 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_Ransomware_Jigsaw {
	meta: 
		 description= "Ransomware_Jigsaw Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-10_19-27-28" 
		 license = "https://github.com/resteex0/resteex_yara_rules"
		 hash1= "2773e3dc59472296cb0024ba7715a64e"

	strings:

	
 		 $s1= "12Xspzstah37626slkwKhsKSHA" fullword wide
		 $s2= "1 file will be deleted." fullword wide
		 $s3= "address/balance/" fullword wide
		 $s4= "After 72 hours all that are left will be deleted." fullword wide
		 $s5= "All you have to do..." fullword wide
		 $s6= "Are you connected to the internet? Try again!" fullword wide
		 $s7= "Assembly Version" fullword wide
		 $s8= "As soon as the payment is received the crypted files will be returned to normal." fullword wide
		 $s9= "BitcoinBlackmailer.exe" fullword wide
		 $s10= "But, don't worry! I have not deleted them, yet." fullword wide
		 $s11= "buttonCheckPayment" fullword wide
		 $s12= "buttonViewEncryptedFiles" fullword wide
		 $s13= "Congratulations. Your software has been registered. Confirmation code 994759" fullword wide
		 $s14= "Copyright 1999-2012 Firefox and Mozzilla developers. All rights reserved." fullword wide
		 $s15= "costura.newtonsoft.json.dll.zip" fullword wide
		 $s16= "dataGridViewEncryptedFiles" fullword wide
		 $s17= "Decrypting your files. It will take for a while. After done I will close and completely remove mysel" fullword wide
		 $s18= "DeleteItself.bat" fullword wide
		 $s19= "Drpbxdrpbx.exe" fullword wide
		 $s20= "Email us this code in the chat to active your software. It can take up to 48 hours." fullword wide
		 $s21= "EncryptedFileList.txt" fullword wide
		 $s22= "Every hour files will be deleted. Increasing in amount every time." fullword wide
		 $s23= "ExtensionsToEncrypt" fullword wide
		 $s24= "f from your computer." fullword wide
		 $s25= "{{ file = {0}, ext = {1} }}" fullword wide
		 $s26= "{{ file = {0}, fi = {1} }}" fullword wide
		 $s27= "FileDescription" fullword wide
		 $s28= "files will be deleted" fullword wide
		 $s29= "FileSystemSimulation" fullword wide
		 $s30= "FormEncryptedFiles" fullword wide
		 $s31= "Frfxfirefox.exe" fullword wide
		 $s32= "Great job, I'm decrypting your files..." fullword wide
		 $s33= "http://btc.blockr.io/api/v1/" fullword wide
		 $s34= "I am a txt test." fullword wide
		 $s35= "I am NOT a txt test." fullword wide
		 $s36= "If you do not have bitcoins Google the website localbitcoins." fullword wide
		 $s37= "I made a payment, now give me back my files!" fullword wide
		 $s38= "I want to play a game" fullword wide
		 $s39= "labelFilesToDelete" fullword wide
		 $s40= "LegalTrademarks" fullword wide
		 $s41= "Lucida Sans Unicode" fullword wide
		 $s42= "Main.Properties.Resources" fullword wide
		 $s43= "newtonsoft.json" fullword wide
		 $s44= "NotTxtTest.nottxt" fullword wide
		 $s45= "OoIsAwwF23cICQoLDA0ODe==" fullword wide
		 $s46= "OriginalFilename" fullword wide
		 $s47= "Purchase 150 American Dollars worth of Bitcoins or .4 BTC. The system will accept either one." fullword wide
		 $s48= "Send to the Bitcoins address specified." fullword wide
		 $s49= "SOFTWAREMicrosoftWindowsCurrentVersionRun" fullword wide
		 $s50= "Try anything funny and the computer has several safety measures to delete your files." fullword wide
		 $s51= "vanityAddresses" fullword wide
		 $s52= "View encrypted files" fullword wide
		 $s53= "VS_VERSION_INFO" fullword wide
		 $s54= "Within two minutes of receiving your payment your computer will receive the decryption key and retur" fullword wide
		 $s55= "worth of Bitcoin here:" fullword wide
		 $s56= "You are about to make a very bad decision. Are you sure about it?" fullword wide
		 $s57= "You did not sent me enough! Try again!" fullword wide
		 $s58= "You have 24 hours to pay 150 USD in Bitcoins to get the decryption key." fullword wide
		 $s59= "You haven't made payment yet! Try again!" fullword wide
		 $s60= "Your computer files have been encrypted. Your photos, videos, documents, etc...." fullword wide
		 $a1= "3System.Resources.Tools.StronglyTypedResourceBuilder" fullword ascii
		 $a2= ">9__CachedAnonymousMethodDelegate1" fullword ascii
		 $a3= "AssemblyConfigurationAttribute" fullword ascii
		 $a4= "AssemblyCopyrightAttribute" fullword ascii
		 $a5= "AssemblyDescriptionAttribute" fullword ascii
		 $a6= "AssemblyFileVersionAttribute" fullword ascii
		 $a7= "AssemblyTrademarkAttribute" fullword ascii
		 $a8= "buttonViewEncryptedFiles_Click" fullword ascii
		 $a9= "CompilationRelaxationsAttribute" fullword ascii
		 $a10= "CompilerGeneratedAttribute" fullword ascii
		 $a11= "costura.newtonsoft.json.dll.zip" fullword ascii
		 $a12= "CreateFileSystemSimulation" fullword ascii
		 $a13= "DataGridViewColumnCollection" fullword ascii
		 $a14= "DataGridViewColumnHeadersHeightSizeMode" fullword ascii
		 $a15= "dataGridViewEncryptedFiles" fullword ascii
		 $a16= "DataGridViewRowCollection" fullword ascii
		 $a17= "DataGridViewTextBoxColumn" fullword ascii
		 $a18= "DebuggerBrowsableAttribute" fullword ascii
		 $a19= "DebuggerNonUserCodeAttribute" fullword ascii
		 $a20= "FBD2112E56A53790B3D53B084795822F604F11FC" fullword ascii
		 $a21= "GetFileNameWithoutExtension" fullword ascii
		 $a22= "GetManifestResourceStream" fullword ascii
		 $a23= ">h__TransparentIdentifier0" fullword ascii
		 $a24= "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" fullword ascii
		 $a25= "Main.Properties.Resources.resources" fullword ascii
		 $a26= "MaxFilesizeToEncryptInBytes" fullword ascii
		 $a27= "PrivateImplementationDetails>" fullword ascii
		 $a28= "QbZlczhiHcyXUZulvpHjfBbHhhxY" fullword ascii
		 $a29= "ReadFromEmbeddedResources" fullword ascii
		 $a30= "RuntimeCompatibilityAttribute" fullword ascii
		 $a31= "set_ColumnHeadersHeightSizeMode" fullword ascii
		 $a32= "set_UseVisualStyleBackColor" fullword ascii
		 $a33= "__StaticArrayInitTypeSize=16" fullword ascii
		 $a34= "System.Collections.Generic" fullword ascii
		 $a35= "System.Collections.IEnumerable.GetEnumerator" fullword ascii
		 $a36= "System.Collections.IEnumerator.Current" fullword ascii
		 $a37= "System.Collections.IEnumerator.get_Current" fullword ascii
		 $a38= "System.Collections.IEnumerator.Reset" fullword ascii
		 $a39= "System.IDisposable.Dispose" fullword ascii
		 $a40= "System.Runtime.CompilerServices" fullword ascii
		 $a41= "System.Runtime.InteropServices" fullword ascii
		 $a42= "System.Security.Cryptography" fullword ascii
		 $a43= "System.String>.get_Current" fullword ascii
		 $a44= "System.String>.GetEnumerator" fullword ascii
		 $a45= "TimerActivateCheckerInterval" fullword ascii
		 $a46= "timerActivateChecker_Tick" fullword ascii

		 $hex1= {246131303d2022436f}
		 $hex2= {246131313d2022636f}
		 $hex3= {246131323d20224372}
		 $hex4= {246131333d20224461}
		 $hex5= {246131343d20224461}
		 $hex6= {246131353d20226461}
		 $hex7= {246131363d20224461}
		 $hex8= {246131373d20224461}
		 $hex9= {246131383d20224465}
		 $hex10= {246131393d20224465}
		 $hex11= {2461313d2022335379}
		 $hex12= {246132303d20224642}
		 $hex13= {246132313d20224765}
		 $hex14= {246132323d20224765}
		 $hex15= {246132333d20223e68}
		 $hex16= {246132343d20224b4d}
		 $hex17= {246132353d20224d61}
		 $hex18= {246132363d20224d61}
		 $hex19= {246132373d20225072}
		 $hex20= {246132383d20225162}
		 $hex21= {246132393d20225265}
		 $hex22= {2461323d20223e395f}
		 $hex23= {246133303d20225275}
		 $hex24= {246133313d20227365}
		 $hex25= {246133323d20227365}
		 $hex26= {246133333d20225f5f}
		 $hex27= {246133343d20225379}
		 $hex28= {246133353d20225379}
		 $hex29= {246133363d20225379}
		 $hex30= {246133373d20225379}
		 $hex31= {246133383d20225379}
		 $hex32= {246133393d20225379}
		 $hex33= {2461333d2022417373}
		 $hex34= {246134303d20225379}
		 $hex35= {246134313d20225379}
		 $hex36= {246134323d20225379}
		 $hex37= {246134333d20225379}
		 $hex38= {246134343d20225379}
		 $hex39= {246134353d20225469}
		 $hex40= {246134363d20227469}
		 $hex41= {2461343d2022417373}
		 $hex42= {2461353d2022417373}
		 $hex43= {2461363d2022417373}
		 $hex44= {2461373d2022417373}
		 $hex45= {2461383d2022627574}
		 $hex46= {2461393d2022436f6d}
		 $hex47= {247331303d20224275}
		 $hex48= {247331313d20226275}
		 $hex49= {247331323d20226275}
		 $hex50= {247331333d2022436f}
		 $hex51= {247331343d2022436f}
		 $hex52= {247331353d2022636f}
		 $hex53= {247331363d20226461}
		 $hex54= {247331373d20224465}
		 $hex55= {247331383d20224465}
		 $hex56= {247331393d20224472}
		 $hex57= {2473313d2022313258}
		 $hex58= {247332303d2022456d}
		 $hex59= {247332313d2022456e}
		 $hex60= {247332323d20224576}
		 $hex61= {247332333d20224578}
		 $hex62= {247332343d20226620}
		 $hex63= {247332353d20227b7b}
		 $hex64= {247332363d20227b7b}
		 $hex65= {247332373d20224669}
		 $hex66= {247332383d20226669}
		 $hex67= {247332393d20224669}
		 $hex68= {2473323d2022312066}
		 $hex69= {247333303d2022466f}
		 $hex70= {247333313d20224672}
		 $hex71= {247333323d20224772}
		 $hex72= {247333333d20226874}
		 $hex73= {247333343d20224920}
		 $hex74= {247333353d20224920}
		 $hex75= {247333363d20224966}
		 $hex76= {247333373d20224920}
		 $hex77= {247333383d20224920}
		 $hex78= {247333393d20226c61}
		 $hex79= {2473333d2022616464}
		 $hex80= {247334303d20224c65}
		 $hex81= {247334313d20224c75}
		 $hex82= {247334323d20224d61}
		 $hex83= {247334333d20226e65}
		 $hex84= {247334343d20224e6f}
		 $hex85= {247334353d20224f6f}
		 $hex86= {247334363d20224f72}
		 $hex87= {247334373d20225075}
		 $hex88= {247334383d20225365}
		 $hex89= {247334393d2022534f}
		 $hex90= {2473343d2022416674}
		 $hex91= {247335303d20225472}
		 $hex92= {247335313d20227661}
		 $hex93= {247335323d20225669}
		 $hex94= {247335333d20225653}
		 $hex95= {247335343d20225769}
		 $hex96= {247335353d2022776f}
		 $hex97= {247335363d2022596f}
		 $hex98= {247335373d2022596f}
		 $hex99= {247335383d2022596f}
		 $hex100= {247335393d2022596f}
		 $hex101= {2473353d2022416c6c}
		 $hex102= {247336303d2022596f}
		 $hex103= {2473363d2022417265}
		 $hex104= {2473373d2022417373}
		 $hex105= {2473383d2022417320}
		 $hex106= {2473393d2022426974}

	condition:
		13 of them
}
