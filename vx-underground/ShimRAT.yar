
/*
   YARA Rule Set
   Author: resteex
   Identifier: vx_underground2_ShimRAT 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_vx_underground2_ShimRAT {
	meta: 
		 description= "vx_underground2_ShimRAT Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_22-17-15" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "0067bbd63db0a4f5662cdb1633d92444"
		 hash2= "06cca5013175c5a1c8ff89a494e24245"
		 hash3= "2384febe404ef48d6585f050e3cd51a8"
		 hash4= "23a1a7f0f30f18ba4d0461829eb46766"
		 hash5= "25e87e846bb969802e8db9b36d6cf67c"
		 hash6= "26ff9e2da06b7e90443d6190388581ab"
		 hash7= "2f14d8c3d4815436f806fc1a435e29e3"
		 hash8= "36e057fa2020c65f2849d718f2bb90ad"
		 hash9= "3dab6ff3719ff7fcb01080fc36fe97dc"
		 hash10= "48368ea31d0c65f11427234639aebb1e"
		 hash11= "484c7f9e6c9233ba6ed4adb79b87ebce"
		 hash12= "4e22e8bc3034d0df1e902413c9cfefc9"
		 hash13= "4e493a649e2b87ef1a341809dab34a38"
		 hash14= "582e4adddfd12f7d68035c3b8e2e3378"
		 hash15= "5965731f2f237a12f7a4873e3e37658a"
		 hash16= "5c00ccf456135514c591478904b146e3"
		 hash17= "663e54e686842eb8f8bae2472cf01ba1"
		 hash18= "6b126cd9a5f2af30bb048caef92ceb51"
		 hash19= "888cac09f613db4505c4ee8d01d4291b"
		 hash20= "916a2a20a447b10e379543a47a60b40f"
		 hash21= "9a6167cf7c180f15d8ae13f48d549d2e"
		 hash22= "a326e2abacc72c7a050ffe36e3d3d0eb"
		 hash23= "a3f7895fae05fa121a4e23dd3595c366"
		 hash24= "b281a2e1457cd5ca8c85700817018902"
		 hash25= "b43e5988bde7bb03133eec60daaf22d5"
		 hash26= "b4554c52f708154e529f62ba8e0de084"
		 hash27= "c27fb6999a0243f041c5e387280f9442"
		 hash28= "ca41c19366bee737fe5bc5008250976a"
		 hash29= "cf883d04762b868b450275017ab3ccfa"
		 hash30= "d7a575895b07b007d0daf1f15bfb14a1"
		 hash31= "d8b95e942993b979fb82c22ea5b5ca18"
		 hash32= "e79b2d2934e5525e7a40d74875f9d761"
		 hash33= "f34c6239b7d70f23ce02a8d207176637"
		 hash34= "f4b247a44be362898c4e587545c7653f"
		 hash35= "fb80354303a0ff748696baae3d264af4"

	strings:

	
 		 $s1= "%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X" fullword wide
		 $s2= "C:WindowsSystem32sysprepcryptbase.dll" fullword wide
		 $s3= "C:windowssystem32sysprepsysprep.exe" fullword wide
		 $s4= "SoftwareMicrosoftWindowsCurrentVersionInternet Settings" fullword wide
		 $s5= "SOFTWAREMicrosoftWindows NTCurrentVersionHotfixQ246009" fullword wide
		 $s6= "SYSTEMCurrentControlSetControlProductOptions" fullword wide
		 $a1= "47618mqqu?**das`kqpw`i`dwklkb+h`*ru(fjkq`kq*puijdav*lka`}+umu" fullword ascii
		 $a2= "47619mqqu?**ijbjk+mda(jk`(ojg+fjh*755=*sfdwav*ijb*pv*lka`}+umu" fullword ascii
		 $a3= "+5>%Rlkajrv%KQ%3+4>%Qwla`kq*0+5," fullword ascii

		 $hex1= {2461313d2022343736}
		 $hex2= {2461323d2022343736}
		 $hex3= {2461333d20222b353e}
		 $hex4= {2473313d202225322e}
		 $hex5= {2473323d2022433a57}
		 $hex6= {2473333d2022433a77}
		 $hex7= {2473343d2022536f66}
		 $hex8= {2473353d2022534f46}
		 $hex9= {2473363d2022535953}

	condition:
		6 of them
}
