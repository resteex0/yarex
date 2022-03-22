
/*
   YARA Rule Set
   Author: resteex
   Identifier: APT_Sample_Lazarus 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_APT_Sample_Lazarus {
	meta: 
		 description= "APT_Sample_Lazarus Group" 
		 author = "Resteex Generator" 
		 date = "2022-03-22_14-16-37" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "4f6b0be2dbd49871ff32e8388b011d90"
		 hash2= "5f9a6b47e1d2f0ad1494504398877c10"
		 hash3= "86c314bc2dc37ba84f7364acd5108c2b"
		 hash4= "9ce9a0b3876aacbf0e8023c97fd0a21d"

	strings:

	
 		 $s1= "1xjEipesrc3jo/lx3DoZHzT2b8gatOsUutbx/8yzqq4=!10.0.17134.1#" fullword wide
		 $s2= "api-ms-win-appmodel-runtime-l1-1-1" fullword wide
		 $s3= "api-ms-win-core-datetime-l1-1-1" fullword wide
		 $s4= "api-ms-win-core-fibers-l1-1-1" fullword wide
		 $s5= "api-ms-win-core-file-l2-1-1" fullword wide
		 $s6= "api-ms-win-core-localization-l1-2-1" fullword wide
		 $s7= "api-ms-win-core-localization-obsolete-l1-2-0" fullword wide
		 $s8= "api-ms-win-core-processthreads-l1-1-2" fullword wide
		 $s9= "api-ms-win-core-string-l1-1-0" fullword wide
		 $s10= "api-ms-win-core-synch-l1-2-0" fullword wide
		 $s11= "api-ms-win-core-sysinfo-l1-2-1" fullword wide
		 $s12= "api-ms-win-core-winrt-l1-1-0" fullword wide
		 $s13= "api-ms-win-core-xstate-l2-1-0" fullword wide
		 $s14= "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		 $s15= "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		 $s16= "com.apple.cs.CodeDirectory" fullword wide
		 $s17= "com.apple.cs.CodeRequirements" fullword wide
		 $s18= "com.apple.cs.CodeRequirements-1" fullword wide
		 $s19= "com.apple.cs.CodeSignature" fullword wide
		 $s20= "com.apple.lastuseddate#PS" fullword wide
		 $s21= "ext-ms-win-kernel32-package-current-l1-1-0" fullword wide
		 $s22= "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		 $s23= "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		 $s24= "+JYJT5FRloq614PL+EHmNmsQgce3MgQndMmoFjzLvfU=!10.0.17134.1#" fullword wide
		 $s25= "ZVhntg02deKB+ixcxeWygc/erRryY=!10.0.1713" fullword wide
		 $a1= "amd64_1394.inf.resources_31bf3856ad364e35_zh-cn_b8b3d82378e15786" fullword ascii
		 $a2= "amd64_dual_netl1e64.inf_31bf3856ad364e35_none_e8f9919dec45efdd@" fullword ascii
		 $a3= "amd64_dual_netl260a.inf_31bf3856ad364e35_none_325da7b4773f0430mi" fullword ascii
		 $a4= "amd64_dual_netlldp.inf_31bf3856ad364e35_none_885da4749d660c5b.dl" fullword ascii
		 $a5= "amd64_dual_netloop.inf_31bf3856ad364e35_none_1681eb990b8245cb" fullword ascii
		 $a6= "amd64_dual_netmlx5.inf_31bf3856ad364e35_none_77941a859cc4c323" fullword ascii
		 $a7= "amd64_dual_netmscli.inf_31bf3856ad364e35_none_fc1c5870e2261ec78f" fullword ascii
		 $a8= "amd64_dual_netnvm64.inf_31bf3856ad364e35_none_fc96e18e64bdaa7ex" fullword ascii
		 $a9= "amd64_dual_netnvma.inf_31bf3856ad364e35_none_efa43a340f298e43" fullword ascii
		 $a10= "amd64_dual_netpacer.inf_31bf3856ad364e35_none_609706d8079cccf6" fullword ascii
		 $a11= "amd64_dual_netpgm.inf_31bf3856ad364e35_none_a45005a0051d00a74dac" fullword ascii
		 $a12= "amd64_dual_netr28ux.inf_31bf3856ad364e35_none_2a591c4e383874268f" fullword ascii
		 $a13= "amd64_dual_netr28x.inf_31bf3856ad364e35_none_42e3027c007bfcb7" fullword ascii
		 $a14= "amd64_dual_netr7364.inf_31bf3856ad364e35_none_53510a6a91988b5f" fullword ascii
		 $a15= "amd64_dual_netrasa.inf_31bf3856ad364e35_none_c5903f8ffb760722" fullword ascii
		 $a16= "amd64_dual_netrast.inf_31bf3856ad364e35_none_144dba69e2e0dcef" fullword ascii
		 $a17= "amd64_dual_netrndis.inf_31bf3856ad364e35_none_c8fe19179cf62725" fullword ascii
		 $a18= "amd64_dual_netrtl64.inf_31bf3856ad364e35_none_444ad6684b7c7193D" fullword ascii
		 $a19= "amd64_dual_netrtwlane.inf_31bf3856ad364e35_none_583047fa7457e9d4" fullword ascii
		 $a20= "amd64_dual_netserv.inf_31bf3856ad364e35_none_3ef3099e6761dc39" fullword ascii
		 $a21= "amd64_dual_netsstpa.inf_31bf3856ad364e35_none_05aa0a4338d7989e" fullword ascii
		 $a22= "amd64_dual_nett4x64.inf_31bf3856ad364e35_none_c18bcc599acd94cd" fullword ascii
		 $a23= "amd64_dual_nettcpip.inf_31bf3856ad364e35_none_c4025978473d630f" fullword ascii
		 $a24= "amd64_dual_netvg63a.inf_31bf3856ad364e35_none_6cc1a7010c364aae" fullword ascii
		 $a25= "amd64_dual_netwbw02.inf_31bf3856ad364e35_none_67181df8d089277fL" fullword ascii
		 $a26= "amd64_dual_netwew00.inf_31bf3856ad364e35_none_a91c14c345368dfaL" fullword ascii
		 $a27= "amd64_dual_netwlv64.inf_31bf3856ad364e35_none_ea26420f61d7c058" fullword ascii
		 $a28= "amd64_dual_netwns64.inf_31bf3856ad364e35_none_4360b558525ccbbb.1" fullword ascii
		 $a29= "amd64_dual_netwtw04.inf_31bf3856ad364e35_none_ded79f34d089277f3e" fullword ascii
		 $a30= "amd64_dual_netxex64.inf_31bf3856ad364e35_none_1611400a9174480815" fullword ascii
		 $a31= "amd64_dual_ntprint4.inf_31bf3856ad364e35_none_b6653a673285ec97e" fullword ascii
		 $a32= "amd64_dual_nulhpopr.inf_31bf3856ad364e35_none_ccec91af500fb388 " fullword ascii
		 $a33= "amd64_dual_nvdimm.inf_31bf3856ad364e35_none_1ee002f794c74749" fullword ascii
		 $a34= "amd64_dual_nvraid.inf_31bf3856ad364e35_none_0c326df30d950946" fullword ascii
		 $a35= "amd64_dual_pcmcia.inf_31bf3856ad364e35_none_ec587d91b59af54f/" fullword ascii
		 $a36= "amd64_dual_percsas2i.inf_31bf3856ad364e35_none_d8cdb816cee1447ea" fullword ascii
		 $a37= "amd64_dual_percsas3i.inf_31bf3856ad364e35_none_7bebfc1fc17261b7" fullword ascii
		 $a38= "amd64_dual_printqueue.inf_31bf3856ad364e35_none_33dc9c5a9831815a" fullword ascii
		 $a39= "amd64_dual_prnbrcl1.inf_31bf3856ad364e35_none_95ed80ed012b52ba" fullword ascii
		 $a40= "amd64_dual_prnepcl2.inf_31bf3856ad364e35_none_18841fc724aa426a" fullword ascii
		 $a41= "amd64_dual_prnge001.inf_31bf3856ad364e35_none_9039ce42826c6dabpc" fullword ascii
		 $a42= "amd64_dual_prnhpcl1.inf_31bf3856ad364e35_none_afb3e0779ee6b846" fullword ascii
		 $a43= "amd64_dual_prnhpcl2.inf_31bf3856ad364e35_none_52d224809177d57fU" fullword ascii
		 $a44= "amd64_dual_prnhpcl3.inf_31bf3856ad364e35_none_f5f068898408f2b8_3" fullword ascii
		 $a45= "amd64_dual_prnhpcl4.inf_31bf3856ad364e35_none_990eac92769a0ff1" fullword ascii
		 $a46= "amd64_dual_prnhpnul.inf_31bf3856ad364e35_none_8056e1d88186d0835" fullword ascii
		 $a47= "amd64_dual_prnkmcl4.inf_31bf3856ad364e35_none_4b652de889980219" fullword ascii
		 $a48= "amd64_dual_prnlxclw.inf_31bf3856ad364e35_none_58accefb1dd07c70#" fullword ascii
		 $a49= "amd64_dual_prnms003.inf_31bf3856ad364e35_none_c7330099e4481299Y" fullword ascii
		 $a50= "amd64_dual_prnms007.inf_31bf3856ad364e35_none_53ac10bdae8c877d-c" fullword ascii
		 $a51= "amd64_dual_prnms010.inf_31bf3856ad364e35_none_c70a9947263c098d60" fullword ascii
		 $a52= "amd64_dual_prnms012.inf_31bf3856ad364e35_none_0d4721590b5e43ff/" fullword ascii
		 $a53= "amd64_dual_prnms013.inf_31bf3856ad364e35_none_b0656561fdef6138" fullword ascii
		 $a54= "amd64_dual_prnokcl1.inf_31bf3856ad364e35_none_aa4768dcb1c1adecys" fullword ascii
		 $a55= "amd64_dual_rhproxy.inf_31bf3856ad364e35_none_a4c196754297db2e-_" fullword ascii
		 $a56= "amd64_dual_rt640x64.inf_31bf3856ad364e35_none_731691f52e230930" fullword ascii
		 $a57= "amd64_dual_rtux64w10.inf_31bf3856ad364e35_none_fdaf0a9981fef1f5" fullword ascii
		 $a58= "amd64_dual_rtvdevx64.inf_31bf3856ad364e35_none_f0009f603024dd53" fullword ascii
		 $a59= "amd64_dual_sbp2.inf_31bf3856ad364e35_none_d6791a75098682d5rces_3" fullword ascii
		 $a60= "amd64_dual_scmbus.inf_31bf3856ad364e35_none_7a82baeca96e357f" fullword ascii
		 $a61= "amd64_dual_scmvolume.inf_31bf3856ad364e35_none_d501749f999a0c01" fullword ascii
		 $a62= "amd64_dual_scunknown.inf_31bf3856ad364e35_none_494cc1353e892726" fullword ascii
		 $a63= "amd64_dual_sdstor.inf_31bf3856ad364e35_none_8cb94b28efaa7acf" fullword ascii
		 $a64= "amd64_dual_sisraid4.inf_31bf3856ad364e35_none_dd771e17a7b4567d" fullword ascii
		 $a65= "amd64_dual_smrvolume.inf_31bf3856ad364e35_none_c55a436ae015740c" fullword ascii
		 $a66= "amd64_dual_storufs.inf_31bf3856ad364e35_none_ddca4eb439ed4650" fullword ascii
		 $a67= "amd64_dual_swenum.inf_31bf3856ad364e35_none_e201f0c0fd510989W" fullword ascii
		 $a68= "amd64_dual_tdibth.inf_31bf3856ad364e35_none_d8926f7ab9c59379H@" fullword ascii
		 $a69= "amd64_dual_termmou.inf_31bf3856ad364e35_none_69af5f867aecade5urc" fullword ascii
		 $a70= "amd64_dual_ts_generic.inf_31bf3856ad364e35_none_643ab9324689e24f" fullword ascii
		 $a71= "amd64_dual_tsprint.inf_31bf3856ad364e35_none_40b706322790a33e" fullword ascii
		 $a72= "amd64_dual_tsusbhub.inf_31bf3856ad364e35_none_d8e949096e153450" fullword ascii
		 $a73= "amd64_dual_ts_wpdmtp.inf_31bf3856ad364e35_none_998ce1be85602e9e" fullword ascii
		 $a74= "amd64_dual_uicciso.inf_31bf3856ad364e35_none_f7099deeefe39437" fullword ascii
		 $a75= "amd64_dual_uiccspb.inf_31bf3856ad364e35_none_e40b9aaf8268a3ff" fullword ascii
		 $a76= "amd64_dual_umbus.inf_31bf3856ad364e35_none_28ee92f5adc584eadows-" fullword ascii
		 $a77= "amd64_dual_umpass.inf_31bf3856ad364e35_none_44019bec712454cdf.ex" fullword ascii
		 $a78= "amd64_dual_usbcir.inf_31bf3856ad364e35_none_3a701e612bbe7618n" fullword ascii
		 $a79= "amd64_dual_usbhub3.inf_31bf3856ad364e35_none_d5f9184ff3768b10" fullword ascii
		 $a80= "amd64_dual_usbncm.inf_31bf3856ad364e35_none_298eb20166c447a4!" fullword ascii
		 $a81= "amd64_dual_usbnet.inf_31bf3856ad364e35_none_8823db5d5277af21" fullword ascii
		 $a82= "amd64_dual_usbport.inf_31bf3856ad364e35_none_1cc6f4fee9beefedk " fullword ascii
		 $a83= "amd64_dual_usbprint.inf_31bf3856ad364e35_none_b44edae9c944603bt." fullword ascii
		 $a84= "amd64_dual_usbstor.inf_31bf3856ad364e35_none_1537e9aed87856aayen" fullword ascii
		 $a85= "amd64_dual_usbvideo.inf_31bf3856ad364e35_none_2b1f2d8874221fdd" fullword ascii
		 $a86= "amd64_dual_usbxhci.inf_31bf3856ad364e35_none_ea9adce419c2cc9056a" fullword ascii
		 $a87= "amd64_dual_virtdisk.inf_31bf3856ad364e35_none_2b29ec0759977d3a" fullword ascii
		 $a88= "amd64_dual_v_mscdsc.inf_31bf3856ad364e35_none_890220b9141cec04j" fullword ascii
		 $a89= "amd64_dual_volume.inf_31bf3856ad364e35_none_afaebca1fea1c24c" fullword ascii
		 $a90= "amd64_dual_vrd.inf_31bf3856ad364e35_none_786b1fcdd449ef70y.resou" fullword ascii
		 $a91= "amd64_dual_vsmraid.inf_31bf3856ad364e35_none_eb6d235cc051e448" fullword ascii
		 $a92= "amd64_dual_vstxraid.inf_31bf3856ad364e35_none_4bcc4b9d371920434a" fullword ascii
		 $a93= "amd64_dual_wdmaudio.inf_31bf3856ad364e35_none_ebc912f85506142e" fullword ascii
		 $a94= "amd64_dual_wdma_usb.inf_31bf3856ad364e35_none_e12376e11c9566ae" fullword ascii
		 $a95= "amd64_dual_wdmvsc.inf_31bf3856ad364e35_none_124461873337a260" fullword ascii
		 $a96= "amd64_dual_wfcvsc.inf_31bf3856ad364e35_none_5e2f676708624bd8I" fullword ascii
		 $a97= "amd64_dual_wfpcapture.inf_31bf3856ad364e35_none_fc89fa929099897b" fullword ascii
		 $a98= "amd64_dual_whvcrash.inf_31bf3856ad364e35_none_b305ec55ecd8ff402" fullword ascii
		 $a99= "amd64_dual_wiahp008.inf_31bf3856ad364e35_none_7408a5a41f0823816" fullword ascii
		 $a100= "amd64_dual_wiasa003.inf_31bf3856ad364e35_none_1beb394a856b8810P" fullword ascii
		 $a101= "amd64_dual_wiaxx002.inf_31bf3856ad364e35_none_993d74654e138713Y" fullword ascii
		 $a102= "amd64_dual_wmiacpi.inf_31bf3856ad364e35_none_acce13f652b57ffa" fullword ascii
		 $a103= "amd64_dual_wpdcomp.inf_31bf3856ad364e35_none_25bc90852de38b1e" fullword ascii
		 $a104= "amd64_dual_wpdmtphw.inf_31bf3856ad364e35_none_43b86d1affa93433/" fullword ascii
		 $a105= "amd64_dual_wsdprint.inf_31bf3856ad364e35_none_491949978389795fV" fullword ascii
		 $a106= "amd64_dual_wsdscdrv.inf_31bf3856ad364e35_none_c27d942bfd712eb4y" fullword ascii
		 $a107= "amd64_dual_wstorflt.inf_31bf3856ad364e35_none_8f41717422a687ef3" fullword ascii
		 $a108= "amd64_dual_wvmbus.inf_31bf3856ad364e35_none_5e48814590f67a381" fullword ascii
		 $a109= "amd64_dual_wvmbusr.inf_31bf3856ad364e35_none_aa08997fcf370ca6" fullword ascii
		 $a110= "amd64_dual_wvmic_ext.inf_31bf3856ad364e35_none_1ab969079170aa5a" fullword ascii
		 $a111= "amd64_dual_wvms_pp.inf_31bf3856ad364e35_none_c3dcd0edd993642c" fullword ascii
		 $a112= "amd64_dual_wvms_vsft.inf_31bf3856ad364e35_none_7e7fd83e481572fb" fullword ascii
		 $a113= "amd64_dual_wvms_vspp.inf_31bf3856ad364e35_none_28032cc74a0115f9" fullword ascii
		 $a114= "amd64_dual_wvpcivsp.inf_31bf3856ad364e35_none_6490f69da29405dau" fullword ascii
		 $a115= "amd64_dual_xinputhid.inf_31bf3856ad364e35_none_97ac01789fb082b5" fullword ascii
		 $a116= "amd64_presentationcore_31bf3856ad364e35_none_9d0fae743fccc3ad" fullword ascii
		 $a117= "amd64_system.drawing.tlb_31bf3856ad364e35_none_d3ec14ea42bf9922" fullword ascii
		 $a118= "amd64_system.transactions_b77a5c561934e089_none_07cff7bff55cd548" fullword ascii
		 $a119= "amd64_windows-defender-ui_31bf3856ad364e35_none_c9b0b556ef371def" fullword ascii
		 $a120= "amd64_windows-media-ocr_31bf3856ad364e35_none_8426ddee2e108fa2" fullword ascii
		 $a121= "amd64_windowssearchengine_31bf3856ad364e35_none_eb085efa1f494418" fullword ascii
		 $a122= "c!dual_bth.inf_31bf3856ad364e35_10.0.17134.191_3bade30ed5956b62" fullword ascii
		 $a123= "c!dual_bth.inf_31bf3856ad364e35_10.0.17134.376_3bc88824d580ac81" fullword ascii
		 $a124= "c!dual_pci.inf_31bf3856ad364e35_10.0.17134.254_23f4cbff35923512" fullword ascii
		 $a125= "c!dual_sti.inf_31bf3856ad364e35_10.0.17134.48_295aebb08e3ab15b" fullword ascii
		 $a126= "c!dual_tpm.inf_31bf3856ad364e35_10.0.17134.254_00fef55ce97dff9d" fullword ascii
		 $a127= "dual_bth.inf_31bf3856ad364e35_10.0.17134.376_3bc88824d580ac81" fullword ascii
		 $a128= ";http://crl.comodoca.com/COMODORSACertificationAuthority.crl0q" fullword ascii
		 $a129= "msil_system.windows.forms_b77a5c561934e089_none_20e421e146d99832" fullword ascii
		 $a130= "msil_system.xaml.hosting_31bf3856ad364e35_none_caf6f395c326b876" fullword ascii
		 $a131= "msil_uiautomationprovider_31bf3856ad364e35_none_35b97f242172c125" fullword ascii
		 $a132= "msil_uiautomationtypes_31bf3856ad364e35_none_db1206d14c69dfb1" fullword ascii
		 $a133= "wow64_multimedia-mferror_31bf3856ad364e35_none_06e726dbbfdfbb79" fullword ascii
		 $a134= "wow64_netfx4-wcf-client_31bf3856ad364e35_none_b569d7dff7e26bfc" fullword ascii
		 $a135= "wow64_netfx4-wcf-extended_31bf3856ad364e35_none_165085322d5faf6e" fullword ascii
		 $a136= "wow64_netfxaspnetcorecomp_31bf3856ad364e35_none_d12b5024355f3e9e" fullword ascii
		 $a137= "wow64_networking-mpssvc-powershell-core_31bf3856ad364e35hbin" fullword ascii
		 $a138= "wow64_windows-media-ocr_31bf3856ad364e35_none_8e7b88406271519d" fullword ascii
		 $a139= "wow64_windowssearchengine_31bf3856ad364e35_none_f55d094c53aa0613" fullword ascii
		 $a140= "wow64_wsdapi.resources_31bf3856ad364e35_zh-cn_1852a461894f1ba5" fullword ascii
		 $a141= "x86_dual_prnms003.inf_31bf3856ad364e35_none_6b1465162beaa163" fullword ascii
		 $a142= "x86_netfx-mscoree_dll_31bf3856ad364e35_none_d75e4580629be046" fullword ascii
		 $a143= "x86_netfx-mscorees_dll_31bf3856ad364e35_none_f4098f98959b74c1" fullword ascii
		 $a144= "x86_netfx-mscories_dll_31bf3856ad364e35_none_fba36e008a34a725" fullword ascii
		 $a145= "x86_smsvchost.registry_31bf3856ad364e35_none_8c93461e86736c1c" fullword ascii
		 $a146= "x86_system.drawing.tlb_31bf3856ad364e35_none_77cd79668a6227ec" fullword ascii

		 $hex1= {2b4a594a543546526c}
		 $hex2= {31786a456970657372}
		 $hex3= {3b687474703a2f2f63}
		 $hex4= {5a56686e7467303264}
		 $hex5= {616d6436345f313339}
		 $hex6= {616d6436345f647561}
		 $hex7= {616d6436345f707265}
		 $hex8= {616d6436345f737973}
		 $hex9= {616d6436345f77696e}
		 $hex10= {6170692d6d732d7769}
		 $hex11= {63216475616c5f6274}
		 $hex12= {63216475616c5f7063}
		 $hex13= {63216475616c5f7374}
		 $hex14= {63216475616c5f7470}
		 $hex15= {636f6d2e6170706c65}
		 $hex16= {6475616c5f6274682e}
		 $hex17= {6578742d6d732d7769}
		 $hex18= {6d73696c5f73797374}
		 $hex19= {6d73696c5f75696175}
		 $hex20= {776f7736345f6d756c}
		 $hex21= {776f7736345f6e6574}
		 $hex22= {776f7736345f77696e}
		 $hex23= {776f7736345f777364}
		 $hex24= {7838365f6475616c5f}
		 $hex25= {7838365f6e65746678}
		 $hex26= {7838365f736d737663}
		 $hex27= {7838365f7379737465}

	condition:
		66 of them
}
