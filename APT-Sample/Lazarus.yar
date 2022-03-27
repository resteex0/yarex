
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
		 date = "2022-03-27_08-13-56" 
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

		 $hex1= {2b??4a??59??4a??54??35??46??52??6c??6f??71??36??31??34??50??4c??2b??45??48??6d??4e??6d??73??51??67??63??65??33??4d??67??}
		 $hex2= {31??78??6a??45??69??70??65??73??72??63??33??6a??6f??2f??6c??78??33??44??6f??5a??48??7a??54??32??62??38??67??61??74??4f??}
		 $hex3= {5a??56??68??6e??74??67??30??32??64??65??4b??42??2b??69??78??63??78??65??57??79??67??63??2f??65??72??52??72??79??59??3d??}
		 $hex4= {61??6d??64??36??34??5f??31??33??39??34??2e??69??6e??66??2e??72??65??73??6f??75??72??63??65??73??5f??33??31??62??66??33??}
		 $hex5= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6c??31??65??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex6= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6c??32??36??30??61??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex7= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6c??6c??64??70??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex8= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6c??6f??6f??70??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex9= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6d??6c??78??35??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex10= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6d??73??63??6c??69??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex11= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6e??76??6d??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex12= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??6e??76??6d??61??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex13= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??70??61??63??65??72??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex14= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??70??67??6d??2e??69??6e??66??5f??33??31??62??66??33??38??35??36??}
		 $hex15= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??32??38??75??78??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex16= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??32??38??78??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex17= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??37??33??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex18= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??61??73??61??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex19= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??61??73??74??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex20= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??6e??64??69??73??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex21= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??74??6c??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex22= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??72??74??77??6c??61??6e??65??2e??69??6e??66??5f??33??31??62??66??}
		 $hex23= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??73??65??72??76??2e??69??6e??66??5f??33??31??62??66??33??38??35??}
		 $hex24= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??73??73??74??70??61??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex25= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??74??34??78??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex26= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??74??63??70??69??70??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex27= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??76??67??36??33??61??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex28= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??77??62??77??30??32??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex29= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??77??65??77??30??30??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex30= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??77??6c??76??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex31= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??77??6e??73??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex32= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??77??74??77??30??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex33= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??65??74??78??65??78??36??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex34= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??74??70??72??69??6e??74??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex35= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??75??6c??68??70??6f??70??72??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex36= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??76??64??69??6d??6d??2e??69??6e??66??5f??33??31??62??66??33??38??35??36??}
		 $hex37= {61??6d??64??36??34??5f??64??75??61??6c??5f??6e??76??72??61??69??64??2e??69??6e??66??5f??33??31??62??66??33??38??35??36??}
		 $hex38= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??63??6d??63??69??61??2e??69??6e??66??5f??33??31??62??66??33??38??35??36??}
		 $hex39= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??65??72??63??73??61??73??32??69??2e??69??6e??66??5f??33??31??62??66??33??}
		 $hex40= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??65??72??63??73??61??73??33??69??2e??69??6e??66??5f??33??31??62??66??33??}
		 $hex41= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??69??6e??74??71??75??65??75??65??2e??69??6e??66??5f??33??31??62??66??}
		 $hex42= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??62??72??63??6c??31??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex43= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??65??70??63??6c??32??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex44= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??67??65??30??30??31??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex45= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??68??70??63??6c??31??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex46= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??68??70??63??6c??32??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex47= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??68??70??63??6c??33??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex48= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??68??70??63??6c??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex49= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??68??70??6e??75??6c??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex50= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??6b??6d??63??6c??34??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex51= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??6c??78??63??6c??77??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex52= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??6d??73??30??30??33??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex53= {61??6d??64??36??34??5f??64??75??61??6c??5f??70??72??6e??6d??73??30??30??37??2e??69??6e??66??5f??33??31??62??66??33??38??}
		 $hex54= {61??70??69??2d??6d??73??2d??77??69??6e??2d??61??70??70??6d??6f??64??65??6c??2d??72??75??6e??74??69??6d??65??2d??6c??31??}
		 $hex55= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??64??61??74??65??74??69??6d??65??2d??6c??31??2d??31??2d??}
		 $hex56= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??62??65??72??73??2d??6c??31??2d??31??2d??31??0a??}
		 $hex57= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??66??69??6c??65??2d??6c??32??2d??31??2d??31??0a??}
		 $hex58= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??6c??6f??63??61??6c??69??7a??61??74??69??6f??6e??2d??6c??}
		 $hex59= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??6c??6f??63??61??6c??69??7a??61??74??69??6f??6e??2d??6f??}
		 $hex60= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??70??72??6f??63??65??73??73??74??68??72??65??61??64??73??}
		 $hex61= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??74??72??69??6e??67??2d??6c??31??2d??31??2d??30??0a??}
		 $hex62= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??6e??63??68??2d??6c??31??2d??32??2d??30??0a??}
		 $hex63= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??73??79??73??69??6e??66??6f??2d??6c??31??2d??32??2d??31??}
		 $hex64= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??77??69??6e??72??74??2d??6c??31??2d??31??2d??30??0a??}
		 $hex65= {61??70??69??2d??6d??73??2d??77??69??6e??2d??63??6f??72??65??2d??78??73??74??61??74??65??2d??6c??32??2d??31??2d??30??0a??}
		 $hex66= {61??70??69??2d??6d??73??2d??77??69??6e??2d??72??74??63??6f??72??65??2d??6e??74??75??73??65??72??2d??77??69??6e??64??6f??}
		 $hex67= {61??70??69??2d??6d??73??2d??77??69??6e??2d??73??65??63??75??72??69??74??79??2d??73??79??73??74??65??6d??66??75??6e??63??}
		 $hex68= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??44??69??72??65??63??74??6f??72??79??0a??}
		 $hex69= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??0a??}
		 $hex70= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??52??65??71??75??69??72??65??6d??65??6e??74??73??2d??}
		 $hex71= {63??6f??6d??2e??61??70??70??6c??65??2e??63??73??2e??43??6f??64??65??53??69??67??6e??61??74??75??72??65??0a??}
		 $hex72= {63??6f??6d??2e??61??70??70??6c??65??2e??6c??61??73??74??75??73??65??64??64??61??74??65??23??50??53??0a??}
		 $hex73= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6b??65??72??6e??65??6c??33??32??2d??70??61??63??6b??61??67??65??2d??63??75??}
		 $hex74= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??64??69??61??6c??6f??67??62??6f??78??2d??6c??31??}
		 $hex75= {65??78??74??2d??6d??73??2d??77??69??6e??2d??6e??74??75??73??65??72??2d??77??69??6e??64??6f??77??73??74??61??74??69??6f??}

	condition:
		83 of them
}