
/*
   YARA Rule Set
   Author: resteex
   Identifier: MacOS_KeRanger 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_MacOS_KeRanger {
	meta: 
		 description= "MacOS_KeRanger Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_11-18-26" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "14a4df1df622562b3bf5bc9a94e6a783"
		 hash2= "1d6297e2427f1d00a5b355d6d50809cb"
		 hash3= "24a8f01cfdc4228b4fc9bb87fedf6eb7"
		 hash4= "3151d9a085d14508fa9f10d48afc7016"
		 hash5= "56b1d956112b0b7bd3e44f20cf1f2c19"
		 hash6= "861c3da2bbce6c09eda2709c8994f34c"

	strings:

	
 		 $s1= "!com.apple.LaunchServices.OpenWith" fullword wide
		 $a1= "@88@0:8@16@24^{tr_torrent=}32@40^{tr_session=}48@56@64@72@80" fullword ascii
		 $a2= "drawInRect:fromRect:operation:fraction:respectFlipped:hints:" fullword ascii
		 $a3= "_evthread_is_debug_lock_held((handle->current_req->base)->lock)" fullword ascii
		 $a4= "@executable_path/../Frameworks/Growl.framework/Versions/A/Growl" fullword ascii
		 $a5= "@loader_path/../Frameworks/Sparkle.framework/Versions/A/Sparkle" fullword ascii
		 $a6= "outlineView:shouldTypeSelectForEvent:withCurrentSearchString:" fullword ascii
		 $a7= "outlineView:toolTipForCell:rect:tableColumn:item:mouseLocation:" fullword ascii
		 $a8= "presentSheetForFileListNode:modalForWindow:completionHandler:" fullword ascii
		 $a9= "rectForStatusWithString:withAboveRect:withRightRect:inBounds:" fullword ascii
		 $a10= "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:" fullword ascii
		 $a11= "sharingService:sourceWindowForShareItems:sharingContentScope:" fullword ascii
		 $a12= "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit" fullword ascii
		 $a13= "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon" fullword ascii
		 $a14= "/System/Library/Frameworks/Quartz.framework/Versions/A/Quartz" fullword ascii
		 $a15= "tableView:toolTipForCell:rect:tableColumn:row:mouseLocation:" fullword ascii
		 $a16= "timeString:includesTimeRemainingPhrase:showSeconds:maxFields:" fullword ascii
		 $a17= "/Users/admin/Workspace/Transmission/libtransmission/announcer.c" fullword ascii
		 $a18= "/Users/admin/Workspace/Transmission/libtransmission/bandwidth.c" fullword ascii
		 $a19= "/Users/admin/Workspace/Transmission/libtransmission/blocklist.c" fullword ascii
		 $a20= "/Users/admin/Workspace/Transmission/libtransmission/fdlimit.c" fullword ascii
		 $a21= "/Users/admin/Workspace/Transmission/libtransmission/file-posix.c" fullword ascii
		 $a22= "/Users/admin/Workspace/Transmission/libtransmission/handshake.c" fullword ascii
		 $a23= "/Users/admin/Workspace/Transmission/libtransmission/makemeta.c" fullword ascii
		 $a24= "/Users/admin/Workspace/Transmission/libtransmission/metainfo.c" fullword ascii
		 $a25= "/Users/admin/Workspace/Transmission/libtransmission/natpmp.c" fullword ascii
		 $a26= "/Users/admin/Workspace/Transmission/libtransmission/peer-io.c" fullword ascii
		 $a27= "/Users/admin/Workspace/Transmission/libtransmission/peer-mgr.c" fullword ascii
		 $a28= "/Users/admin/Workspace/Transmission/libtransmission/peer-msgs.c" fullword ascii
		 $a29= "/Users/admin/Workspace/Transmission/libtransmission/platform.c" fullword ascii
		 $a30= "/Users/admin/Workspace/Transmission/libtransmission/resume.c" fullword ascii
		 $a31= "/Users/admin/Workspace/Transmission/libtransmission/rpcimpl.c" fullword ascii
		 $a32= "/Users/admin/Workspace/Transmission/libtransmission/rpc-server.c" fullword ascii
		 $a33= "/Users/admin/Workspace/Transmission/libtransmission/session.c" fullword ascii
		 $a34= "/Users/admin/Workspace/Transmission/libtransmission/torrent.c" fullword ascii
		 $a35= "/Users/admin/Workspace/Transmission/libtransmission/tr-dht.c" fullword ascii
		 $a36= "/Users/admin/Workspace/Transmission/libtransmission/trevent.c" fullword ascii
		 $a37= "/Users/admin/Workspace/Transmission/libtransmission/tr-lpd.c" fullword ascii
		 $a38= "/Users/admin/Workspace/Transmission/libtransmission/tr-udp.c" fullword ascii
		 $a39= "/Users/admin/Workspace/Transmission/libtransmission/tr-utp.c" fullword ascii
		 $a40= "/Users/admin/Workspace/Transmission/libtransmission/variant.c" fullword ascii
		 $a41= "/Users/admin/Workspace/Transmission/libtransmission/verify.c" fullword ascii
		 $a42= "/Users/admin/Workspace/Transmission/third-party/libevent/evdns.c" fullword ascii
		 $a43= "/Users/admin/Workspace/Transmission/third-party/libevent/event.c" fullword ascii
		 $a44= "/Users/admin/Workspace/Transmission/third-party/libevent/evmap.c" fullword ascii
		 $a45= "/Users/admin/Workspace/Transmission/third-party/libevent/http.c" fullword ascii
		 $a46= "/Users/admin/Workspace/Transmission/third-party/libevent/poll.c" fullword ascii
		 $a47= "v80@0:8@16{CGRect={CGPoint=dd}{CGSize=dd}}24@56{CGPoint=dd}64" fullword ascii

		 $hex1= {246131303d20227363}
		 $hex2= {246131313d20227368}
		 $hex3= {246131323d20222f53}
		 $hex4= {246131333d20222f53}
		 $hex5= {246131343d20222f53}
		 $hex6= {246131353d20227461}
		 $hex7= {246131363d20227469}
		 $hex8= {246131373d20222f55}
		 $hex9= {246131383d20222f55}
		 $hex10= {246131393d20222f55}
		 $hex11= {2461313d2022403838}
		 $hex12= {246132303d20222f55}
		 $hex13= {246132313d20222f55}
		 $hex14= {246132323d20222f55}
		 $hex15= {246132333d20222f55}
		 $hex16= {246132343d20222f55}
		 $hex17= {246132353d20222f55}
		 $hex18= {246132363d20222f55}
		 $hex19= {246132373d20222f55}
		 $hex20= {246132383d20222f55}
		 $hex21= {246132393d20222f55}
		 $hex22= {2461323d2022647261}
		 $hex23= {246133303d20222f55}
		 $hex24= {246133313d20222f55}
		 $hex25= {246133323d20222f55}
		 $hex26= {246133333d20222f55}
		 $hex27= {246133343d20222f55}
		 $hex28= {246133353d20222f55}
		 $hex29= {246133363d20222f55}
		 $hex30= {246133373d20222f55}
		 $hex31= {246133383d20222f55}
		 $hex32= {246133393d20222f55}
		 $hex33= {2461333d20225f6576}
		 $hex34= {246134303d20222f55}
		 $hex35= {246134313d20222f55}
		 $hex36= {246134323d20222f55}
		 $hex37= {246134333d20222f55}
		 $hex38= {246134343d20222f55}
		 $hex39= {246134353d20222f55}
		 $hex40= {246134363d20222f55}
		 $hex41= {246134373d20227638}
		 $hex42= {2461343d2022406578}
		 $hex43= {2461353d2022406c6f}
		 $hex44= {2461363d20226f7574}
		 $hex45= {2461373d20226f7574}
		 $hex46= {2461383d2022707265}
		 $hex47= {2461393d2022726563}
		 $hex48= {2473313d202221636f}

	condition:
		24 of them
}
