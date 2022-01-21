
/*
   YARA Rule Set
   Author: resteex
   Identifier: theZoo_Win32_TransparentTribe_B 
   /
/* Rule Set ----------------------------------------------------------------- */

rule resteex_theZoo_Win32_TransparentTribe_B {
	meta: 
		 description= "theZoo_Win32_TransparentTribe_B Group" 
		 author = "Resteex Generator" 
		 date = "2022-01-20_21-36-57" 
		 license = "https://github.com/resteex0/yarex"
		 hash1= "15da10765b7becfcca3325a91d90db37"
		 hash2= "48476da4403243b342a166d8a6be7a3f"
		 hash3= "53cd72147b0ef6bf6e64d266bf3ccafe"
		 hash4= "6c3308cd8a060327d841626a677a0549"
		 hash5= "d7d6889bfa96724f7b3f951bc06e8c02"

	strings:

	
 		 $s1= "8BFFDB8BB9D}#2.0#0#C:Users" fullword wide
		 $s2= "DocumentSummaryInformation" fullword wide
		 $s3= "spanish-dominican republic" fullword wide
		 $s4= "TableStyleMedium9PivotStyleLight16" fullword wide
		 $a1= ".?AVCancellationTokenRegistration_TaskProc@details@Concurrency@@" fullword ascii
		 $a2= ".?AVinvalid_scheduler_policy_thread_specification@Concurrency@@" fullword ascii
		 $a3= "kotlin/collections/AbstractMutableCollection.kotlin_metadatae" fullword ascii
		 $a4= "kotlin/collections/AbstractMutableCollection.kotlin_metadataPK" fullword ascii
		 $a5= "kotlin/collections/MutableMapWithDefaultImpl.kotlin_metadatamPKS" fullword ascii
		 $a6= "kotlin/collections/MutableMapWithDefaultImpl.kotlin_metadataPK" fullword ascii
		 $a7= "kotlin/coroutines/ContinuationInterceptor.kotlin_metadataUOMJ" fullword ascii
		 $a8= "kotlin/coroutines/experimental/CombinedContext.kotlin_metadata5P" fullword ascii
		 $a9= "kotlin/coroutines/experimental/CombinedContext.kotlin_metadataPK" fullword ascii
		 $a10= "kotlin/coroutines/experimental/Continuation.kotlin_metadataE" fullword ascii
		 $a11= "kotlin/coroutines/experimental/Continuation.kotlin_metadataPK" fullword ascii
		 $a12= "kotlin/coroutines/experimental/CoroutineContext.kotlin_metadatae" fullword ascii
		 $a13= "kotlin/coroutines/experimental/SafeContinuation.kotlin_metadataU" fullword ascii
		 $a14= "kotlin/coroutines/experimental/SequenceBuilder.kotlin_metadata]" fullword ascii
		 $a15= "kotlin/coroutines/experimental/SequenceBuilder.kotlin_metadataPK" fullword ascii
		 $a16= "kotlin/experimental/ExperimentalTypeInference.kotlin_metadataM" fullword ascii
		 $a17= "kotlin/experimental/ExperimentalTypeInference.kotlin_metadataPK" fullword ascii
		 $a18= "kotlin/internal/LowPriorityInOverloadResolution.kotlin_metadataE" fullword ascii
		 $a19= "kotlin/sequences/TransformingIndexedSequence.kotlin_metadata=N=O" fullword ascii
		 $a20= "kotlin/sequences/TransformingIndexedSequence.kotlin_metadataPK" fullword ascii
		 $a21= "kotlin/UninitializedPropertyAccessException.kotlin_metadataE" fullword ascii
		 $a22= "kotlin/UninitializedPropertyAccessException.kotlin_metadataPK" fullword ascii
		 $a23= "META-INF/androidx.coordinatorlayout_coordinatorlayout.versionPK" fullword ascii
		 $a24= "META-INF/androidx.slidingpanelayout_slidingpanelayout.version5" fullword ascii
		 $a25= "META-INF/androidx.slidingpanelayout_slidingpanelayout.versionPK" fullword ascii
		 $a26= "META-INF/androidx.swiperefreshlayout_swiperefreshlayout.version5" fullword ascii
		 $a27= "META-INF/kotlin-stdlib-common-coroutines.kotlin_modulec```f```" fullword ascii
		 $a28= "META-INF/kotlin-stdlib_coroutinesExperimental.kotlin_modulePK" fullword ascii
		 $a29= "::res/drawable-hdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a30= "res/drawable-hdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a31= "::res/drawable-mdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a32= "::res/drawable-xhdpi-v4/notification_bg_normal_pressed.9.png" fullword ascii
		 $a33= ";;res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.png" fullword ascii
		 $a34= "res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.png5" fullword ascii
		 $a35= "res/drawable-xhdpi-v4/notify_panel_notification_icon_bg.pngPK" fullword ascii
		 $a36= "res/layout/notification_template_big_media_narrow_custom.xml" fullword ascii
		 $a37= "res/layout/notification_template_big_media_narrow_custom.xmlPK" fullword ascii
		 $a38= "res/layout-v17/notification_template_big_media_narrow_custom.xml" fullword ascii

		 $hex1= {246131303d20226b6f}
		 $hex2= {246131313d20226b6f}
		 $hex3= {246131323d20226b6f}
		 $hex4= {246131333d20226b6f}
		 $hex5= {246131343d20226b6f}
		 $hex6= {246131353d20226b6f}
		 $hex7= {246131363d20226b6f}
		 $hex8= {246131373d20226b6f}
		 $hex9= {246131383d20226b6f}
		 $hex10= {246131393d20226b6f}
		 $hex11= {2461313d20222e3f41}
		 $hex12= {246132303d20226b6f}
		 $hex13= {246132313d20226b6f}
		 $hex14= {246132323d20226b6f}
		 $hex15= {246132333d20224d45}
		 $hex16= {246132343d20224d45}
		 $hex17= {246132353d20224d45}
		 $hex18= {246132363d20224d45}
		 $hex19= {246132373d20224d45}
		 $hex20= {246132383d20224d45}
		 $hex21= {246132393d20223a3a}
		 $hex22= {2461323d20222e3f41}
		 $hex23= {246133303d20227265}
		 $hex24= {246133313d20223a3a}
		 $hex25= {246133323d20223a3a}
		 $hex26= {246133333d20223b3b}
		 $hex27= {246133343d20227265}
		 $hex28= {246133353d20227265}
		 $hex29= {246133363d20227265}
		 $hex30= {246133373d20227265}
		 $hex31= {246133383d20227265}
		 $hex32= {2461333d20226b6f74}
		 $hex33= {2461343d20226b6f74}
		 $hex34= {2461353d20226b6f74}
		 $hex35= {2461363d20226b6f74}
		 $hex36= {2461373d20226b6f74}
		 $hex37= {2461383d20226b6f74}
		 $hex38= {2461393d20226b6f74}
		 $hex39= {2473313d2022384246}
		 $hex40= {2473323d2022446f63}
		 $hex41= {2473333d2022737061}
		 $hex42= {2473343d2022546162}

	condition:
		28 of them
}
