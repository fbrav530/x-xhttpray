/*
 ============================================================================
 Name        : ServiceReceiver.java
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 xyz
 Description : ServiceReceiver
 ============================================================================
 */

package com.x.tunnel;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

public class ServiceReceiver extends BroadcastReceiver {
	@Override
	public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals(Intent.ACTION_BOOT_COMPLETED)) {
            Preferences prefs = new Preferences(context);
            prefs.setEnable(false);
        }
	}
}

