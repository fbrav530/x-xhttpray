/*
 ============================================================================
 Name        : MainActivity.java
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2023 xyz
 Description : Main Activity
 ============================================================================
 */

package com.x.tunnel;

import android.os.Bundle;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.Context;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.widget.FrameLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class MainActivity extends Activity implements View.OnClickListener {
	private Preferences prefs;
    private View item_profile_select;
    private TextView value_profile;
    private Button btn_add_profile;
    private Button btn_save_profile;
    private Button btn_rename_profile;
    private Button btn_delete_profile;
    private View item_wss_addr;
    private View item_token;
    private View item_pref_ip;
    private View item_udp_block_ports;
    private View item_ech_dns;
    private View item_ech_domain;
    private View item_ips_pref;
    private View item_insecure;
    private View item_disable_ech;
    private View item_ws_conn;
    private TextView value_wss_addr;
    private TextView value_token;
    private TextView value_pref_ip;
    private TextView value_udp_block_ports;
    private TextView value_ech_dns;
    private TextView value_ech_domain;
    private TextView value_ips_pref;
    private TextView value_ws_conn;
    private Button button_ws_conn_minus;
    private Button button_ws_conn_plus;
    private CheckBox checkbox_global;
    private CheckBox checkbox_disable_ech;
    private CheckBox checkbox_insecure;
    private Button button_apps;
    private Button button_control;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		prefs = new Preferences(this);
		setContentView(R.layout.main);

        item_profile_select = findViewById(R.id.item_profile_select);
        value_profile = (TextView) findViewById(R.id.value_profile);
        btn_add_profile = (Button) findViewById(R.id.btn_add_profile);
        btn_save_profile = (Button) findViewById(R.id.btn_save_profile);
        btn_rename_profile = (Button) findViewById(R.id.btn_rename_profile);
        btn_delete_profile = (Button) findViewById(R.id.btn_delete_profile);

        item_wss_addr = findViewById(R.id.item_wss_addr);
        item_token = findViewById(R.id.item_token);
        item_pref_ip = findViewById(R.id.item_pref_ip);
        item_udp_block_ports = findViewById(R.id.item_udp_block_ports);
        item_ech_dns = findViewById(R.id.item_ech_dns);
        item_ech_domain = findViewById(R.id.item_ech_domain);
        item_ips_pref = findViewById(R.id.item_ips_pref);
        item_insecure = findViewById(R.id.item_insecure);
        item_disable_ech = findViewById(R.id.item_disable_ech);
        item_ws_conn = findViewById(R.id.item_ws_conn);
        value_wss_addr = (TextView) findViewById(R.id.value_wss_addr);
        value_token = (TextView) findViewById(R.id.value_token);
        value_pref_ip = (TextView) findViewById(R.id.value_pref_ip);
        value_udp_block_ports = (TextView) findViewById(R.id.value_udp_block_ports);
        value_ech_dns = (TextView) findViewById(R.id.value_ech_dns);
        value_ech_domain = (TextView) findViewById(R.id.value_ech_domain);
        value_ips_pref = (TextView) findViewById(R.id.value_ips_pref);
        value_ws_conn = (TextView) findViewById(R.id.value_ws_conn);
        button_ws_conn_minus = (Button) findViewById(R.id.ws_conn_minus);
        button_ws_conn_plus = (Button) findViewById(R.id.ws_conn_plus);
        checkbox_global = (CheckBox) findViewById(R.id.global);
        checkbox_disable_ech = (CheckBox) findViewById(R.id.disable_ech);
        checkbox_insecure = (CheckBox) findViewById(R.id.insecure);
        button_apps = (Button) findViewById(R.id.apps);
        button_control = (Button) findViewById(R.id.control);

        btn_add_profile.setOnClickListener(this);
        btn_save_profile.setOnClickListener(this);
        btn_rename_profile.setOnClickListener(this);
        btn_delete_profile.setOnClickListener(this);
        checkbox_global.setOnClickListener(this);
        item_profile_select.setOnClickListener(this);
        item_wss_addr.setOnClickListener(this);
        item_token.setOnClickListener(this);
        item_pref_ip.setOnClickListener(this);
        item_udp_block_ports.setOnClickListener(this);
        item_ech_dns.setOnClickListener(this);
        item_ech_domain.setOnClickListener(this);
        item_ips_pref.setOnClickListener(this);
        item_insecure.setOnClickListener(this);
        item_disable_ech.setOnClickListener(this);
        button_ws_conn_minus.setOnClickListener(this);
        button_ws_conn_plus.setOnClickListener(this);
        button_apps.setOnClickListener(this);
        button_control.setOnClickListener(this);
        
		updateUI();

        Intent intent = VpnService.prepare(MainActivity.this);
		if (intent != null)
		  startActivityForResult(intent, 0);
		else
		  onActivityResult(0, RESULT_OK, null);
	}

    private class ProfileItem {
        String id;
        String name;
        
        ProfileItem(String id, String name) {
            this.id = id;
            this.name = name;
        }
        
        @Override
        public String toString() {
            return name;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ProfileItem that = (ProfileItem) o;
            return id.equals(that.id);
        }
    }

    private List<ProfileItem> getSortedProfileItems() {
        Set<String> ids = prefs.getProfileIds();
        List<ProfileItem> items = new ArrayList<>();

        for (String id : ids) {
            String name = prefs.getProfileName(id);
            items.add(new ProfileItem(id, name));
        }

        java.util.Collections.sort(items, new java.util.Comparator<ProfileItem>() {
            @Override
            public int compare(ProfileItem a, ProfileItem b) {
                return a.name.compareToIgnoreCase(b.name);
            }
        });
        return items;
    }

    private void showProfileSelectDialog() {
        final List<ProfileItem> items = getSortedProfileItems();
        if (items.isEmpty()) return;

        String currentId = prefs.getCurrentProfileId();
        int selectedIndex = 0;
        String[] names = new String[items.size()];
        for (int i = 0; i < items.size(); i++) {
            ProfileItem it = items.get(i);
            names[i] = it.name;
            if (it.id.equals(currentId)) {
                selectedIndex = i;
            }
        }

        new AlertDialog.Builder(this)
            .setTitle("选择节点")
            .setSingleChoiceItems(names, selectedIndex, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    ProfileItem it = items.get(which);
                    if (!it.id.equals(prefs.getCurrentProfileId())) {
                        savePrefs();
                        prefs.setCurrentProfileId(it.id);
                        updateUI();
                    }
                    dialog.dismiss();
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if ((result == RESULT_OK) && prefs.getEnable()) {
            Intent intent = new Intent(this, TProxyService.class);
            startService(intent.setAction(TProxyService.ACTION_CONNECT));
        }
    }

    private void showAddProfileDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.dialog_hint_name);
        final AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_add)
            .setView(input)
            .setPositiveButton(R.string.ok, null)
            .setNegativeButton(R.string.cancel, null)
            .create();

        dialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface d) {
                Button button = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
                button.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
                        String name = input.getText().toString().trim();
                        if (name.isEmpty()) {
                            Toast.makeText(MainActivity.this, R.string.toast_name_empty, Toast.LENGTH_SHORT).show();
                            return;
                        }
                        for (String id : prefs.getProfileIds()) {
                            if (prefs.getProfileName(id).equals(name)) {
                                Toast.makeText(MainActivity.this, R.string.toast_profile_exists, Toast.LENGTH_SHORT).show();
                                return;
                            }
                        }
                        String newId = UUID.randomUUID().toString();
                        savePrefs();
                        prefs.addProfile(newId, name);
                        prefs.setCurrentProfileId(newId);
                        updateUI();
                        dialog.dismiss();
                    }
                });
            }
        });
        dialog.show();
    }

    private void showRenameProfileDialog() {
        final String currentId = prefs.getCurrentProfileId();
        final EditText input = new EditText(this);
        input.setText(prefs.getProfileName(currentId));
        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_rename)
            .setView(input)
            .setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    String name = input.getText().toString().trim();
                    if (!name.isEmpty()) {
                        for (String id : prefs.getProfileIds()) {
                            if (!id.equals(currentId) && prefs.getProfileName(id).equals(name)) {
                                Toast.makeText(MainActivity.this, R.string.toast_profile_exists, Toast.LENGTH_SHORT).show();
                                return;
                            }
                        }
                        prefs.setProfileName(currentId, name);
                        updateUI();
                    }
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    private void deleteCurrentProfile() {
        final String currentId = prefs.getCurrentProfileId();
        Set<String> ids = prefs.getProfileIds();
        if (ids.size() <= 1) {
            Toast.makeText(this, R.string.toast_cannot_delete_last, Toast.LENGTH_SHORT).show();
            return;
        }

        new AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title_delete)
            .setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    prefs.removeProfile(currentId);
                    List<ProfileItem> items = getSortedProfileItems();
                    if (items.isEmpty()) return;
                    String nextId = items.get(0).id;
                    prefs.setCurrentProfileId(nextId);
                    updateUI();
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    private interface ValueCallback {
        void onValue(String v);
    }

    private void showTextInputDialog(int titleResId, String currentValue, String hint, int inputType, final ValueCallback callback) {
        final EditText input = new EditText(this);
        input.setInputType(inputType);
        input.setSingleLine(true);
        if (currentValue != null) {
            input.setText(currentValue);
            input.setSelection(input.getText().length());
        }
        if (hint != null) {
            input.setHint(hint);
        }

        FrameLayout container = new FrameLayout(this);
        int margin = (int) (20 * getResources().getDisplayMetrics().density);
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT
        );
        params.leftMargin = margin;
        params.rightMargin = margin;
        params.topMargin = (int) (8 * getResources().getDisplayMetrics().density);
        params.bottomMargin = (int) (4 * getResources().getDisplayMetrics().density);
        container.addView(input, params);

        new AlertDialog.Builder(this)
            .setTitle(titleResId)
            .setView(container)
            .setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    if (callback != null) {
                        callback.onValue(input.getText().toString());
                    }
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    private void setValueOrPlaceholder(TextView view, String value) {
        if (view == null) return;
        if (value == null) value = "";
        String v = value.trim();
        if (v.isEmpty()) {
            view.setText("点击设置");
            view.setAlpha(0.6f);
        } else {
            view.setText(value);
            view.setAlpha(1.0f);
        }
    }

    private void showIpsPrefDialog() {
        final String[] entries = getResources().getStringArray(R.array.ips_pref_entries);
        int selected = getIpsPrefSelection(prefs.getIpsPref());
        new AlertDialog.Builder(this)
            .setTitle(R.string.ips_pref)
            .setSingleChoiceItems(entries, selected, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    prefs.setIpsPref(getIpsPrefValue(which));
                    updateUI();
                    dialog.dismiss();
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

	@Override
	public void onClick(View view) {
        if (view == checkbox_global) {
            savePrefs();
            updateUI();
        } else if (view == item_profile_select) {
            if (prefs.getEnable()) return;
            showProfileSelectDialog();
        } else if (view == item_wss_addr) {
            showTextInputDialog(R.string.wss_addr, prefs.getWssAddr(), "例如：example.com:443", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setWssAddr(v.trim());
                    updateUI();
                }
            });
        } else if (view == item_token) {
            showTextInputDialog(R.string.token, prefs.getToken(), "留空则不使用", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setToken(v);
                    updateUI();
                }
            });
        } else if (view == item_pref_ip) {
            showTextInputDialog(R.string.pref_ip, prefs.getPrefIp(), "多 IP 用逗号分隔", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setPrefIp(v);
                    updateUI();
                }
            });
        } else if (view == item_udp_block_ports) {
            showTextInputDialog(R.string.udp_block_ports, prefs.getUdpBlockPorts(), "留空则不禁用任何端口", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setUdpBlockPorts(v.trim());
                    updateUI();
                }
            });
        } else if (view == item_ech_dns) {
            showTextInputDialog(R.string.ech_dns, prefs.getEchDns(), "例如：https://doh.pub/dns-query", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setEchDns(v.trim());
                    updateUI();
                }
            });
        } else if (view == item_ech_domain) {
            showTextInputDialog(R.string.ech_domain, prefs.getEchDomain(), "例如：cloudflare-ech.com", InputType.TYPE_CLASS_TEXT, new ValueCallback() {
                @Override
                public void onValue(String v) {
                    prefs.setEchDomain(v.trim());
                    updateUI();
                }
            });
        } else if (view == item_ips_pref) {
            showIpsPrefDialog();
        } else if (view == item_insecure) {
            if (prefs.getEnable()) return;
            boolean checked = !checkbox_insecure.isChecked();
            prefs.setInsecure(checked);
            if (checked) {
                prefs.setDisableEch(true);
            }
            updateUI();
        } else if (view == item_disable_ech) {
            if (prefs.getEnable()) return;
            if (prefs.getInsecure()) {
                return;
            }
            prefs.setDisableEch(!checkbox_disable_ech.isChecked());
            updateUI();
        } else if (view == button_ws_conn_minus) {
            if (prefs.getEnable()) return;
            int v = prefs.getWsConn();
            if (v > 2) {
                prefs.setWsConn(v - 1);
                updateUI();
            }
        } else if (view == button_ws_conn_plus) {
            if (prefs.getEnable()) return;
            int v = prefs.getWsConn();
            if (v < 10) {
                prefs.setWsConn(v + 1);
                updateUI();
            }
        } else if (view == button_apps) {
            startActivity(new Intent(this, AppListActivity.class));
        } else if (view == btn_add_profile) {
            showAddProfileDialog();
        } else if (view == btn_save_profile) {
            String wssAddr = prefs.getWssAddr().trim();
            if (wssAddr.isEmpty()) {
                Toast.makeText(this, "服务器地址不能为空", Toast.LENGTH_SHORT).show();
                return;
            }
            savePrefs();
            Toast.makeText(this, R.string.toast_saved, Toast.LENGTH_SHORT).show();
        } else if (view == btn_rename_profile) {
            showRenameProfileDialog();
        } else if (view == btn_delete_profile) {
            deleteCurrentProfile();
        } else if (view == button_control) {
            boolean isEnable = prefs.getEnable();
            if (isEnable) {
                prefs.setEnable(false);
                updateUI();
                startService(new Intent(this, TProxyService.class).setAction(TProxyService.ACTION_DISCONNECT));
            } else {
                String wssAddr = prefs.getWssAddr().trim();
                if (wssAddr.isEmpty()) {
                    Toast.makeText(this, "服务器地址不能为空", Toast.LENGTH_SHORT).show();
                    return;
                }
                savePrefs();
                prefs.setEnable(true);
                updateUI();
                startService(new Intent(this, TProxyService.class).setAction(TProxyService.ACTION_CONNECT));
            }
        }
	}

	private void updateUI() {
        value_profile.setText(prefs.getProfileName(prefs.getCurrentProfileId()));
        setValueOrPlaceholder(value_wss_addr, prefs.getWssAddr());
        setValueOrPlaceholder(value_token, prefs.getToken());
        setValueOrPlaceholder(value_pref_ip, prefs.getPrefIp());
        setValueOrPlaceholder(value_udp_block_ports, prefs.getUdpBlockPorts());
        setValueOrPlaceholder(value_ech_dns, prefs.getEchDns());
        setValueOrPlaceholder(value_ech_domain, prefs.getEchDomain());
        value_ws_conn.setText(Integer.toString(prefs.getWsConn()));
        String[] entries = getResources().getStringArray(R.array.ips_pref_entries);
        int sel = getIpsPrefSelection(prefs.getIpsPref());
        if (sel < 0 || sel >= entries.length) sel = 0;
        value_ips_pref.setText(entries[sel]);
        value_ips_pref.setAlpha(1.0f);
		checkbox_global.setChecked(prefs.getGlobal());
        checkbox_insecure.setChecked(prefs.getInsecure());
        checkbox_disable_ech.setChecked(prefs.getInsecure() ? true : prefs.getDisableEch());

        boolean editable = !prefs.getEnable();
        item_profile_select.setEnabled(editable);
        item_profile_select.setAlpha(editable ? 1.0f : 0.5f);
        item_wss_addr.setEnabled(editable);
        item_token.setEnabled(editable);
        item_pref_ip.setEnabled(editable);
        item_udp_block_ports.setEnabled(editable);
        item_ech_dns.setEnabled(editable);
        item_ech_domain.setEnabled(editable);
        item_ips_pref.setEnabled(editable);
        item_ws_conn.setEnabled(editable);
        int wsConn = prefs.getWsConn();
        if (wsConn < 2) wsConn = 2;
        if (wsConn > 10) wsConn = 10;
        if (wsConn != prefs.getWsConn()) {
            prefs.setWsConn(wsConn);
            value_ws_conn.setText(Integer.toString(wsConn));
        }
        button_ws_conn_minus.setEnabled(editable && wsConn > 2);
        button_ws_conn_plus.setEnabled(editable && wsConn < 10);
        checkbox_global.setEnabled(editable);
        item_insecure.setEnabled(editable);
        checkbox_insecure.setEnabled(editable);
        item_disable_ech.setEnabled(editable && !prefs.getInsecure());
        checkbox_disable_ech.setEnabled(editable && !prefs.getInsecure());
        
        boolean globalChecked = checkbox_global.isChecked();
        button_apps.setEnabled(editable && !globalChecked);
        if (button_apps.isEnabled()) {
             button_apps.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF9C27B0));
        } else {
             button_apps.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFBDBDBD));
        }
        
        btn_add_profile.setEnabled(editable);
        btn_save_profile.setEnabled(editable);
        btn_rename_profile.setEnabled(editable);
        btn_delete_profile.setEnabled(editable);

        int grey = 0xFFBDBDBD;
        btn_add_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFF4CAF50 : grey));
        btn_save_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFF2196F3 : grey));
        btn_rename_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFFFF9800 : grey));
        btn_delete_profile.setBackgroundTintList(android.content.res.ColorStateList.valueOf(editable ? 0xFFF44336 : grey));

        if (editable) {
          button_control.setText(R.string.control_enable);
          button_control.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF4CAF50));
        } else {
          button_control.setText(R.string.control_disable);
          button_control.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFF44336));
        }
	}

    private int getIpsPrefSelection(String v) {
        if (v == null || v.isEmpty()) return 0;
        String vv = v.replace(" ", "");
        if (vv.equals("4,6")) return 1;
        if (vv.equals("6,4")) return 2;
        if (vv.equals("4")) return 3;
        if (vv.equals("6")) return 4;
        return 0;
    }

    private String getIpsPrefValue(int selection) {
        switch (selection) {
            case 1: return "4,6";
            case 2: return "6,4";
            case 3: return "4";
            case 4: return "6";
            default: return "";
        }
    }

	private void savePrefs() {
		prefs.setGlobal(checkbox_global.isChecked());
        prefs.setInsecure(checkbox_insecure.isChecked());
        if (checkbox_insecure.isChecked()) {
            prefs.setDisableEch(true);
        } else {
            prefs.setDisableEch(checkbox_disable_ech.isChecked());
        }
        prefs.setUdpInTcp(false);
        prefs.setRemoteDns(true);
    }
}
