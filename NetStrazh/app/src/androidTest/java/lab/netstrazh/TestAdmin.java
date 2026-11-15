package lab.netstrazh;

import android.app.admin.DeviceAdminReceiver;

/**
 * Lets the test APK be made the device owner of the emulator (the test does that with "dpm"), so it
 * can switch Android's always-on VPN and "block connections without VPN" on and off: only the
 * Settings app and a device owner may. See {@link OtherAppProxy}.
 */
public class TestAdmin extends DeviceAdminReceiver {
}
