"""Step 15: Reflective Permission-Behavior Correlation.

Maps declared Android permissions to reflectively-invoked API classes
to determine which permissions are actually exercised via reflection.
"""

from typing import Dict, List, Any

PERMISSION_CATEGORIES: Dict[str, frozenset] = {
    "sms": frozenset({
        "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS",
        "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    }),
    "network": frozenset({
        "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
        "CHANGE_WIFI_STATE", "CHANGE_NETWORK_STATE",
        "ACCESS_WIFI_STATE", "CHANGE_WIFI_MULTICAST_STATE",
    }),
    "storage": frozenset({
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
        "ACCESS_MEDIA_LOCATION", "MANAGE_EXTERNAL_STORAGE",
    }),
    "location": frozenset({
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
    }),
    "camera": frozenset({"CAMERA"}),
    "contacts": frozenset({
        "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    }),
    "phone": frozenset({
        "READ_PHONE_STATE", "READ_PRECISE_PHONE_STATE",
        "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
        "ANSWER_PHONE_CALLS",
    }),
    "calendar": frozenset({"READ_CALENDAR", "WRITE_CALENDAR"}),
    "audio": frozenset({"RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT"}),
    "sensors": frozenset({
        "BODY_SENSORS", "ACTIVITY_RECOGNITION",
        "ACCESS_SENSOR", "ACCESS_SENSOR",
    }),
    "bluetooth": frozenset({
        "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_SCAN",
        "BLUETOOTH_ADVERTISE", "BLUETOOTH_CONNECT",
    }),
    "microphone": frozenset({"RECORD_AUDIO"}),
}

PERMISSION_API_MAP: Dict[str, List[str]] = {
    "android.permission.SEND_SMS": ["SmsManager"],
    "android.permission.RECEIVE_SMS": ["SmsManager", "SmsMessage", "SmsBroadcastReceiver"],
    "android.permission.READ_SMS": ["SmsManager", "SmsMessage"],
    "android.permission.WRITE_SMS": ["SmsManager"],
    "android.permission.INTERNET": [
        "URL", "HttpURLConnection", "HttpsURLConnection",
        "Socket", "ServerSocket", "DatagramSocket",
        "InetAddress", "NetworkInterface",
    ],
    "android.permission.ACCESS_NETWORK_STATE": [
        "ConnectivityManager", "NetworkInfo", "Network",
    ],
    "android.permission.ACCESS_WIFI_STATE": ["WifiManager", "WifiInfo"],
    "android.permission.CHANGE_WIFI_STATE": ["WifiManager"],
    "android.permission.CAMERA": ["Camera"],
    "android.permission.READ_CONTACTS": ["ContactsContract", "ContentResolver", "Cursor"],
    "android.permission.WRITE_CONTACTS": ["ContactsContract", "ContentResolver"],
    "android.permission.READ_EXTERNAL_STORAGE": ["File", "FileInputStream", "FileOutputStream"],
    "android.permission.WRITE_EXTERNAL_STORAGE": ["File", "FileOutputStream"],
    "android.permission.ACCESS_FINE_LOCATION": [
        "LocationManager", "Location", "GpsStatus",
        "FusedLocationProviderClient",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        "LocationManager", "Location",
    ],
    "android.permission.ACCESS_BACKGROUND_LOCATION": [
        "LocationManager", "FusedLocationProviderClient",
    ],
    "android.permission.READ_PHONE_STATE": [
        "TelephonyManager", "PhoneStateListener",
    ],
    "android.permission.CALL_PHONE": [
        "TelephonyManager", "PhoneUtils",
    ],
    "android.permission.RECORD_AUDIO": [
        "MediaRecorder", "AudioRecord",
    ],
    "android.permission.BLUETOOTH": [
        "BluetoothAdapter", "BluetoothDevice", "BluetoothSocket",
    ],
    "android.permission.BLUETOOTH_ADMIN": [
        "BluetoothAdapter",
    ],
    "android.permission.READ_CALENDAR": [
        "CalendarContract", "ContentResolver",
    ],
    "android.permission.WRITE_CALENDAR": [
        "CalendarContract", "ContentResolver",
    ],
    "android.permission.BODY_SENSORS": [
        "SensorManager", "Sensor", "SensorEventListener",
    ],
    "android.permission.GET_ACCOUNTS": [
        "AccountManager", "Account",
    ],
    "android.permission.USE_SIP": [
        "SipManager", "SipProfile", "SipSession",
    ],
    "android.permission.PROCESS_OUTGOING_CALLS": [
        "PhoneStateListener",
    ],
    "android.permission.ACTIVITY_RECOGNITION": [
        "ActivityRecognitionClient",
    ],
    "android.permission.MANAGE_EXTERNAL_STORAGE": [
        "File", "Environment",
    ],
}


def classify_permission_category(perm_string: str) -> str:
    """Classify a permission string into a category based on its suffix."""
    suffix = perm_string.rsplit(".", 1)[-1]
    for category, suffixes in PERMISSION_CATEGORIES.items():
        if suffix in suffixes:
            return category
    return "other"


def _is_permission_used_reflectively(
    permission: str,
    api_map: Dict[str, List[str]],
    resolved_classes: List[str],
) -> bool:
    """Check if a permission's associated API classes appear in resolved classes."""
    apis = api_map.get(permission, [])
    if not apis:
        return False
    for resolved in resolved_classes:
        for api_class in apis:
            if resolved.endswith(api_class):
                return True
    return False


def correlate_reflective_permission_usage(
    permissions_list: List[str],
    reflective_calls_list: List[dict],
) -> Dict[str, Any]:
    """Correlate declared permissions with reflectively-invoked API classes.

    Args:
        permissions_list: List of permission strings
            (e.g. "android.permission.INTERNET").
        reflective_calls_list: List of dicts, each with at least a
            "resolved_class" key.

    Returns:
        Dict with correlation statistics and per-permission usage.
    """
    resolved_classes = [
        call["resolved_class"]
        for call in reflective_calls_list
        if "resolved_class" in call
    ]

    if not permissions_list:
        return {
            "total_permissions": 0,
            "total_used_reflectively": 0,
            "total_unused_reflectively": 0,
            "usage_ratio": 0.0,
            "used_permissions": [],
            "unused_permissions": [],
            "category_breakdown": {},
        }

    used_permissions = []
    unused_permissions = []
    used_count = 0

    for perm in permissions_list:
        used = _is_permission_used_reflectively(
            perm, PERMISSION_API_MAP, resolved_classes,
        )
        used_permissions.append({
            "permission": perm,
            "used_reflectively": used,
        })
        if used:
            used_count += 1
        else:
            unused_permissions.append(perm)

    total = len(permissions_list)
    usage_ratio = used_count / total if total > 0 else 0.0

    category_breakdown = {}
    for perm in permissions_list:
        cat = classify_permission_category(perm)
        if cat not in category_breakdown:
            category_breakdown[cat] = {"total": 0, "used_reflectively": 0, "ratio": 0.0}
        category_breakdown[cat]["total"] += 1

    for perm in permissions_list:
        used = _is_permission_used_reflectively(
            perm, PERMISSION_API_MAP, resolved_classes,
        )
        cat = classify_permission_category(perm)
        if used:
            category_breakdown[cat]["used_reflectively"] += 1

    for cat in category_breakdown:
        total_cat = category_breakdown[cat]["total"]
        used_cat = category_breakdown[cat]["used_reflectively"]
        category_breakdown[cat]["ratio"] = used_cat / total_cat if total_cat > 0 else 0.0

    return {
        "total_permissions": total,
        "total_used_reflectively": used_count,
        "total_unused_reflectively": total - used_count,
        "usage_ratio": usage_ratio,
        "used_permissions": used_permissions,
        "unused_permissions": unused_permissions,
        "category_breakdown": category_breakdown,
    }
