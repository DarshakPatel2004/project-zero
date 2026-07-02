"""Tests for Step 15: Reflective Permission-Behavior Correlation."""

import pytest
from analysis.step15_reflective_permission_correlation import (
    correlate_reflective_permission_usage,
    classify_permission_category,
    PERMISSION_API_MAP,
    PERMISSION_CATEGORIES,
)


class TestClassifyPermissionCategory:
    def test_sms(self):
        assert classify_permission_category("android.permission.SEND_SMS") == "sms"

    def test_network(self):
        assert classify_permission_category("android.permission.INTERNET") == "network"

    def test_unknown(self):
        assert classify_permission_category("android.permission.UNKNOWN_THING") == "other"

    def test_storage(self):
        assert (
            classify_permission_category("android.permission.READ_EXTERNAL_STORAGE")
            == "storage"
        )

    def test_location(self):
        assert (
            classify_permission_category("android.permission.ACCESS_FINE_LOCATION")
            == "location"
        )


class TestCorrelateReflectivePermissionUsage:
    def test_empty_permissions_and_calls(self):
        result = correlate_reflective_permission_usage([], [])
        assert result["total_permissions"] == 0
        assert result["total_used_reflectively"] == 0
        assert result["total_unused_reflectively"] == 0
        assert result["usage_ratio"] == 0.0
        assert result["used_permissions"] == []
        assert result["unused_permissions"] == []
        assert result["category_breakdown"] == {}

    def test_with_matching_data(self):
        permissions = [
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
        ]
        reflective_calls = [
            {"resolved_class": "android.telephony.SmsManager", "sensitive": True},
            {"resolved_class": "java.net.URL", "sensitive": False},
            {"resolved_class": "android.hardware.Camera", "sensitive": True},
        ]
        result = correlate_reflective_permission_usage(permissions, reflective_calls)

        assert result["total_permissions"] == 4
        assert result["total_used_reflectively"] == 3
        assert result["total_unused_reflectively"] == 1

        used_perms = {p["permission"]: p for p in result["used_permissions"]}
        assert used_perms["android.permission.SEND_SMS"]["used_reflectively"] is True
        assert used_perms["android.permission.INTERNET"]["used_reflectively"] is True
        assert used_perms["android.permission.CAMERA"]["used_reflectively"] is True
        assert used_perms["android.permission.READ_CONTACTS"]["used_reflectively"] is False

        assert "android.permission.READ_CONTACTS" in result["unused_permissions"]

    def test_no_match(self):
        permissions = ["android.permission.CAMERA"]
        reflective_calls = [
            {"resolved_class": "java.net.URL", "sensitive": False},
        ]
        result = correlate_reflective_permission_usage(permissions, reflective_calls)
        assert result["total_used_reflectively"] == 0
        assert result["total_unused_reflectively"] == 1
        assert result["usage_ratio"] == 0.0

    def test_all_match(self):
        permissions = [
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
        ]
        reflective_calls = [
            {"resolved_class": "android.telephony.SmsManager", "sensitive": True},
            {"resolved_class": "java.net.URL", "sensitive": False},
            {"resolved_class": "java.net.Socket", "sensitive": False},
        ]
        result = correlate_reflective_permission_usage(permissions, reflective_calls)
        assert result["total_used_reflectively"] == 2
        assert result["total_unused_reflectively"] == 0
        assert result["usage_ratio"] == 1.0

    def test_category_breakdown(self):
        permissions = [
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
        ]
        reflective_calls = [
            {"resolved_class": "android.telephony.SmsManager", "sensitive": True},
        ]
        result = correlate_reflective_permission_usage(permissions, reflective_calls)

        assert "sms" in result["category_breakdown"]
        assert "network" in result["category_breakdown"]
        assert result["category_breakdown"]["sms"]["total"] == 1
        assert result["category_breakdown"]["sms"]["used_reflectively"] == 1
        assert result["category_breakdown"]["sms"]["ratio"] == 1.0
        assert result["category_breakdown"]["network"]["total"] == 1
        assert result["category_breakdown"]["network"]["used_reflectively"] == 0
        assert result["category_breakdown"]["network"]["ratio"] == 0.0


class TestUsageRatioNotRenamed:
    def test_usage_ratio_key_present(self):
        result = correlate_reflective_permission_usage(
            ["android.permission.INTERNET"], []
        )
        assert "usage_ratio" in result
        assert "reflective_usage_ratio" not in result

    def test_used_reflectively_not_used(self):
        result = correlate_reflective_permission_usage(
            ["android.permission.SEND_SMS"],
            [{"resolved_class": "android.telephony.SmsManager", "sensitive": True}],
        )
        perm_entry = result["used_permissions"][0]
        assert "used_reflectively" in perm_entry
        assert "used" not in perm_entry


class TestConstants:
    def test_permission_api_map_not_empty(self):
        assert len(PERMISSION_API_MAP) > 0

    def test_permission_categories_not_empty(self):
        assert len(PERMISSION_CATEGORIES) > 0
