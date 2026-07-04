"""Unit tests for Step 12 reflective tracing."""

import json
import pytest
from analysis.step12_reflective_tracing import (
    find_reflective_calls,
    SENSITIVE_API_CLASSES,
    CLASS_FOR_NAME,
    METHOD_INVOKE,
    DECLARED_METHOD,
)


def test_sensitive_api_map_defined():
    assert len(SENSITIVE_API_CLASSES) > 0


def test_find_reflective_calls_empty():
    result = find_reflective_calls({})
    assert result["total_reflective_calls"] == 0
    assert result["total_sensitive"] == 0
    assert result["reflective_calls"] == []
    assert result["risk_categories"] == {}


def test_find_reflective_calls_with_data(tmp_path):
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    smali_file = smali_dir / "MainActivity.smali"

    smali_content = """
.class public Lcom/example/MainActivity;
.super Landroid/app/Activity;

.method private dynamicLoad()V
    .registers 3
    const-string v0, "android.telephony.SmsManager"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    const-string v0, "android.telephony.TelephonyManager"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    const-string v1, "sendTextMessage"
    invoke-virtual {v0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
.end method
"""
    smali_file.write_text(smali_content)

    extraction = {"extracted_path": str(tmp_path)}
    result = find_reflective_calls(extraction)

    assert result["total_reflective_calls"] > 0
    assert result["total_sensitive"] > 0


def test_find_reflective_calls_non_sensitive(tmp_path):
    smali_dir = tmp_path / "sources" / "test"
    smali_dir.mkdir(parents=True)
    smali_file = smali_dir / "Test.smali"

    smali_content = """
.class LTest;
.method foo()V
    const-string v0, "java.util.ArrayList"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
.end method
"""
    smali_file.write_text(smali_content)

    extraction = {"extracted_path": str(tmp_path)}
    result = find_reflective_calls(extraction)

    assert result["total_reflective_calls"] == 1
    assert result["total_sensitive"] == 0
    assert len(result["reflective_calls"]) == 1
    assert result["reflective_calls"][0]["sensitive"] is False


def test_find_reflective_calls_jadx_dir(tmp_path):
    jadx_dir = tmp_path / "jadx_output" / "sources"
    jadx_dir.mkdir(parents=True)
    smali_file = jadx_dir / "Malware.smali"

    smali_content = """
.class LMalware;
.method start()V
    const-string v0, "android.location.LocationManager"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    const-string v1, "getLastKnownLocation"
    invoke-virtual {v0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
.end method
"""
    smali_file.write_text(smali_content)

    extraction = {"extracted_path": str(tmp_path)}
    result = find_reflective_calls(extraction)

    assert result["total_reflective_calls"] == 2
    assert result["total_sensitive"] == 1
    assert "location" in result["risk_categories"]
    assert result["risk_categories"]["location"] >= 1


def test_method_invoke_pattern():
    assert CLASS_FOR_NAME.search('invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;')
    assert METHOD_INVOKE.search('invoke-virtual {v0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;')
    assert DECLARED_METHOD.search('invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;')
    assert DECLARED_METHOD.search('invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;')
    assert DECLARED_METHOD.search('invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;')
    assert not CLASS_FOR_NAME.search('invoke-virtual {v0}, Ljava/lang/String;->length()I')
    assert not METHOD_INVOKE.search('const-string v0, "invoke"')
