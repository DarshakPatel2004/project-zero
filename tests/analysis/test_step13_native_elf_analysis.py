"""Unit tests for Step 13 native ELF analysis."""

from analysis.step13_native_elf_analysis import (
    extract_elf_files,
    parse_elf_header,
    detect_elf_obfuscation,
    analyze_native_libraries_from_apk,
)


def test_extract_elf_files_no_apk():
    result = extract_elf_files("nonexistent.apk")
    assert result["native_libs"] == []


def test_detect_elf_obfuscation():
    sections = {
        ".text": {"size": 500000, "entropy": 7.8},
        ".data.rel.ro": {"size": 20000, "entropy": 4.2},
    }
    result = detect_elf_obfuscation(sections)
    assert result["obfuscation_score"] > 0
    assert len(result["indicators"]) > 0


def test_detect_elf_obfuscation_clean():
    sections = {
        ".text": {"size": 50000, "entropy": 5.2},
    }
    result = detect_elf_obfuscation(sections)
    assert result["obfuscation_score"] == 0.0


def test_parse_elf_header_no_elf():
    result = parse_elf_header({})
    assert result == {}
