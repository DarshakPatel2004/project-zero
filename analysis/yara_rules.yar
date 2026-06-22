/*
 * DroidForensix - YARA Detection Rules
 * Generated from Android malware analysis pipeline results
 * 
 * Date: 2026-06-16
 * Samples analyzed: 156
 * Encodings found: 5149
 * Payloads decoded: 5148
 * C2 indicators: 1117
 *
 * These rules detect patterns found in analyzed APK samples
 * including XOR-encoded strings, base64-encoded payloads,
 * decoded payload magic bytes, and C2 infrastructure patterns.
 */


rule XOR_Key_1_multi_family {
    meta:
        description = "XOR key 1 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "906"
        family = "multi-family"
        xor_key = "1"
        confidence = "high"

    strings:
        $xor_0 = { e9 9c 80 e8 a6 81 e5 b0 86 e4 bd a0 e7 9a 84 41 }
        $xor_1 = { 64 65 6c 65 67 61 74 65 2e 72 61 77 51 75 65 72 }
        $xor_2 = { 3c 21 44 4f 43 54 59 50 45 20 68 74 6d 6c 3e 3c }
        $xor_3 = { 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 }
        $xor_4 = { 49 4e 53 45 52 54 20 4f 52 20 52 45 50 4c 41 43 }
        $xor_5 = { 4d 65 74 68 6f 64 20 6e 6f 74 20 64 65 63 6f 6d }
        $xor_6 = { 69 56 42 4f 52 77 30 4b 47 67 6f 41 41 41 41 4e }
        $xor_7 = { 41 64 56 69 65 77 e7 9a 84 e4 b8 80 e4 b8 aa e7 }
        $xor_8 = { e9 95 b7 e9 94 96 e1 94 8a ec 8c 9e c6 8a e0 ae }
        $xor_9 = { 4e 6f 4d 6f 72 65 44 61 74 61 20 69 73 20 6e 6f }

    condition:
        uint16(0) == 1 or any of them
}

rule XOR_Key_2_multi_family {
    meta:
        description = "XOR key 2 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "28"
        family = "multi-family"
        xor_key = "2"
        confidence = "high"

    strings:
        $xor_0 = { 6a 61 76 61 73 63 72 69 70 74 3a 66 75 6e 63 74 }
        $xor_1 = { 21 22 23 24 25 25 26 27 28 29 2a 2b 2c 2d 2e 2e }
        $xor_2 = { 7e 4d 4c 4d 4c 4b 4a 4b 4a 4b 4a 49 48 49 48 49 }
        $xor_3 = { 7e 61 60 63 62 65 64 67 66 69 68 6b 6a 6d 6c 6f }
        $xor_4 = { 7e 7c 7a 78 75 73 71 6f 6d 6b 69 67 65 63 61 5f }
        $xor_5 = { 21 22 23 24 25 26 26 27 28 29 2a 2b 2c 2d 2e 2f }
        $xor_6 = { e5 86 85 e5 ad 98 e5 8d a0 e7 94 a8 e5 b7 b2 e7 }
        $xor_7 = { 21 22 23 23 24 25 26 26 27 28 29 29 2a 2b 2c 2d }

    condition:
        uint16(0) == 2 or any of them
}

rule XOR_Key_3_multi_family {
    meta:
        description = "XOR key 3 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "26"
        family = "multi-family"
        xor_key = "3"
        confidence = "high"

    strings:
        $xor_0 = { 6d 48 61 77 64 31 50 74 6c 57 30 43 42 75 6b 35 }
        $xor_1 = { 21 21 23 24 28 2c 31 36 3b 43 49 4e 53 58 20 20 }
        $xor_2 = { 21 22 24 27 2a 2e 35 3b 40 49 4e 53 58 5e 20 20 }
        $xor_3 = { 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31 }
        $xor_4 = { 69 56 42 4f 52 77 30 4b 47 67 6f 41 41 41 41 4e }
        $xor_5 = { eb b3 b8 20 ec 96 b4 ed 94 8c eb a6 ac ec bc 80 }
        $xor_6 = { 3e 3d 40 3f 3a 39 3c 3b 36 35 38 37 32 31 34 33 }
        $xor_7 = { 30 33 36 35 3c 3f 3a 39 28 2b 2e 2d 24 27 22 21 }
        $xor_8 = { 21 22 24 27 2d 32 38 40 47 4d 52 58 5e 64 20 21 }
        $xor_9 = { 3c 68 74 6d 6c 3e 0a 3c 68 65 61 64 3e 0a 09 3c }

    condition:
        uint16(0) == 3 or any of them
}

rule XOR_Key_4_multi_family {
    meta:
        description = "XOR key 4 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "19"
        family = "multi-family"
        xor_key = "4"
        confidence = "high"

    strings:
        $xor_0 = { 53 4d 41 50 5c 6e 43 6c 61 73 73 52 65 66 65 72 }
        $xor_1 = { 53 4d 41 50 5c 6e 48 6f 6d 65 46 72 61 67 6d 65 }
        $xor_2 = { 53 4d 41 50 5c 6e 41 70 70 45 64 69 74 56 69 65 }
        $xor_3 = { 53 4d 41 50 5c 6e 41 70 70 53 65 6c 65 63 74 54 }
        $xor_4 = { 53 4d 41 50 5c 6e 50 6c 61 63 65 46 72 61 67 6d }
        $xor_5 = { 53 4d 41 50 5c 6e 41 64 64 54 72 69 70 44 69 61 }
        $xor_6 = { 53 4d 41 50 5c 6e 4d 61 69 6e 54 61 62 56 69 65 }
        $xor_7 = { 53 4d 41 50 5c 6e 53 74 61 74 73 46 72 61 67 6d }
        $xor_8 = { 53 4d 41 50 5c 6e 46 72 61 67 6d 65 6e 74 4e 61 }
        $xor_9 = { 53 4d 41 50 5c 6e 41 6c 65 72 74 44 69 61 6c 6f }
        $xor_10 = { 53 4d 41 50 5c 6e 41 72 72 61 79 44 65 71 75 65 }
        $xor_11 = { 53 4d 41 50 5c 6e 43 68 65 63 6b 49 6e 56 69 65 }

    condition:
        uint16(0) == 4 or any of them
}

rule XOR_Key_5_multi_family {
    meta:
        description = "XOR key 5 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "7"
        family = "multi-family"
        xor_key = "5"
        confidence = "high"

    strings:
        $xor_0 = { 69 66 28 21 77 69 6e 64 6f 77 2e 48 6f 67 61 6e }
        $xor_1 = { 6a 61 76 61 73 63 72 69 70 74 3a 28 66 75 6e 63 }
        $xor_2 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_3 = { 5b 60 7e 21 40 23 24 25 5e 26 2a 28 29 2b 3d 7c }
        $xor_4 = { 64 65 6e 73 65 28 47 72 6f 75 70 49 6e 66 6f 53 }
        $xor_5 = { 21 24 29 2a 2b 2c 2d 35 37 39 3c 3d 3f 40 41 43 }

    condition:
        uint16(0) == 5 or any of them
}

rule XOR_Key_6_unknown {
    meta:
        description = "XOR key 6 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "unknown"
        xor_key = "6"
        confidence = "high"

    strings:
        $xor_0 = { 57 52 5f 56 45 52 54 45 58 5f 53 48 41 44 45 52 }
        $xor_1 = { 4d 4f 5a 5f 52 45 4c 45 41 53 45 5f 41 53 53 45 }
        $xor_2 = { 21 24 25 26 27 28 29 2a 2d 31 32 33 35 36 38 39 }

    condition:
        uint16(0) == 6 or any of them
}

rule XOR_Key_7_unknown {
    meta:
        description = "XOR key 7 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "7"
        confidence = "high"

    strings:
        $xor_0 = { 55 6e 6b 6e 6f 77 6e 20 45 72 72 6f 72 50 61 72 }

    condition:
        uint16(0) == 7 or any of them
}

rule XOR_Key_8_unknown {
    meta:
        description = "XOR key 8 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "8"
        confidence = "high"

    strings:
        $xor_0 = { 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 }

    condition:
        uint16(0) == 8 or any of them
}

rule XOR_Key_10_unknown {
    meta:
        description = "XOR key 10 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "unknown"
        xor_key = "10"
        confidence = "high"

    strings:
        $xor_0 = { 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 }
        $xor_1 = { 21 21 63 68 61 69 6e 3b 21 21 71 75 6f 74 65 64 }
        $xor_2 = { 21 21 21 22 23 23 24 24 27 28 2a 2c 2d 30 32 35 }

    condition:
        uint16(0) == 10 or any of them
}

rule XOR_Key_11_unknown {
    meta:
        description = "XOR key 11 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "11"
        confidence = "high"

    strings:
        $xor_0 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }

    condition:
        uint16(0) == 11 or any of them
}

rule XOR_Key_12_unknown {
    meta:
        description = "XOR key 12 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "12"
        confidence = "high"

    strings:
        $xor_0 = { 21 22 24 25 26 28 29 2a 2c 2d 2e 2f 31 32 33 34 }

    condition:
        uint16(0) == 12 or any of them
}

rule XOR_Key_14_multi_family {
    meta:
        description = "XOR key 14 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "56"
        family = "multi-family"
        xor_key = "14"
        confidence = "high"

    strings:
        $xor_0 = { 43 52 45 41 54 45 20 54 41 42 4c 45 20 49 46 20 }
        $xor_1 = { 53 45 4c 45 43 54 20 27 43 52 45 41 54 45 20 54 }
        $xor_2 = { 53 45 4c 45 43 54 20 27 49 4e 53 45 52 54 20 49 }
        $xor_3 = { 53 45 4c 45 43 54 20 6c 65 76 65 6c 20 46 52 4f }
        $xor_4 = { 6f 72 69 67 69 6e 31 30 30 31 30 31 32 30 31 32 }
        $xor_5 = { 55 50 44 41 54 45 20 25 51 2e 25 73 20 53 45 54 }
        $xor_6 = { 69 56 42 4f 52 77 30 4b 47 67 6f 41 41 41 41 4e }
        $xor_7 = { 24 28 2b 2e 30 33 36 38 3a 3c 3e 40 42 44 46 48 }
        $xor_8 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 }

    condition:
        uint16(0) == 14 or any of them
}

rule XOR_Key_15_multi_family {
    meta:
        description = "XOR key 15 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        xor_key = "15"
        confidence = "high"

    strings:
        $xor_0 = { 26 27 28 29 2a 2b 2c 2d 2e 33 34 35 36 37 38 39 }
        $xor_1 = { 6c 62 74 73 67 71 35 62 76 7a 75 5c 75 30 30 37 }

    condition:
        uint16(0) == 15 or any of them
}

rule XOR_Key_16_multi_family {
    meta:
        description = "XOR key 16 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        xor_key = "16"
        confidence = "high"

    strings:
        $xor_0 = { 26 2e 2e 34 39 3d 3f 21 29 2f 2e 33 38 3c 3f 25 }
        $xor_1 = { 21 21 22 22 23 23 24 24 25 25 25 26 26 27 27 28 }
        $xor_2 = { 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f }

    condition:
        uint16(0) == 16 or any of them
}

rule XOR_Key_17_unknown {
    meta:
        description = "XOR key 17 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "17"
        confidence = "high"

    strings:
        $xor_0 = { 21 23 29 31 39 42 20 20 22 24 2a 32 39 41 20 20 }

    condition:
        uint16(0) == 17 or any of them
}

rule XOR_Key_18_unknown {
    meta:
        description = "XOR key 18 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "18"
        confidence = "high"

    strings:
        $xor_0 = { 30 39 44 20 2e 35 3f 24 2e 33 3c 28 2e 32 3a 2c }

    condition:
        uint16(0) == 18 or any of them
}

rule XOR_Key_19_unknown {
    meta:
        description = "XOR key 19 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "unknown"
        xor_key = "19"
        confidence = "high"

    strings:
        $xor_0 = { 41 45 6c 69 67 3d 35 69 3b 32 76 26 41 4d 50 3d }
        $xor_1 = { 21 21 63 68 61 69 6e 3b 21 21 71 75 6f 74 65 64 }
        $xor_2 = { 3c 73 63 72 69 70 74 3e 28 66 75 6e 63 74 69 6f }
        $xor_3 = { 23 2c 2d 30 34 3a 3d 21 25 2e 2d 2f 33 39 3d 21 }
        $xor_4 = { 23 28 2c 2e 2d 2e 30 33 34 39 3a 3c 3d 3e 21 23 }

    condition:
        uint16(0) == 19 or any of them
}

rule XOR_Key_20_unknown {
    meta:
        description = "XOR key 20 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "unknown"
        xor_key = "20"
        confidence = "high"

    strings:
        $xor_0 = { 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b }
        $xor_1 = { 3d 3d 20 63 6f 75 6e 74 20 2b 20 31 61 73 73 65 }
        $xor_2 = { 4d 4f 5a 5f 52 45 4c 45 41 53 45 5f 41 53 53 45 }
        $xor_3 = { 55 6e 6f 72 6d 55 6e 6f 72 6d 53 72 67 62 48 64 }
        $xor_4 = { 3c 77 3a 73 74 79 6c 65 73 20 78 6d 6c 6e 73 3a }

    condition:
        uint16(0) == 20 or any of them
}

rule XOR_Key_21_multi_family {
    meta:
        description = "XOR key 21 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        xor_key = "21"
        confidence = "high"

    strings:
        $xor_0 = { 5c 72 5c 6e 5c 74 5c 74 2f 2a 20 3d 3d 3d 3d 3d }
        $xor_1 = { 23 25 28 2a 2c 2f 31 33 35 37 39 3a 3c 3e 40 41 }
        $xor_2 = { 67 77 63 66 7c 6c 2a 5c 75 30 30 37 66 6d 6f 62 }

    condition:
        uint16(0) == 21 or any of them
}

rule XOR_Key_22_unknown {
    meta:
        description = "XOR key 22 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        xor_key = "22"
        confidence = "high"

    strings:
        $xor_0 = { 41 46 61 69 6c 65 64 20 74 6f 20 69 6e 69 74 69 }
        $xor_1 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_2 = { 64 61 74 61 3a 69 6d 61 67 65 2f 70 6e 67 3b 62 }

    condition:
        uint16(0) == 22 or any of them
}

rule XOR_Key_23_com_tencent_android_qqdownload {
    meta:
        description = "XOR key 23 encoded strings found in com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        xor_key = "23"
        confidence = "high"

    strings:
        $xor_0 = { 4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 }

    condition:
        uint16(0) == 23 or any of them
}

rule XOR_Key_24_multi_family {
    meta:
        description = "XOR key 24 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        xor_key = "24"
        confidence = "high"

    strings:
        $xor_0 = { 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 }
        $xor_1 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_2 = { 42 57 31 30 6d 70 31 76 43 44 56 32 64 76 20 20 }

    condition:
        uint16(0) == 24 or any of them
}

rule XOR_Key_26_multi_family {
    meta:
        description = "XOR key 26 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        xor_key = "26"
        confidence = "high"

    strings:
        $xor_0 = { 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 }
        $xor_1 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_2 = { 4c 79 38 4e 43 69 38 76 49 43 42 74 63 6d 46 70 }
        $xor_3 = { 5f 5a 4e 34 4d 4d 67 63 31 35 47 43 48 61 73 68 }

    condition:
        uint16(0) == 26 or any of them
}

rule XOR_Key_27_unknown {
    meta:
        description = "XOR key 27 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        xor_key = "27"
        confidence = "high"

    strings:
        $xor_0 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_1 = { 21 23 2c 3b 47 52 57 20 22 24 2d 3b 47 50 57 20 }

    condition:
        uint16(0) == 27 or any of them
}

rule XOR_Key_28_multi_family {
    meta:
        description = "XOR key 28 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        xor_key = "28"
        confidence = "high"

    strings:
        $xor_0 = { 28 3f 3a 28 3f 3a 5b 61 2d 7a 41 2d 5a 30 2d 39 }
        $xor_1 = { 4c 53 30 74 4c 53 31 43 52 55 64 4a 54 69 42 44 }
        $xor_2 = { 28 3f 3a 28 3f 3a 28 3f 3a 5b 61 2d 7a 41 2d 5a }

    condition:
        uint16(0) == 28 or any of them
}

rule XOR_Key_29_unknown {
    meta:
        description = "XOR key 29 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        xor_key = "29"
        confidence = "high"

    strings:
        $xor_0 = { 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 }
        $xor_1 = { 5e 76 61 38 75 62 70 48 65 77 5d 5b 5a 30 33 4d }

    condition:
        uint16(0) == 29 or any of them
}

rule XOR_Key_30_multi_family {
    meta:
        description = "XOR key 30 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "multi-family"
        xor_key = "30"
        confidence = "high"

    strings:
        $xor_0 = { 21 23 24 26 27 29 2a 2b 2d 2e 30 31 32 34 35 36 }

    condition:
        uint16(0) == 30 or any of them
}

rule XOR_Key_31_multi_family {
    meta:
        description = "XOR key 31 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "9"
        family = "multi-family"
        xor_key = "31"
        confidence = "high"

    strings:
        $xor_0 = { 53 54 41 54 55 53 3a 20 50 6c 65 61 73 65 20 73 }
        $xor_1 = { 5f 5a 4e 37 61 76 6d 70 6c 75 73 31 35 41 76 6d }
        $xor_2 = { 24 26 28 2a 2b 2d 2e 30 32 33 35 36 38 39 3a 3c }
        $xor_3 = { 5f 5a 4e 37 61 76 6d 70 6c 75 73 31 34 54 65 78 }
        $xor_4 = { 3c 21 44 4f 43 54 59 50 45 20 68 74 6d 6c 3e 5c }
        $xor_5 = { 5f 5a 4e 34 44 4a 56 55 38 44 6a 56 75 46 69 6c }
        $xor_6 = { 6c 61 79 6f 75 74 28 62 75 69 6c 74 69 6e 3d 31 }
        $xor_7 = { 5f 5a 53 74 34 62 69 6e 64 49 4d 4e 37 63 6f 63 }

    condition:
        uint16(0) == 31 or any of them
}

rule XOR_Key_34_unknown {
    meta:
        description = "XOR key 34 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "34"
        confidence = "high"

    strings:
        $xor_0 = { 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d }

    condition:
        uint16(0) == 34 or any of them
}

rule XOR_Key_35_unknown {
    meta:
        description = "XOR key 35 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "35"
        confidence = "high"

    strings:
        $xor_0 = { 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c }

    condition:
        uint16(0) == 35 or any of them
}

rule XOR_Key_79_multi_family {
    meta:
        description = "XOR key 79 encoded strings found in multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        xor_key = "79"
        confidence = "high"

    strings:
        $xor_0 = { 28 3f 3a 28 3f 3a 28 3f 3a 61 61 61 7c 61 61 72 }
        $xor_1 = { 28 3f 3a 28 3f 3a 61 61 61 7c 61 61 72 70 7c 61 }

    condition:
        uint16(0) == 79 or any of them
}

rule XOR_Key_90_unknown {
    meta:
        description = "XOR key 90 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "90"
        confidence = "high"

    strings:
        $xor_0 = { 61 73 73 65 72 74 69 6f 6e 20 66 61 69 6c 65 64 }

    condition:
        uint16(0) == 90 or any of them
}

rule XOR_Key_97_unknown {
    meta:
        description = "XOR key 97 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "97"
        confidence = "high"

    strings:
        $xor_0 = { e7 ac ac e5 85 ad e7 ab a0 0a 0a 0a 0a e2 80 9c }

    condition:
        uint16(0) == 97 or any of them
}

rule XOR_Key_111_unknown {
    meta:
        description = "XOR key 111 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "111"
        confidence = "high"

    strings:
        $xor_0 = { 31 3d 45 20 2d 37 40 24 2e 36 3d 29 2f 36 3b 2e }

    condition:
        uint16(0) == 111 or any of them
}

rule XOR_Key_113_unknown {
    meta:
        description = "XOR key 113 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "113"
        confidence = "high"

    strings:
        $xor_0 = { 43 61 75 73 65 64 20 62 79 3a 41 72 72 61 79 56 }

    condition:
        uint16(0) == 113 or any of them
}

rule XOR_Key_125_unknown {
    meta:
        description = "XOR key 125 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "125"
        confidence = "high"

    strings:
        $xor_0 = { 21 21 23 29 2c 31 20 20 21 22 24 2a 2d 31 20 20 }

    condition:
        uint16(0) == 125 or any of them
}

rule XOR_Key_167_unknown {
    meta:
        description = "XOR key 167 encoded strings found in unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        xor_key = "167"
        confidence = "high"

    strings:
        $xor_0 = { c3 8f c3 93 c3 93 c3 97 c3 94 c2 9d c2 88 c2 88 }

    condition:
        uint16(0) == 167 or any of them
}

rule Payload_Magic_00108310 {
    meta:
        description = "Decoded payload with magic bytes 00108310"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "27"
        family = "multi-family"
        magic_bytes = "00108310"
        confidence = "high"

    strings:
        $magic = { 10 83 10 }

    condition:
        $magic
}

rule Payload_Magic_00208449 {
    meta:
        description = "Decoded payload with magic bytes 00208449"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "00208449"
        confidence = "high"

    strings:
        $magic = { 20 84 49 }

    condition:
        $magic
}

rule Payload_Magic_0024c838 {
    meta:
        description = "Decoded payload with magic bytes 0024c838"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "7"
        family = "unknown"
        magic_bytes = "0024c838"
        confidence = "high"

    strings:
        $magic = { 24 c8 38 }

    condition:
        $magic
}

rule Payload_Magic_002e810c {
    meta:
        description = "Decoded payload with magic bytes 002e810c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "002e810c"
        confidence = "high"

    strings:
        $magic = { 2e 81 0c }

    condition:
        $magic
}

rule Payload_Magic_0044bed7 {
    meta:
        description = "Decoded payload with magic bytes 0044bed7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0044bed7"
        confidence = "high"

    strings:
        $magic = { 44 be d7 }

    condition:
        $magic
}

rule Payload_Magic_0044bedb {
    meta:
        description = "Decoded payload with magic bytes 0044bedb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0044bedb"
        confidence = "high"

    strings:
        $magic = { 44 be db }

    condition:
        $magic
}

rule Payload_Magic_0044bf08 {
    meta:
        description = "Decoded payload with magic bytes 0044bf08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "unknown"
        magic_bytes = "0044bf08"
        confidence = "high"

    strings:
        $magic = { 44 bf 08 }

    condition:
        $magic
}

rule Payload_Magic_00510514 {
    meta:
        description = "Decoded payload with magic bytes 00510514"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "00510514"
        confidence = "high"

    strings:
        $magic = { 51 05 14 }

    condition:
        $magic
}

rule Payload_Magic_008cda4b {
    meta:
        description = "Decoded payload with magic bytes 008cda4b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "008cda4b"
        confidence = "high"

    strings:
        $magic = { 8c da 4b }

    condition:
        $magic
}

rule Payload_Magic_00b2ce58 {
    meta:
        description = "Decoded payload with magic bytes 00b2ce58"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "00b2ce58"
        confidence = "high"

    strings:
        $magic = { b2 ce 58 }

    condition:
        $magic
}

rule Payload_Magic_01020304 {
    meta:
        description = "Decoded payload with magic bytes 01020304"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "01020304"
        confidence = "high"

    strings:
        $magic = { 01 02 03 04 }

    condition:
        $magic
}

rule Payload_Magic_01050003 {
    meta:
        description = "Decoded payload with magic bytes 01050003"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "01050003"
        confidence = "high"

    strings:
        $magic = { 01 05 00 03 }

    condition:
        $magic
}

rule Payload_Magic_012375fc {
    meta:
        description = "Decoded payload with magic bytes 012375fc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "012375fc"
        confidence = "high"

    strings:
        $magic = { 01 23 75 fc }

    condition:
        $magic
}

rule Payload_Magic_012375fd {
    meta:
        description = "Decoded payload with magic bytes 012375fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "012375fd"
        confidence = "high"

    strings:
        $magic = { 01 23 75 fd }

    condition:
        $magic
}

rule Payload_Magic_01249430 {
    meta:
        description = "Decoded payload with magic bytes 01249430"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "01249430"
        confidence = "high"

    strings:
        $magic = { 01 24 94 30 }

    condition:
        $magic
}

rule Payload_Magic_0144c739 {
    meta:
        description = "Decoded payload with magic bytes 0144c739"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0144c739"
        confidence = "high"

    strings:
        $magic = { 01 44 c7 39 }

    condition:
        $magic
}

rule Payload_Magic_019406d5 {
    meta:
        description = "Decoded payload with magic bytes 019406d5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "019406d5"
        confidence = "high"

    strings:
        $magic = { 01 94 06 d5 }

    condition:
        $magic
}

rule Payload_Magic_01c71eb2 {
    meta:
        description = "Decoded payload with magic bytes 01c71eb2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "01c71eb2"
        confidence = "high"

    strings:
        $magic = { 01 c7 1e b2 }

    condition:
        $magic
}

rule Payload_Magic_01cb62a2 {
    meta:
        description = "Decoded payload with magic bytes 01cb62a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "01cb62a2"
        confidence = "high"

    strings:
        $magic = { 01 cb 62 a2 }

    condition:
        $magic
}

rule Payload_Magic_01d52c7a {
    meta:
        description = "Decoded payload with magic bytes 01d52c7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "01d52c7a"
        confidence = "high"

    strings:
        $magic = { 01 d5 2c 7a }

    condition:
        $magic
}

rule Payload_Magic_02776ba2 {
    meta:
        description = "Decoded payload with magic bytes 02776ba2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "02776ba2"
        confidence = "high"

    strings:
        $magic = { 02 77 6b a2 }

    condition:
        $magic
}

rule Payload_Magic_02b2acec {
    meta:
        description = "Decoded payload with magic bytes 02b2acec"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "02b2acec"
        confidence = "high"

    strings:
        $magic = { 02 b2 ac ec }

    condition:
        $magic
}

rule Payload_Magic_037df9f7 {
    meta:
        description = "Decoded payload with magic bytes 037df9f7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "037df9f7"
        confidence = "high"

    strings:
        $magic = { 03 7d f9 f7 }

    condition:
        $magic
}

rule Payload_Magic_039f40ef {
    meta:
        description = "Decoded payload with magic bytes 039f40ef"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "039f40ef"
        confidence = "high"

    strings:
        $magic = { 03 9f 40 ef }

    condition:
        $magic
}

rule Payload_Magic_040060f0 {
    meta:
        description = "Decoded payload with magic bytes 040060f0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "040060f0"
        confidence = "high"

    strings:
        $magic = { 04 00 60 f0 }

    condition:
        $magic
}

rule Payload_Magic_040081ba {
    meta:
        description = "Decoded payload with magic bytes 040081ba"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "040081ba"
        confidence = "high"

    strings:
        $magic = { 04 00 81 ba }

    condition:
        $magic
}

rule Payload_Magic_04009d73 {
    meta:
        description = "Decoded payload with magic bytes 04009d73"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04009d73"
        confidence = "high"

    strings:
        $magic = { 04 00 9d 73 }

    condition:
        $magic
}

rule Payload_Magic_0400c685 {
    meta:
        description = "Decoded payload with magic bytes 0400c685"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0400c685"
        confidence = "high"

    strings:
        $magic = { 04 00 c6 85 }

    condition:
        $magic
}

rule Payload_Magic_0400d9b6 {
    meta:
        description = "Decoded payload with magic bytes 0400d9b6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0400d9b6"
        confidence = "high"

    strings:
        $magic = { 04 00 d9 b6 }

    condition:
        $magic
}

rule Payload_Magic_0400fac9 {
    meta:
        description = "Decoded payload with magic bytes 0400fac9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0400fac9"
        confidence = "high"

    strings:
        $magic = { 04 00 fa c9 }

    condition:
        $magic
}

rule Payload_Magic_04015d48 {
    meta:
        description = "Decoded payload with magic bytes 04015d48"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04015d48"
        confidence = "high"

    strings:
        $magic = { 04 01 5d 48 }

    condition:
        $magic
}

rule Payload_Magic_04017232 {
    meta:
        description = "Decoded payload with magic bytes 04017232"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04017232"
        confidence = "high"

    strings:
        $magic = { 04 01 72 32 }

    condition:
        $magic
}

rule Payload_Magic_0401a57a {
    meta:
        description = "Decoded payload with magic bytes 0401a57a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0401a57a"
        confidence = "high"

    strings:
        $magic = { 04 01 a5 7a }

    condition:
        $magic
}

rule Payload_Magic_0401f481 {
    meta:
        description = "Decoded payload with magic bytes 0401f481"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0401f481"
        confidence = "high"

    strings:
        $magic = { 04 01 f4 81 }

    condition:
        $magic
}

rule Payload_Magic_04026eb7 {
    meta:
        description = "Decoded payload with magic bytes 04026eb7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04026eb7"
        confidence = "high"

    strings:
        $magic = { 04 02 6e b7 }

    condition:
        $magic
}

rule Payload_Magic_0402fe13 {
    meta:
        description = "Decoded payload with magic bytes 0402fe13"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0402fe13"
        confidence = "high"

    strings:
        $magic = { 04 02 fe 13 }

    condition:
        $magic
}

rule Payload_Magic_04030300 {
    meta:
        description = "Decoded payload with magic bytes 04030300"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04030300"
        confidence = "high"

    strings:
        $magic = { 04 03 03 00 }

    condition:
        $magic
}

rule Payload_Magic_040356dc {
    meta:
        description = "Decoded payload with magic bytes 040356dc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "040356dc"
        confidence = "high"

    strings:
        $magic = { 04 03 56 dc }

    condition:
        $magic
}

rule Payload_Magic_04036997 {
    meta:
        description = "Decoded payload with magic bytes 04036997"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04036997"
        confidence = "high"

    strings:
        $magic = { 04 03 69 97 }

    condition:
        $magic
}

rule Payload_Magic_0403f0eb {
    meta:
        description = "Decoded payload with magic bytes 0403f0eb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0403f0eb"
        confidence = "high"

    strings:
        $magic = { 04 03 f0 eb }

    condition:
        $magic
}

rule Payload_Magic_0404880b {
    meta:
        description = "Decoded payload with magic bytes 0404880b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0404880b"
        confidence = "high"

    strings:
        $magic = { 04 04 88 0b }

    condition:
        $magic
}

rule Payload_Magic_04050321 {
    meta:
        description = "Decoded payload with magic bytes 04050321"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04050321"
        confidence = "high"

    strings:
        $magic = { 04 05 03 21 }

    condition:
        $magic
}

rule Payload_Magic_0405f939 {
    meta:
        description = "Decoded payload with magic bytes 0405f939"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0405f939"
        confidence = "high"

    strings:
        $magic = { 04 05 f9 39 }

    condition:
        $magic
}

rule Payload_Magic_04161ff7 {
    meta:
        description = "Decoded payload with magic bytes 04161ff7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04161ff7"
        confidence = "high"

    strings:
        $magic = { 04 16 1f f7 }

    condition:
        $magic
}

rule Payload_Magic_04188da8 {
    meta:
        description = "Decoded payload with magic bytes 04188da8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04188da8"
        confidence = "high"

    strings:
        $magic = { 04 18 8d a8 }

    condition:
        $magic
}

rule Payload_Magic_0429a0b6 {
    meta:
        description = "Decoded payload with magic bytes 0429a0b6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0429a0b6"
        confidence = "high"

    strings:
        $magic = { 04 29 a0 b6 }

    condition:
        $magic
}

rule Payload_Magic_042aaaaa {
    meta:
        description = "Decoded payload with magic bytes 042aaaaa"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "042aaaaa"
        confidence = "high"

    strings:
        $magic = { 04 2a aa aa }

    condition:
        $magic
}

rule Payload_Magic_043b4c38 {
    meta:
        description = "Decoded payload with magic bytes 043b4c38"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "043b4c38"
        confidence = "high"

    strings:
        $magic = { 04 3b 4c 38 }

    condition:
        $magic
}

rule Payload_Magic_043ef5df {
    meta:
        description = "Decoded payload with magic bytes 043ef5df"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "043ef5df"
        confidence = "high"

    strings:
        $magic = { 04 3e f5 df }

    condition:
        $magic
}

rule Payload_Magic_044a96b5 {
    meta:
        description = "Decoded payload with magic bytes 044a96b5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "044a96b5"
        confidence = "high"

    strings:
        $magic = { 04 4a 96 b5 }

    condition:
        $magic
}

rule Payload_Magic_0452dcb0 {
    meta:
        description = "Decoded payload with magic bytes 0452dcb0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0452dcb0"
        confidence = "high"

    strings:
        $magic = { 04 52 dc b0 }

    condition:
        $magic
}

rule Payload_Magic_046b17d1 {
    meta:
        description = "Decoded payload with magic bytes 046b17d1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "046b17d1"
        confidence = "high"

    strings:
        $magic = { 04 6b 17 d1 }

    condition:
        $magic
}

rule Payload_Magic_0479be66 {
    meta:
        description = "Decoded payload with magic bytes 0479be66"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0479be66"
        confidence = "high"

    strings:
        $magic = { 04 79 be 66 }

    condition:
        $magic
}

rule Payload_Magic_0483bf81 {
    meta:
        description = "Decoded payload with magic bytes 0483bf81"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0483bf81"
        confidence = "high"

    strings:
        $magic = { 04 83 bf 81 }

    condition:
        $magic
}

rule Payload_Magic_0483bfb1 {
    meta:
        description = "Decoded payload with magic bytes 0483bfb1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0483bfb1"
        confidence = "high"

    strings:
        $magic = { 04 83 bf b1 }

    condition:
        $magic
}

rule Payload_Magic_04a1455b {
    meta:
        description = "Decoded payload with magic bytes 04a1455b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04a1455b"
        confidence = "high"

    strings:
        $magic = { 04 a1 45 5b }

    condition:
        $magic
}

rule Payload_Magic_04aa87ca {
    meta:
        description = "Decoded payload with magic bytes 04aa87ca"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04aa87ca"
        confidence = "high"

    strings:
        $magic = { 04 aa 87 ca }

    condition:
        $magic
}

rule Payload_Magic_04b70e0c {
    meta:
        description = "Decoded payload with magic bytes 04b70e0c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04b70e0c"
        confidence = "high"

    strings:
        $magic = { 04 b7 0e 0c }

    condition:
        $magic
}

rule Payload_Magic_04db4ff1 {
    meta:
        description = "Decoded payload with magic bytes 04db4ff1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "04db4ff1"
        confidence = "high"

    strings:
        $magic = { 04 db 4f f1 }

    condition:
        $magic
}

rule Payload_Magic_072b5e06 {
    meta:
        description = "Decoded payload with magic bytes 072b5e06"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "072b5e06"
        confidence = "high"

    strings:
        $magic = { 07 2b 5e 06 }

    condition:
        $magic
}

rule Payload_Magic_07df41f7 {
    meta:
        description = "Decoded payload with magic bytes 07df41f7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "07df41f7"
        confidence = "high"

    strings:
        $magic = { 07 df 41 f7 }

    condition:
        $magic
}

rule Payload_Magic_0803c004 {
    meta:
        description = "Decoded payload with magic bytes 0803c004"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0803c004"
        confidence = "high"

    strings:
        $magic = { 08 03 c0 04 }

    condition:
        $magic
}

rule Payload_Magic_08445320 {
    meta:
        description = "Decoded payload with magic bytes 08445320"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "08445320"
        confidence = "high"

    strings:
        $magic = { 08 44 53 20 }

    condition:
        $magic
}

rule Payload_Magic_085034e3 {
    meta:
        description = "Decoded payload with magic bytes 085034e3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "085034e3"
        confidence = "high"

    strings:
        $magic = { 08 50 34 e3 }

    condition:
        $magic
}

rule Payload_Magic_08c002fc {
    meta:
        description = "Decoded payload with magic bytes 08c002fc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "08c002fc"
        confidence = "high"

    strings:
        $magic = { 08 c0 02 fc }

    condition:
        $magic
}

rule Payload_Magic_08e345fe {
    meta:
        description = "Decoded payload with magic bytes 08e345fe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "08e345fe"
        confidence = "high"

    strings:
        $magic = { 08 e3 45 fe }

    condition:
        $magic
}

rule Payload_Magic_0912ff0c {
    meta:
        description = "Decoded payload with magic bytes 0912ff0c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0912ff0c"
        confidence = "high"

    strings:
        $magic = { 09 12 ff 0c }

    condition:
        $magic
}

rule Payload_Magic_09160f4c {
    meta:
        description = "Decoded payload with magic bytes 09160f4c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "09160f4c"
        confidence = "high"

    strings:
        $magic = { 09 16 0f 4c }

    condition:
        $magic
}

rule Payload_Magic_09a99ead {
    meta:
        description = "Decoded payload with magic bytes 09a99ead"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "09a99ead"
        confidence = "high"

    strings:
        $magic = { 09 a9 9e ad }

    condition:
        $magic
}

rule Payload_Magic_0a589e9e {
    meta:
        description = "Decoded payload with magic bytes 0a589e9e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0a589e9e"
        confidence = "high"

    strings:
        $magic = { 0a 58 9e 9e }

    condition:
        $magic
}

rule Payload_Magic_0a89a6a2 {
    meta:
        description = "Decoded payload with magic bytes 0a89a6a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "0a89a6a2"
        confidence = "high"

    strings:
        $magic = { 0a 89 a6 a2 }

    condition:
        $magic
}

rule Payload_Magic_0b5f7a04 {
    meta:
        description = "Decoded payload with magic bytes 0b5f7a04"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0b5f7a04"
        confidence = "high"

    strings:
        $magic = { 0b 5f 7a 04 }

    condition:
        $magic
}

rule Payload_Magic_0b8f43df {
    meta:
        description = "Decoded payload with magic bytes 0b8f43df"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0b8f43df"
        confidence = "high"

    strings:
        $magic = { 0b 8f 43 df }

    condition:
        $magic
}

rule Payload_Magic_0b9fa5a5 {
    meta:
        description = "Decoded payload with magic bytes 0b9fa5a5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0b9fa5a5"
        confidence = "high"

    strings:
        $magic = { 0b 9f a5 a5 }

    condition:
        $magic
}

rule Payload_Magic_0c42c44c {
    meta:
        description = "Decoded payload with magic bytes 0c42c44c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "0c42c44c"
        confidence = "high"

    strings:
        $magic = { 0c 42 c4 4c }

    condition:
        $magic
}

rule Payload_Magic_0c44bf08 {
    meta:
        description = "Decoded payload with magic bytes 0c44bf08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0c44bf08"
        confidence = "high"

    strings:
        $magic = { 0c 44 bf 08 }

    condition:
        $magic
}

rule Payload_Magic_0c44bf72 {
    meta:
        description = "Decoded payload with magic bytes 0c44bf72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0c44bf72"
        confidence = "high"

    strings:
        $magic = { 0c 44 bf 72 }

    condition:
        $magic
}

rule Payload_Magic_0c44bf79 {
    meta:
        description = "Decoded payload with magic bytes 0c44bf79"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0c44bf79"
        confidence = "high"

    strings:
        $magic = { 0c 44 bf 79 }

    condition:
        $magic
}

rule Payload_Magic_0c844409 {
    meta:
        description = "Decoded payload with magic bytes 0c844409"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "0c844409"
        confidence = "high"

    strings:
        $magic = { 0c 84 44 09 }

    condition:
        $magic
}

rule Payload_Magic_0c8493fc {
    meta:
        description = "Decoded payload with magic bytes 0c8493fc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0c8493fc"
        confidence = "high"

    strings:
        $magic = { 0c 84 93 fc }

    condition:
        $magic
}

rule Payload_Magic_0cefcd39 {
    meta:
        description = "Decoded payload with magic bytes 0cefcd39"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0cefcd39"
        confidence = "high"

    strings:
        $magic = { 0c ef cd 39 }

    condition:
        $magic
}

rule Payload_Magic_0cf5625d {
    meta:
        description = "Decoded payload with magic bytes 0cf5625d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "0cf5625d"
        confidence = "high"

    strings:
        $magic = { 0c f5 62 5d }

    condition:
        $magic
}

rule Payload_Magic_0d23bf72 {
    meta:
        description = "Decoded payload with magic bytes 0d23bf72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0d23bf72"
        confidence = "high"

    strings:
        $magic = { 0d 23 bf 72 }

    condition:
        $magic
}

rule Payload_Magic_0d23bf81 {
    meta:
        description = "Decoded payload with magic bytes 0d23bf81"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0d23bf81"
        confidence = "high"

    strings:
        $magic = { 0d 23 bf 81 }

    condition:
        $magic
}

rule Payload_Magic_0d23bfb1 {
    meta:
        description = "Decoded payload with magic bytes 0d23bfb1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "0d23bfb1"
        confidence = "high"

    strings:
        $magic = { 0d 23 bf b1 }

    condition:
        $magic
}

rule Payload_Magic_0de7daba {
    meta:
        description = "Decoded payload with magic bytes 0de7daba"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0de7daba"
        confidence = "high"

    strings:
        $magic = { 0d e7 da ba }

    condition:
        $magic
}

rule Payload_Magic_0de95ac8 {
    meta:
        description = "Decoded payload with magic bytes 0de95ac8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "0de95ac8"
        confidence = "high"

    strings:
        $magic = { 0d e9 5a c8 }

    condition:
        $magic
}

rule Payload_Magic_0de9a80d {
    meta:
        description = "Decoded payload with magic bytes 0de9a80d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0de9a80d"
        confidence = "high"

    strings:
        $magic = { 0d e9 a8 0d }

    condition:
        $magic
}

rule Payload_Magic_0e2b268a {
    meta:
        description = "Decoded payload with magic bytes 0e2b268a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0e2b268a"
        confidence = "high"

    strings:
        $magic = { 0e 2b 26 8a }

    condition:
        $magic
}

rule Payload_Magic_0e2b2995 {
    meta:
        description = "Decoded payload with magic bytes 0e2b2995"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0e2b2995"
        confidence = "high"

    strings:
        $magic = { 0e 2b 29 95 }

    condition:
        $magic
}

rule Payload_Magic_0e8c2796 {
    meta:
        description = "Decoded payload with magic bytes 0e8c2796"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0e8c2796"
        confidence = "high"

    strings:
        $magic = { 0e 8c 27 96 }

    condition:
        $magic
}

rule Payload_Magic_0f4f44f3 {
    meta:
        description = "Decoded payload with magic bytes 0f4f44f3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "0f4f44f3"
        confidence = "high"

    strings:
        $magic = { 0f 4f 44 f3 }

    condition:
        $magic
}

rule Payload_Magic_104005d0 {
    meta:
        description = "Decoded payload with magic bytes 104005d0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "104005d0"
        confidence = "high"

    strings:
        $magic = { 10 40 05 d0 }

    condition:
        $magic
}

rule Payload_Magic_10d0012c {
    meta:
        description = "Decoded payload with magic bytes 10d0012c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "10d0012c"
        confidence = "high"

    strings:
        $magic = { 10 d0 01 2c }

    condition:
        $magic
}

rule Payload_Magic_10d09160 {
    meta:
        description = "Decoded payload with magic bytes 10d09160"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "10d09160"
        confidence = "high"

    strings:
        $magic = { 10 d0 91 60 }

    condition:
        $magic
}

rule Payload_Magic_11147f81 {
    meta:
        description = "Decoded payload with magic bytes 11147f81"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "11147f81"
        confidence = "high"

    strings:
        $magic = { 11 14 7f 81 }

    condition:
        $magic
}

rule Payload_Magic_11147f96 {
    meta:
        description = "Decoded payload with magic bytes 11147f96"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "11147f96"
        confidence = "high"

    strings:
        $magic = { 11 14 7f 96 }

    condition:
        $magic
}

rule Payload_Magic_11147fa5 {
    meta:
        description = "Decoded payload with magic bytes 11147fa5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "11147fa5"
        confidence = "high"

    strings:
        $magic = { 11 14 7f a5 }

    condition:
        $magic
}

rule Payload_Magic_11147fad {
    meta:
        description = "Decoded payload with magic bytes 11147fad"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "11147fad"
        confidence = "high"

    strings:
        $magic = { 11 14 7f ad }

    condition:
        $magic
}

rule Payload_Magic_11147fb1 {
    meta:
        description = "Decoded payload with magic bytes 11147fb1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "11147fb1"
        confidence = "high"

    strings:
        $magic = { 11 14 7f b1 }

    condition:
        $magic
}

rule Payload_Magic_1153ff08 {
    meta:
        description = "Decoded payload with magic bytes 1153ff08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff08"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 08 }

    condition:
        $magic
}

rule Payload_Magic_1153ff0e {
    meta:
        description = "Decoded payload with magic bytes 1153ff0e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff0e"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 0e }

    condition:
        $magic
}

rule Payload_Magic_1153ff30 {
    meta:
        description = "Decoded payload with magic bytes 1153ff30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff30"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 30 }

    condition:
        $magic
}

rule Payload_Magic_1153ff3c {
    meta:
        description = "Decoded payload with magic bytes 1153ff3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff3c"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 3c }

    condition:
        $magic
}

rule Payload_Magic_1153ff69 {
    meta:
        description = "Decoded payload with magic bytes 1153ff69"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff69"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 69 }

    condition:
        $magic
}

rule Payload_Magic_1153ff81 {
    meta:
        description = "Decoded payload with magic bytes 1153ff81"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1153ff81"
        confidence = "high"

    strings:
        $magic = { 11 53 ff 81 }

    condition:
        $magic
}

rule Payload_Magic_1174c434 {
    meta:
        description = "Decoded payload with magic bytes 1174c434"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "1174c434"
        confidence = "high"

    strings:
        $magic = { 11 74 c4 34 }

    condition:
        $magic
}

rule Payload_Magic_1174d103 {
    meta:
        description = "Decoded payload with magic bytes 1174d103"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "1174d103"
        confidence = "high"

    strings:
        $magic = { 11 74 d1 03 }

    condition:
        $magic
}

rule Payload_Magic_126a2388 {
    meta:
        description = "Decoded payload with magic bytes 126a2388"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "unknown"
        magic_bytes = "126a2388"
        confidence = "high"

    strings:
        $magic = { 12 6a 23 88 }

    condition:
        $magic
}

rule Payload_Magic_13171ea6 {
    meta:
        description = "Decoded payload with magic bytes 13171ea6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "13171ea6"
        confidence = "high"

    strings:
        $magic = { 13 17 1e a6 }

    condition:
        $magic
}

rule Payload_Magic_131b5eae {
    meta:
        description = "Decoded payload with magic bytes 131b5eae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "131b5eae"
        confidence = "high"

    strings:
        $magic = { 13 1b 5e ae }

    condition:
        $magic
}

rule Payload_Magic_138ae823 {
    meta:
        description = "Decoded payload with magic bytes 138ae823"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "138ae823"
        confidence = "high"

    strings:
        $magic = { 13 8a e8 23 }

    condition:
        $magic
}

rule Payload_Magic_142d4513 {
    meta:
        description = "Decoded payload with magic bytes 142d4513"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "142d4513"
        confidence = "high"

    strings:
        $magic = { 14 2d 45 13 }

    condition:
        $magic
}

rule Payload_Magic_14514514 {
    meta:
        description = "Decoded payload with magic bytes 14514514"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "14514514"
        confidence = "high"

    strings:
        $magic = { 14 51 45 14 }

    condition:
        $magic
}

rule Payload_Magic_14b006fc {
    meta:
        description = "Decoded payload with magic bytes 14b006fc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "14b006fc"
        confidence = "high"

    strings:
        $magic = { 14 b0 06 fc }

    condition:
        $magic
}

rule Payload_Magic_14b006fd {
    meta:
        description = "Decoded payload with magic bytes 14b006fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "14b006fd"
        confidence = "high"

    strings:
        $magic = { 14 b0 06 fd }

    condition:
        $magic
}

rule Payload_Magic_14d0b5fd {
    meta:
        description = "Decoded payload with magic bytes 14d0b5fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "14d0b5fd"
        confidence = "high"

    strings:
        $magic = { 14 d0 b5 fd }

    condition:
        $magic
}

rule Payload_Magic_15db689b {
    meta:
        description = "Decoded payload with magic bytes 15db689b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "15db689b"
        confidence = "high"

    strings:
        $magic = { 15 db 68 9b }

    condition:
        $magic
}

rule Payload_Magic_15eed339 {
    meta:
        description = "Decoded payload with magic bytes 15eed339"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "15eed339"
        confidence = "high"

    strings:
        $magic = { 15 ee d3 39 }

    condition:
        $magic
}

rule Payload_Magic_168adc78 {
    meta:
        description = "Decoded payload with magic bytes 168adc78"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "168adc78"
        confidence = "high"

    strings:
        $magic = { 16 8a dc 78 }

    condition:
        $magic
}

rule Payload_Magic_16b6a099 {
    meta:
        description = "Decoded payload with magic bytes 16b6a099"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "16b6a099"
        confidence = "high"

    strings:
        $magic = { 16 b6 a0 99 }

    condition:
        $magic
}

rule Payload_Magic_18434444 {
    meta:
        description = "Decoded payload with magic bytes 18434444"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "18434444"
        confidence = "high"

    strings:
        $magic = { 18 43 44 44 }

    condition:
        $magic
}

rule Payload_Magic_1924ff0c {
    meta:
        description = "Decoded payload with magic bytes 1924ff0c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "1924ff0c"
        confidence = "high"

    strings:
        $magic = { 19 24 ff 0c }

    condition:
        $magic
}

rule Payload_Magic_19eb457a {
    meta:
        description = "Decoded payload with magic bytes 19eb457a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "19eb457a"
        confidence = "high"

    strings:
        $magic = { 19 eb 45 7a }

    condition:
        $magic
}

rule Payload_Magic_1b0f31ed {
    meta:
        description = "Decoded payload with magic bytes 1b0f31ed"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "1b0f31ed"
        confidence = "high"

    strings:
        $magic = { 1b 0f 31 ed }

    condition:
        $magic
}

rule Payload_Magic_1da965c8 {
    meta:
        description = "Decoded payload with magic bytes 1da965c8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "1da965c8"
        confidence = "high"

    strings:
        $magic = { 1d a9 65 c8 }

    condition:
        $magic
}

rule Payload_Magic_20202020 {
    meta:
        description = "Decoded payload with magic bytes 20202020"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "20202020"
        confidence = "high"

    strings:
        $magic = { 20 20 20 20 }

    condition:
        $magic
}

rule Payload_Magic_20202022 {
    meta:
        description = "Decoded payload with magic bytes 20202022"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202022"
        confidence = "high"

    strings:
        $magic = { 20 20 20 22 }

    condition:
        $magic
}

rule Payload_Magic_20202023 {
    meta:
        description = "Decoded payload with magic bytes 20202023"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        magic_bytes = "20202023"
        confidence = "high"

    strings:
        $magic = { 20 20 20 23 }

    condition:
        $magic
}

rule Payload_Magic_20202121 {
    meta:
        description = "Decoded payload with magic bytes 20202121"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202121"
        confidence = "high"

    strings:
        $magic = { 20 20 21 21 }

    condition:
        $magic
}

rule Payload_Magic_20202220 {
    meta:
        description = "Decoded payload with magic bytes 20202220"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202220"
        confidence = "high"

    strings:
        $magic = { 20 20 22 20 }

    condition:
        $magic
}

rule Payload_Magic_20202228 {
    meta:
        description = "Decoded payload with magic bytes 20202228"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202228"
        confidence = "high"

    strings:
        $magic = { 20 20 22 28 }

    condition:
        $magic
}

rule Payload_Magic_20202322 {
    meta:
        description = "Decoded payload with magic bytes 20202322"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        magic_bytes = "20202322"
        confidence = "high"

    strings:
        $magic = { 20 20 23 22 }

    condition:
        $magic
}

rule Payload_Magic_20202323 {
    meta:
        description = "Decoded payload with magic bytes 20202323"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202323"
        confidence = "high"

    strings:
        $magic = { 20 20 23 23 }

    condition:
        $magic
}

rule Payload_Magic_20202426 {
    meta:
        description = "Decoded payload with magic bytes 20202426"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20202426"
        confidence = "high"

    strings:
        $magic = { 20 20 24 26 }

    condition:
        $magic
}

rule Payload_Magic_20206269 {
    meta:
        description = "Decoded payload with magic bytes 20206269"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20206269"
        confidence = "high"

    strings:
        $magic = { 20 20 62 69 }

    condition:
        $magic
}

rule Payload_Magic_20207074 {
    meta:
        description = "Decoded payload with magic bytes 20207074"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20207074"
        confidence = "high"

    strings:
        $magic = { 20 20 70 74 }

    condition:
        $magic
}

rule Payload_Magic_20212121 {
    meta:
        description = "Decoded payload with magic bytes 20212121"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20212121"
        confidence = "high"

    strings:
        $magic = { 20 21 21 21 }

    condition:
        $magic
}

rule Payload_Magic_20222426 {
    meta:
        description = "Decoded payload with magic bytes 20222426"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20222426"
        confidence = "high"

    strings:
        $magic = { 20 22 24 26 }

    condition:
        $magic
}

rule Payload_Magic_20222428 {
    meta:
        description = "Decoded payload with magic bytes 20222428"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20222428"
        confidence = "high"

    strings:
        $magic = { 20 22 24 28 }

    condition:
        $magic
}

rule Payload_Magic_2022242b {
    meta:
        description = "Decoded payload with magic bytes 2022242b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2022242b"
        confidence = "high"

    strings:
        $magic = { 20 22 24 2b }

    condition:
        $magic
}

rule Payload_Magic_20222524 {
    meta:
        description = "Decoded payload with magic bytes 20222524"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "20222524"
        confidence = "high"

    strings:
        $magic = { 20 22 25 24 }

    condition:
        $magic
}

rule Payload_Magic_20222529 {
    meta:
        description = "Decoded payload with magic bytes 20222529"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20222529"
        confidence = "high"

    strings:
        $magic = { 20 22 25 29 }

    condition:
        $magic
}

rule Payload_Magic_2022252b {
    meta:
        description = "Decoded payload with magic bytes 2022252b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2022252b"
        confidence = "high"

    strings:
        $magic = { 20 22 25 2b }

    condition:
        $magic
}

rule Payload_Magic_2022282a {
    meta:
        description = "Decoded payload with magic bytes 2022282a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2022282a"
        confidence = "high"

    strings:
        $magic = { 20 22 28 2a }

    condition:
        $magic
}

rule Payload_Magic_2022292b {
    meta:
        description = "Decoded payload with magic bytes 2022292b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2022292b"
        confidence = "high"

    strings:
        $magic = { 20 22 29 2b }

    condition:
        $magic
}

rule Payload_Magic_20222b30 {
    meta:
        description = "Decoded payload with magic bytes 20222b30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20222b30"
        confidence = "high"

    strings:
        $magic = { 20 22 2b 30 }

    condition:
        $magic
}

rule Payload_Magic_2022303a {
    meta:
        description = "Decoded payload with magic bytes 2022303a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2022303a"
        confidence = "high"

    strings:
        $magic = { 20 22 30 3a }

    condition:
        $magic
}

rule Payload_Magic_20232023 {
    meta:
        description = "Decoded payload with magic bytes 20232023"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232023"
        confidence = "high"

    strings:
        $magic = { 20 23 20 23 }

    condition:
        $magic
}

rule Payload_Magic_20232222 {
    meta:
        description = "Decoded payload with magic bytes 20232222"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232222"
        confidence = "high"

    strings:
        $magic = { 20 23 22 22 }

    condition:
        $magic
}

rule Payload_Magic_20232224 {
    meta:
        description = "Decoded payload with magic bytes 20232224"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "20232224"
        confidence = "high"

    strings:
        $magic = { 20 23 22 24 }

    condition:
        $magic
}

rule Payload_Magic_20232225 {
    meta:
        description = "Decoded payload with magic bytes 20232225"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "10"
        family = "multi-family"
        magic_bytes = "20232225"
        confidence = "high"

    strings:
        $magic = { 20 23 22 25 }

    condition:
        $magic
}

rule Payload_Magic_20232227 {
    meta:
        description = "Decoded payload with magic bytes 20232227"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232227"
        confidence = "high"

    strings:
        $magic = { 20 23 22 27 }

    condition:
        $magic
}

rule Payload_Magic_20232228 {
    meta:
        description = "Decoded payload with magic bytes 20232228"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232228"
        confidence = "high"

    strings:
        $magic = { 20 23 22 28 }

    condition:
        $magic
}

rule Payload_Magic_20232320 {
    meta:
        description = "Decoded payload with magic bytes 20232320"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20232320"
        confidence = "high"

    strings:
        $magic = { 20 23 23 20 }

    condition:
        $magic
}

rule Payload_Magic_20232322 {
    meta:
        description = "Decoded payload with magic bytes 20232322"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232322"
        confidence = "high"

    strings:
        $magic = { 20 23 23 22 }

    condition:
        $magic
}

rule Payload_Magic_20232323 {
    meta:
        description = "Decoded payload with magic bytes 20232323"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232323"
        confidence = "high"

    strings:
        $magic = { 20 23 23 23 }

    condition:
        $magic
}

rule Payload_Magic_20232324 {
    meta:
        description = "Decoded payload with magic bytes 20232324"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232324"
        confidence = "high"

    strings:
        $magic = { 20 23 23 24 }

    condition:
        $magic
}

rule Payload_Magic_20232325 {
    meta:
        description = "Decoded payload with magic bytes 20232325"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232325"
        confidence = "high"

    strings:
        $magic = { 20 23 23 25 }

    condition:
        $magic
}

rule Payload_Magic_20232326 {
    meta:
        description = "Decoded payload with magic bytes 20232326"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232326"
        confidence = "high"

    strings:
        $magic = { 20 23 23 26 }

    condition:
        $magic
}

rule Payload_Magic_20232426 {
    meta:
        description = "Decoded payload with magic bytes 20232426"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232426"
        confidence = "high"

    strings:
        $magic = { 20 23 24 26 }

    condition:
        $magic
}

rule Payload_Magic_20232427 {
    meta:
        description = "Decoded payload with magic bytes 20232427"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20232427"
        confidence = "high"

    strings:
        $magic = { 20 23 24 27 }

    condition:
        $magic
}

rule Payload_Magic_20232428 {
    meta:
        description = "Decoded payload with magic bytes 20232428"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232428"
        confidence = "high"

    strings:
        $magic = { 20 23 24 28 }

    condition:
        $magic
}

rule Payload_Magic_20232524 {
    meta:
        description = "Decoded payload with magic bytes 20232524"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20232524"
        confidence = "high"

    strings:
        $magic = { 20 23 25 24 }

    condition:
        $magic
}

rule Payload_Magic_20232729 {
    meta:
        description = "Decoded payload with magic bytes 20232729"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20232729"
        confidence = "high"

    strings:
        $magic = { 20 23 27 29 }

    condition:
        $magic
}

rule Payload_Magic_20232830 {
    meta:
        description = "Decoded payload with magic bytes 20232830"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20232830"
        confidence = "high"

    strings:
        $magic = { 20 23 28 30 }

    condition:
        $magic
}

rule Payload_Magic_2023303a {
    meta:
        description = "Decoded payload with magic bytes 2023303a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2023303a"
        confidence = "high"

    strings:
        $magic = { 20 23 30 3a }

    condition:
        $magic
}

rule Payload_Magic_2023494b {
    meta:
        description = "Decoded payload with magic bytes 2023494b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "2023494b"
        confidence = "high"

    strings:
        $magic = { 20 23 49 4b }

    condition:
        $magic
}

rule Payload_Magic_2024262b {
    meta:
        description = "Decoded payload with magic bytes 2024262b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2024262b"
        confidence = "high"

    strings:
        $magic = { 20 24 26 2b }

    condition:
        $magic
}

rule Payload_Magic_20242726 {
    meta:
        description = "Decoded payload with magic bytes 20242726"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20242726"
        confidence = "high"

    strings:
        $magic = { 20 24 27 26 }

    condition:
        $magic
}

rule Payload_Magic_20242b2c {
    meta:
        description = "Decoded payload with magic bytes 20242b2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20242b2c"
        confidence = "high"

    strings:
        $magic = { 20 24 2b 2c }

    condition:
        $magic
}

rule Payload_Magic_20242b30 {
    meta:
        description = "Decoded payload with magic bytes 20242b30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20242b30"
        confidence = "high"

    strings:
        $magic = { 20 24 2b 30 }

    condition:
        $magic
}

rule Payload_Magic_20242d31 {
    meta:
        description = "Decoded payload with magic bytes 20242d31"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20242d31"
        confidence = "high"

    strings:
        $magic = { 20 24 2d 31 }

    condition:
        $magic
}

rule Payload_Magic_20252426 {
    meta:
        description = "Decoded payload with magic bytes 20252426"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20252426"
        confidence = "high"

    strings:
        $magic = { 20 25 24 26 }

    condition:
        $magic
}

rule Payload_Magic_20252628 {
    meta:
        description = "Decoded payload with magic bytes 20252628"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20252628"
        confidence = "high"

    strings:
        $magic = { 20 25 26 28 }

    condition:
        $magic
}

rule Payload_Magic_20252729 {
    meta:
        description = "Decoded payload with magic bytes 20252729"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20252729"
        confidence = "high"

    strings:
        $magic = { 20 25 27 29 }

    condition:
        $magic
}

rule Payload_Magic_20252928 {
    meta:
        description = "Decoded payload with magic bytes 20252928"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20252928"
        confidence = "high"

    strings:
        $magic = { 20 25 29 28 }

    condition:
        $magic
}

rule Payload_Magic_20263031 {
    meta:
        description = "Decoded payload with magic bytes 20263031"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20263031"
        confidence = "high"

    strings:
        $magic = { 20 26 30 31 }

    condition:
        $magic
}

rule Payload_Magic_20272625 {
    meta:
        description = "Decoded payload with magic bytes 20272625"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "20272625"
        confidence = "high"

    strings:
        $magic = { 20 27 26 25 }

    condition:
        $magic
}

rule Payload_Magic_2027282f {
    meta:
        description = "Decoded payload with magic bytes 2027282f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2027282f"
        confidence = "high"

    strings:
        $magic = { 20 27 28 2f }

    condition:
        $magic
}

rule Payload_Magic_20272b2f {
    meta:
        description = "Decoded payload with magic bytes 20272b2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20272b2f"
        confidence = "high"

    strings:
        $magic = { 20 27 2b 2f }

    condition:
        $magic
}

rule Payload_Magic_2029282b {
    meta:
        description = "Decoded payload with magic bytes 2029282b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2029282b"
        confidence = "high"

    strings:
        $magic = { 20 29 28 2b }

    condition:
        $magic
}

rule Payload_Magic_202b3030 {
    meta:
        description = "Decoded payload with magic bytes 202b3030"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "202b3030"
        confidence = "high"

    strings:
        $magic = { 20 2b 30 30 }

    condition:
        $magic
}

rule Payload_Magic_205d5c21 {
    meta:
        description = "Decoded payload with magic bytes 205d5c21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "205d5c21"
        confidence = "high"

    strings:
        $magic = { 20 5d 5c 21 }

    condition:
        $magic
}

rule Payload_Magic_20d08e30 {
    meta:
        description = "Decoded payload with magic bytes 20d08e30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "20d08e30"
        confidence = "high"

    strings:
        $magic = { 20 d0 8e 30 }

    condition:
        $magic
}

rule Payload_Magic_20d4c435 {
    meta:
        description = "Decoded payload with magic bytes 20d4c435"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "20d4c435"
        confidence = "high"

    strings:
        $magic = { 20 d4 c4 35 }

    condition:
        $magic
}

rule Payload_Magic_21222022 {
    meta:
        description = "Decoded payload with magic bytes 21222022"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        magic_bytes = "21222022"
        confidence = "high"

    strings:
        $magic = { 21 22 20 22 }

    condition:
        $magic
}

rule Payload_Magic_21249420 {
    meta:
        description = "Decoded payload with magic bytes 21249420"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "21249420"
        confidence = "high"

    strings:
        $magic = { 21 24 94 20 }

    condition:
        $magic
}

rule Payload_Magic_21262425 {
    meta:
        description = "Decoded payload with magic bytes 21262425"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "21262425"
        confidence = "high"

    strings:
        $magic = { 21 26 24 25 }

    condition:
        $magic
}

rule Payload_Magic_2126252e {
    meta:
        description = "Decoded payload with magic bytes 2126252e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2126252e"
        confidence = "high"

    strings:
        $magic = { 21 26 25 2e }

    condition:
        $magic
}

rule Payload_Magic_2130326f {
    meta:
        description = "Decoded payload with magic bytes 2130326f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2130326f"
        confidence = "high"

    strings:
        $magic = { 21 30 32 6f }

    condition:
        $magic
}

rule Payload_Magic_2166756e {
    meta:
        description = "Decoded payload with magic bytes 2166756e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "2166756e"
        confidence = "high"

    strings:
        $magic = { 21 66 75 6e }

    condition:
        $magic
}

rule Payload_Magic_22212025 {
    meta:
        description = "Decoded payload with magic bytes 22212025"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22212025"
        confidence = "high"

    strings:
        $magic = { 22 21 20 25 }

    condition:
        $magic
}

rule Payload_Magic_22212625 {
    meta:
        description = "Decoded payload with magic bytes 22212625"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22212625"
        confidence = "high"

    strings:
        $magic = { 22 21 26 25 }

    condition:
        $magic
}

rule Payload_Magic_22212724 {
    meta:
        description = "Decoded payload with magic bytes 22212724"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22212724"
        confidence = "high"

    strings:
        $magic = { 22 21 27 24 }

    condition:
        $magic
}

rule Payload_Magic_22222027 {
    meta:
        description = "Decoded payload with magic bytes 22222027"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22222027"
        confidence = "high"

    strings:
        $magic = { 22 22 20 27 }

    condition:
        $magic
}

rule Payload_Magic_22222121 {
    meta:
        description = "Decoded payload with magic bytes 22222121"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22222121"
        confidence = "high"

    strings:
        $magic = { 22 22 21 21 }

    condition:
        $magic
}

rule Payload_Magic_22222221 {
    meta:
        description = "Decoded payload with magic bytes 22222221"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22222221"
        confidence = "high"

    strings:
        $magic = { 22 22 22 21 }

    condition:
        $magic
}

rule Payload_Magic_22222323 {
    meta:
        description = "Decoded payload with magic bytes 22222323"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22222323"
        confidence = "high"

    strings:
        $magic = { 22 22 23 23 }

    condition:
        $magic
}

rule Payload_Magic_22222424 {
    meta:
        description = "Decoded payload with magic bytes 22222424"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        magic_bytes = "22222424"
        confidence = "high"

    strings:
        $magic = { 22 22 24 24 }

    condition:
        $magic
}

rule Payload_Magic_22222929 {
    meta:
        description = "Decoded payload with magic bytes 22222929"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22222929"
        confidence = "high"

    strings:
        $magic = { 22 22 29 29 }

    condition:
        $magic
}

rule Payload_Magic_22242629 {
    meta:
        description = "Decoded payload with magic bytes 22242629"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22242629"
        confidence = "high"

    strings:
        $magic = { 22 24 26 29 }

    condition:
        $magic
}

rule Payload_Magic_22242726 {
    meta:
        description = "Decoded payload with magic bytes 22242726"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22242726"
        confidence = "high"

    strings:
        $magic = { 22 24 27 26 }

    condition:
        $magic
}

rule Payload_Magic_22242728 {
    meta:
        description = "Decoded payload with magic bytes 22242728"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22242728"
        confidence = "high"

    strings:
        $magic = { 22 24 27 28 }

    condition:
        $magic
}

rule Payload_Magic_2224292b {
    meta:
        description = "Decoded payload with magic bytes 2224292b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2224292b"
        confidence = "high"

    strings:
        $magic = { 22 24 29 2b }

    condition:
        $magic
}

rule Payload_Magic_22252424 {
    meta:
        description = "Decoded payload with magic bytes 22252424"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22252424"
        confidence = "high"

    strings:
        $magic = { 22 25 24 24 }

    condition:
        $magic
}

rule Payload_Magic_22252427 {
    meta:
        description = "Decoded payload with magic bytes 22252427"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "7"
        family = "unknown"
        magic_bytes = "22252427"
        confidence = "high"

    strings:
        $magic = { 22 25 24 27 }

    condition:
        $magic
}

rule Payload_Magic_22252525 {
    meta:
        description = "Decoded payload with magic bytes 22252525"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22252525"
        confidence = "high"

    strings:
        $magic = { 22 25 25 25 }

    condition:
        $magic
}

rule Payload_Magic_22252726 {
    meta:
        description = "Decoded payload with magic bytes 22252726"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22252726"
        confidence = "high"

    strings:
        $magic = { 22 25 27 26 }

    condition:
        $magic
}

rule Payload_Magic_22252728 {
    meta:
        description = "Decoded payload with magic bytes 22252728"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22252728"
        confidence = "high"

    strings:
        $magic = { 22 25 27 28 }

    condition:
        $magic
}

rule Payload_Magic_22252928 {
    meta:
        description = "Decoded payload with magic bytes 22252928"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22252928"
        confidence = "high"

    strings:
        $magic = { 22 25 29 28 }

    condition:
        $magic
}

rule Payload_Magic_2226292d {
    meta:
        description = "Decoded payload with magic bytes 2226292d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2226292d"
        confidence = "high"

    strings:
        $magic = { 22 26 29 2d }

    condition:
        $magic
}

rule Payload_Magic_22262a2e {
    meta:
        description = "Decoded payload with magic bytes 22262a2e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22262a2e"
        confidence = "high"

    strings:
        $magic = { 22 26 2a 2e }

    condition:
        $magic
}

rule Payload_Magic_22262d2f {
    meta:
        description = "Decoded payload with magic bytes 22262d2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22262d2f"
        confidence = "high"

    strings:
        $magic = { 22 26 2d 2f }

    condition:
        $magic
}

rule Payload_Magic_22272b30 {
    meta:
        description = "Decoded payload with magic bytes 22272b30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22272b30"
        confidence = "high"

    strings:
        $magic = { 22 27 2b 30 }

    condition:
        $magic
}

rule Payload_Magic_22282f2f {
    meta:
        description = "Decoded payload with magic bytes 22282f2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22282f2f"
        confidence = "high"

    strings:
        $magic = { 22 28 2f 2f }

    condition:
        $magic
}

rule Payload_Magic_22283031 {
    meta:
        description = "Decoded payload with magic bytes 22283031"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22283031"
        confidence = "high"

    strings:
        $magic = { 22 28 30 31 }

    condition:
        $magic
}

rule Payload_Magic_22283748 {
    meta:
        description = "Decoded payload with magic bytes 22283748"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22283748"
        confidence = "high"

    strings:
        $magic = { 22 28 37 48 }

    condition:
        $magic
}

rule Payload_Magic_2229282b {
    meta:
        description = "Decoded payload with magic bytes 2229282b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2229282b"
        confidence = "high"

    strings:
        $magic = { 22 29 28 2b }

    condition:
        $magic
}

rule Payload_Magic_22292a2f {
    meta:
        description = "Decoded payload with magic bytes 22292a2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22292a2f"
        confidence = "high"

    strings:
        $magic = { 22 29 2a 2f }

    condition:
        $magic
}

rule Payload_Magic_22292b2f {
    meta:
        description = "Decoded payload with magic bytes 22292b2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "22292b2f"
        confidence = "high"

    strings:
        $magic = { 22 29 2b 2f }

    condition:
        $magic
}

rule Payload_Magic_222a2f2e {
    meta:
        description = "Decoded payload with magic bytes 222a2f2e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "222a2f2e"
        confidence = "high"

    strings:
        $magic = { 22 2a 2f 2e }

    condition:
        $magic
}

rule Payload_Magic_222b2f2c {
    meta:
        description = "Decoded payload with magic bytes 222b2f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "222b2f2c"
        confidence = "high"

    strings:
        $magic = { 22 2b 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_222b5632 {
    meta:
        description = "Decoded payload with magic bytes 222b5632"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "222b5632"
        confidence = "high"

    strings:
        $magic = { 22 2b 56 32 }

    condition:
        $magic
}

rule Payload_Magic_222d3d49 {
    meta:
        description = "Decoded payload with magic bytes 222d3d49"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "222d3d49"
        confidence = "high"

    strings:
        $magic = { 22 2d 3d 49 }

    condition:
        $magic
}

rule Payload_Magic_22656467 {
    meta:
        description = "Decoded payload with magic bytes 22656467"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "22656467"
        confidence = "high"

    strings:
        $magic = { 22 65 64 67 }

    condition:
        $magic
}

rule Payload_Magic_23202021 {
    meta:
        description = "Decoded payload with magic bytes 23202021"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "23202021"
        confidence = "high"

    strings:
        $magic = { 23 20 20 21 }

    condition:
        $magic
}

rule Payload_Magic_23202121 {
    meta:
        description = "Decoded payload with magic bytes 23202121"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "23202121"
        confidence = "high"

    strings:
        $magic = { 23 20 21 21 }

    condition:
        $magic
}

rule Payload_Magic_23202126 {
    meta:
        description = "Decoded payload with magic bytes 23202126"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "7"
        family = "multi-family"
        magic_bytes = "23202126"
        confidence = "high"

    strings:
        $magic = { 23 20 21 26 }

    condition:
        $magic
}

rule Payload_Magic_23222126 {
    meta:
        description = "Decoded payload with magic bytes 23222126"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "23222126"
        confidence = "high"

    strings:
        $magic = { 23 22 21 26 }

    condition:
        $magic
}

rule Payload_Magic_23232020 {
    meta:
        description = "Decoded payload with magic bytes 23232020"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "23232020"
        confidence = "high"

    strings:
        $magic = { 23 23 20 20 }

    condition:
        $magic
}

rule Payload_Magic_23232323 {
    meta:
        description = "Decoded payload with magic bytes 23232323"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "23232323"
        confidence = "high"

    strings:
        $magic = { 23 23 23 23 }

    condition:
        $magic
}

rule Payload_Magic_232b3237 {
    meta:
        description = "Decoded payload with magic bytes 232b3237"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "232b3237"
        confidence = "high"

    strings:
        $magic = { 23 2b 32 37 }

    condition:
        $magic
}

rule Payload_Magic_233e5b50 {
    meta:
        description = "Decoded payload with magic bytes 233e5b50"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "233e5b50"
        confidence = "high"

    strings:
        $magic = { 23 3e 5b 50 }

    condition:
        $magic
}

rule Payload_Magic_23729227 {
    meta:
        description = "Decoded payload with magic bytes 23729227"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "23729227"
        confidence = "high"

    strings:
        $magic = { 23 72 92 27 }

    condition:
        $magic
}

rule Payload_Magic_24212c2f {
    meta:
        description = "Decoded payload with magic bytes 24212c2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "24212c2f"
        confidence = "high"

    strings:
        $magic = { 24 21 2c 2f }

    condition:
        $magic
}

rule Payload_Magic_24272621 {
    meta:
        description = "Decoded payload with magic bytes 24272621"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "24272621"
        confidence = "high"

    strings:
        $magic = { 24 27 26 21 }

    condition:
        $magic
}

rule Payload_Magic_24272629 {
    meta:
        description = "Decoded payload with magic bytes 24272629"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "multi-family"
        magic_bytes = "24272629"
        confidence = "high"

    strings:
        $magic = { 24 27 26 29 }

    condition:
        $magic
}

rule Payload_Magic_24292b2f {
    meta:
        description = "Decoded payload with magic bytes 24292b2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "24292b2f"
        confidence = "high"

    strings:
        $magic = { 24 29 2b 2f }

    condition:
        $magic
}

rule Payload_Magic_242a3321 {
    meta:
        description = "Decoded payload with magic bytes 242a3321"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "242a3321"
        confidence = "high"

    strings:
        $magic = { 24 2a 33 21 }

    condition:
        $magic
}

rule Payload_Magic_242d3945 {
    meta:
        description = "Decoded payload with magic bytes 242d3945"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "242d3945"
        confidence = "high"

    strings:
        $magic = { 24 2d 39 45 }

    condition:
        $magic
}

rule Payload_Magic_2432305a {
    meta:
        description = "Decoded payload with magic bytes 2432305a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "2432305a"
        confidence = "high"

    strings:
        $magic = { 24 32 30 5a }

    condition:
        $magic
}

rule Payload_Magic_2437325a {
    meta:
        description = "Decoded payload with magic bytes 2437325a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2437325a"
        confidence = "high"

    strings:
        $magic = { 24 37 32 5a }

    condition:
        $magic
}

rule Payload_Magic_2471214c {
    meta:
        description = "Decoded payload with magic bytes 2471214c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2471214c"
        confidence = "high"

    strings:
        $magic = { 24 71 21 4c }

    condition:
        $magic
}

rule Payload_Magic_24723b21 {
    meta:
        description = "Decoded payload with magic bytes 24723b21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.qingk.fdovdtvswosuscouwofotferesxrquer"
        magic_bytes = "24723b21"
        confidence = "high"

    strings:
        $magic = { 24 72 3b 21 }

    condition:
        $magic
}

rule Payload_Magic_25202324 {
    meta:
        description = "Decoded payload with magic bytes 25202324"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "25202324"
        confidence = "high"

    strings:
        $magic = { 25 20 23 24 }

    condition:
        $magic
}

rule Payload_Magic_25242726 {
    meta:
        description = "Decoded payload with magic bytes 25242726"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "25242726"
        confidence = "high"

    strings:
        $magic = { 25 24 27 26 }

    condition:
        $magic
}

rule Payload_Magic_25242929 {
    meta:
        description = "Decoded payload with magic bytes 25242929"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25242929"
        confidence = "high"

    strings:
        $magic = { 25 24 29 29 }

    condition:
        $magic
}

rule Payload_Magic_2525272d {
    meta:
        description = "Decoded payload with magic bytes 2525272d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2525272d"
        confidence = "high"

    strings:
        $magic = { 25 25 27 2d }

    condition:
        $magic
}

rule Payload_Magic_25252929 {
    meta:
        description = "Decoded payload with magic bytes 25252929"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25252929"
        confidence = "high"

    strings:
        $magic = { 25 25 29 29 }

    condition:
        $magic
}

rule Payload_Magic_25262021 {
    meta:
        description = "Decoded payload with magic bytes 25262021"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "25262021"
        confidence = "high"

    strings:
        $magic = { 25 26 20 21 }

    condition:
        $magic
}

rule Payload_Magic_25262627 {
    meta:
        description = "Decoded payload with magic bytes 25262627"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "25262627"
        confidence = "high"

    strings:
        $magic = { 25 26 26 27 }

    condition:
        $magic
}

rule Payload_Magic_2526292d {
    meta:
        description = "Decoded payload with magic bytes 2526292d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2526292d"
        confidence = "high"

    strings:
        $magic = { 25 26 29 2d }

    condition:
        $magic
}

rule Payload_Magic_25262b2c {
    meta:
        description = "Decoded payload with magic bytes 25262b2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25262b2c"
        confidence = "high"

    strings:
        $magic = { 25 26 2b 2c }

    condition:
        $magic
}

rule Payload_Magic_25262e34 {
    meta:
        description = "Decoded payload with magic bytes 25262e34"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25262e34"
        confidence = "high"

    strings:
        $magic = { 25 26 2e 34 }

    condition:
        $magic
}

rule Payload_Magic_2527262d {
    meta:
        description = "Decoded payload with magic bytes 2527262d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2527262d"
        confidence = "high"

    strings:
        $magic = { 25 27 26 2d }

    condition:
        $magic
}

rule Payload_Magic_2527292a {
    meta:
        description = "Decoded payload with magic bytes 2527292a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2527292a"
        confidence = "high"

    strings:
        $magic = { 25 27 29 2a }

    condition:
        $magic
}

rule Payload_Magic_25282f2f {
    meta:
        description = "Decoded payload with magic bytes 25282f2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25282f2f"
        confidence = "high"

    strings:
        $magic = { 25 28 2f 2f }

    condition:
        $magic
}

rule Payload_Magic_25292a2d {
    meta:
        description = "Decoded payload with magic bytes 25292a2d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25292a2d"
        confidence = "high"

    strings:
        $magic = { 25 29 2a 2d }

    condition:
        $magic
}

rule Payload_Magic_25292a2f {
    meta:
        description = "Decoded payload with magic bytes 25292a2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25292a2f"
        confidence = "high"

    strings:
        $magic = { 25 29 2a 2f }

    condition:
        $magic
}

rule Payload_Magic_25292d2f {
    meta:
        description = "Decoded payload with magic bytes 25292d2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25292d2f"
        confidence = "high"

    strings:
        $magic = { 25 29 2d 2f }

    condition:
        $magic
}

rule Payload_Magic_25292f2c {
    meta:
        description = "Decoded payload with magic bytes 25292f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25292f2c"
        confidence = "high"

    strings:
        $magic = { 25 29 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_252a2f2c {
    meta:
        description = "Decoded payload with magic bytes 252a2f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "252a2f2c"
        confidence = "high"

    strings:
        $magic = { 25 2a 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_252c3844 {
    meta:
        description = "Decoded payload with magic bytes 252c3844"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "252c3844"
        confidence = "high"

    strings:
        $magic = { 25 2c 38 44 }

    condition:
        $magic
}

rule Payload_Magic_252d313b {
    meta:
        description = "Decoded payload with magic bytes 252d313b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "252d313b"
        confidence = "high"

    strings:
        $magic = { 25 2d 31 3b }

    condition:
        $magic
}

rule Payload_Magic_252f2c30 {
    meta:
        description = "Decoded payload with magic bytes 252f2c30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "252f2c30"
        confidence = "high"

    strings:
        $magic = { 25 2f 2c 30 }

    condition:
        $magic
}

rule Payload_Magic_252f2f33 {
    meta:
        description = "Decoded payload with magic bytes 252f2f33"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "252f2f33"
        confidence = "high"

    strings:
        $magic = { 25 2f 2f 33 }

    condition:
        $magic
}

rule Payload_Magic_25304252 {
    meta:
        description = "Decoded payload with magic bytes 25304252"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "25304252"
        confidence = "high"

    strings:
        $magic = { 25 30 42 52 }

    condition:
        $magic
}

rule Payload_Magic_25344e21 {
    meta:
        description = "Decoded payload with magic bytes 25344e21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25344e21"
        confidence = "high"

    strings:
        $magic = { 25 34 4e 21 }

    condition:
        $magic
}

rule Payload_Magic_25345021 {
    meta:
        description = "Decoded payload with magic bytes 25345021"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25345021"
        confidence = "high"

    strings:
        $magic = { 25 34 50 21 }

    condition:
        $magic
}

rule Payload_Magic_253f5921 {
    meta:
        description = "Decoded payload with magic bytes 253f5921"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "253f5921"
        confidence = "high"

    strings:
        $magic = { 25 3f 59 21 }

    condition:
        $magic
}

rule Payload_Magic_25717473 {
    meta:
        description = "Decoded payload with magic bytes 25717473"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "25717473"
        confidence = "high"

    strings:
        $magic = { 25 71 74 73 }

    condition:
        $magic
}

rule Payload_Magic_26242a28 {
    meta:
        description = "Decoded payload with magic bytes 26242a28"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "26242a28"
        confidence = "high"

    strings:
        $magic = { 26 24 2a 28 }

    condition:
        $magic
}

rule Payload_Magic_26676a51 {
    meta:
        description = "Decoded payload with magic bytes 26676a51"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "26676a51"
        confidence = "high"

    strings:
        $magic = { 26 67 6a 51 }

    condition:
        $magic
}

rule Payload_Magic_27212c3b {
    meta:
        description = "Decoded payload with magic bytes 27212c3b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "27212c3b"
        confidence = "high"

    strings:
        $magic = { 27 21 2c 3b }

    condition:
        $magic
}

rule Payload_Magic_27222320 {
    meta:
        description = "Decoded payload with magic bytes 27222320"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "27222320"
        confidence = "high"

    strings:
        $magic = { 27 22 23 20 }

    condition:
        $magic
}

rule Payload_Magic_27262928 {
    meta:
        description = "Decoded payload with magic bytes 27262928"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "multi-family"
        magic_bytes = "27262928"
        confidence = "high"

    strings:
        $magic = { 27 26 29 28 }

    condition:
        $magic
}

rule Payload_Magic_27263534 {
    meta:
        description = "Decoded payload with magic bytes 27263534"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "27263534"
        confidence = "high"

    strings:
        $magic = { 27 26 35 34 }

    condition:
        $magic
}

rule Payload_Magic_272c2f26 {
    meta:
        description = "Decoded payload with magic bytes 272c2f26"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "272c2f26"
        confidence = "high"

    strings:
        $magic = { 27 2c 2f 26 }

    condition:
        $magic
}

rule Payload_Magic_272f2f35 {
    meta:
        description = "Decoded payload with magic bytes 272f2f35"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "272f2f35"
        confidence = "high"

    strings:
        $magic = { 27 2f 2f 35 }

    condition:
        $magic
}

rule Payload_Magic_276d753a {
    meta:
        description = "Decoded payload with magic bytes 276d753a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "276d753a"
        confidence = "high"

    strings:
        $magic = { 27 6d 75 3a }

    condition:
        $magic
}

rule Payload_Magic_282b2a2d {
    meta:
        description = "Decoded payload with magic bytes 282b2a2d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "282b2a2d"
        confidence = "high"

    strings:
        $magic = { 28 2b 2a 2d }

    condition:
        $magic
}

rule Payload_Magic_2834494e {
    meta:
        description = "Decoded payload with magic bytes 2834494e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2834494e"
        confidence = "high"

    strings:
        $magic = { 28 34 49 4e }

    condition:
        $magic
}

rule Payload_Magic_2845444d {
    meta:
        description = "Decoded payload with magic bytes 2845444d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2845444d"
        confidence = "high"

    strings:
        $magic = { 28 45 44 4d }

    condition:
        $magic
}

rule Payload_Magic_28463f34 {
    meta:
        description = "Decoded payload with magic bytes 28463f34"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "28463f34"
        confidence = "high"

    strings:
        $magic = { 28 46 3f 34 }

    condition:
        $magic
}

rule Payload_Magic_28463f58 {
    meta:
        description = "Decoded payload with magic bytes 28463f58"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "28463f58"
        confidence = "high"

    strings:
        $magic = { 28 46 3f 58 }

    condition:
        $magic
}

rule Payload_Magic_28632e67 {
    meta:
        description = "Decoded payload with magic bytes 28632e67"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "28632e67"
        confidence = "high"

    strings:
        $magic = { 28 63 2e 67 }

    condition:
        $magic
}

rule Payload_Magic_2921715e {
    meta:
        description = "Decoded payload with magic bytes 2921715e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2921715e"
        confidence = "high"

    strings:
        $magic = { 29 21 71 5e }

    condition:
        $magic
}

rule Payload_Magic_29282726 {
    meta:
        description = "Decoded payload with magic bytes 29282726"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "29282726"
        confidence = "high"

    strings:
        $magic = { 29 28 27 26 }

    condition:
        $magic
}

rule Payload_Magic_29282b2a {
    meta:
        description = "Decoded payload with magic bytes 29282b2a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "29282b2a"
        confidence = "high"

    strings:
        $magic = { 29 28 2b 2a }

    condition:
        $magic
}

rule Payload_Magic_29282e73 {
    meta:
        description = "Decoded payload with magic bytes 29282e73"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "29282e73"
        confidence = "high"

    strings:
        $magic = { 29 28 2e 73 }

    condition:
        $magic
}

rule Payload_Magic_29292f2f {
    meta:
        description = "Decoded payload with magic bytes 29292f2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "29292f2f"
        confidence = "high"

    strings:
        $magic = { 29 29 2f 2f }

    condition:
        $magic
}

rule Payload_Magic_29293477 {
    meta:
        description = "Decoded payload with magic bytes 29293477"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "29293477"
        confidence = "high"

    strings:
        $magic = { 29 29 34 77 }

    condition:
        $magic
}

rule Payload_Magic_292a272a {
    meta:
        description = "Decoded payload with magic bytes 292a272a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "292a272a"
        confidence = "high"

    strings:
        $magic = { 29 2a 27 2a }

    condition:
        $magic
}

rule Payload_Magic_292b2a2d {
    meta:
        description = "Decoded payload with magic bytes 292b2a2d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "292b2a2d"
        confidence = "high"

    strings:
        $magic = { 29 2b 2a 2d }

    condition:
        $magic
}

rule Payload_Magic_292b2f2c {
    meta:
        description = "Decoded payload with magic bytes 292b2f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "292b2f2c"
        confidence = "high"

    strings:
        $magic = { 29 2b 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_292f2c31 {
    meta:
        description = "Decoded payload with magic bytes 292f2c31"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "292f2c31"
        confidence = "high"

    strings:
        $magic = { 29 2f 2c 31 }

    condition:
        $magic
}

rule Payload_Magic_292f3135 {
    meta:
        description = "Decoded payload with magic bytes 292f3135"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "292f3135"
        confidence = "high"

    strings:
        $magic = { 29 2f 31 35 }

    condition:
        $magic
}

rule Payload_Magic_294d6e73 {
    meta:
        description = "Decoded payload with magic bytes 294d6e73"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "294d6e73"
        confidence = "high"

    strings:
        $magic = { 29 4d 6e 73 }

    condition:
        $magic
}

rule Payload_Magic_2968655e {
    meta:
        description = "Decoded payload with magic bytes 2968655e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2968655e"
        confidence = "high"

    strings:
        $magic = { 29 68 65 5e }

    condition:
        $magic
}

rule Payload_Magic_2a202d23 {
    meta:
        description = "Decoded payload with magic bytes 2a202d23"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "2a202d23"
        confidence = "high"

    strings:
        $magic = { 2a 20 2d 23 }

    condition:
        $magic
}

rule Payload_Magic_2a262520 {
    meta:
        description = "Decoded payload with magic bytes 2a262520"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "2a262520"
        confidence = "high"

    strings:
        $magic = { 2a 26 25 20 }

    condition:
        $magic
}

rule Payload_Magic_2a282624 {
    meta:
        description = "Decoded payload with magic bytes 2a282624"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2a282624"
        confidence = "high"

    strings:
        $magic = { 2a 28 26 24 }

    condition:
        $magic
}

rule Payload_Magic_2a29282f {
    meta:
        description = "Decoded payload with magic bytes 2a29282f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2a29282f"
        confidence = "high"

    strings:
        $magic = { 2a 29 28 2f }

    condition:
        $magic
}

rule Payload_Magic_2a2f2f2c {
    meta:
        description = "Decoded payload with magic bytes 2a2f2f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2a2f2f2c"
        confidence = "high"

    strings:
        $magic = { 2a 2f 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_2a323b3d {
    meta:
        description = "Decoded payload with magic bytes 2a323b3d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2a323b3d"
        confidence = "high"

    strings:
        $magic = { 2a 32 3b 3d }

    condition:
        $magic
}

rule Payload_Magic_2a716c76 {
    meta:
        description = "Decoded payload with magic bytes 2a716c76"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        magic_bytes = "2a716c76"
        confidence = "high"

    strings:
        $magic = { 2a 71 6c 76 }

    condition:
        $magic
}

rule Payload_Magic_2a8f2d8a {
    meta:
        description = "Decoded payload with magic bytes 2a8f2d8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2a8f2d8a"
        confidence = "high"

    strings:
        $magic = { 2a 8f 2d 8a }

    condition:
        $magic
}

rule Payload_Magic_2b214748 {
    meta:
        description = "Decoded payload with magic bytes 2b214748"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2b214748"
        confidence = "high"

    strings:
        $magic = { 2b 21 47 48 }

    condition:
        $magic
}

rule Payload_Magic_2b2b2b28 {
    meta:
        description = "Decoded payload with magic bytes 2b2b2b28"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2b2b2b28"
        confidence = "high"

    strings:
        $magic = { 2b 2b 2b 28 }

    condition:
        $magic
}

rule Payload_Magic_2b2b6962 {
    meta:
        description = "Decoded payload with magic bytes 2b2b6962"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2b2b6962"
        confidence = "high"

    strings:
        $magic = { 2b 2b 69 62 }

    condition:
        $magic
}

rule Payload_Magic_2b2e2f2e {
    meta:
        description = "Decoded payload with magic bytes 2b2e2f2e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2b2e2f2e"
        confidence = "high"

    strings:
        $magic = { 2b 2e 2f 2e }

    condition:
        $magic
}

rule Payload_Magic_2b6d5e75 {
    meta:
        description = "Decoded payload with magic bytes 2b6d5e75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2b6d5e75"
        confidence = "high"

    strings:
        $magic = { 2b 6d 5e 75 }

    condition:
        $magic
}

rule Payload_Magic_2c203620 {
    meta:
        description = "Decoded payload with magic bytes 2c203620"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2c203620"
        confidence = "high"

    strings:
        $magic = { 2c 20 36 20 }

    condition:
        $magic
}

rule Payload_Magic_2c242f24 {
    meta:
        description = "Decoded payload with magic bytes 2c242f24"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2c242f24"
        confidence = "high"

    strings:
        $magic = { 2c 24 2f 24 }

    condition:
        $magic
}

rule Payload_Magic_2c2c2c2c {
    meta:
        description = "Decoded payload with magic bytes 2c2c2c2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "2c2c2c2c"
        confidence = "high"

    strings:
        $magic = { 2c 2c 2c 2c }

    condition:
        $magic
}

rule Payload_Magic_2c2f3034 {
    meta:
        description = "Decoded payload with magic bytes 2c2f3034"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2c2f3034"
        confidence = "high"

    strings:
        $magic = { 2c 2f 30 34 }

    condition:
        $magic
}

rule Payload_Magic_2d23262e {
    meta:
        description = "Decoded payload with magic bytes 2d23262e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2d23262e"
        confidence = "high"

    strings:
        $magic = { 2d 23 26 2e }

    condition:
        $magic
}

rule Payload_Magic_2d2e2829 {
    meta:
        description = "Decoded payload with magic bytes 2d2e2829"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2d2e2829"
        confidence = "high"

    strings:
        $magic = { 2d 2e 28 29 }

    condition:
        $magic
}

rule Payload_Magic_2d303840 {
    meta:
        description = "Decoded payload with magic bytes 2d303840"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2d303840"
        confidence = "high"

    strings:
        $magic = { 2d 30 38 40 }

    condition:
        $magic
}

rule Payload_Magic_2d402123 {
    meta:
        description = "Decoded payload with magic bytes 2d402123"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "2d402123"
        confidence = "high"

    strings:
        $magic = { 2d 40 21 23 }

    condition:
        $magic
}

rule Payload_Magic_2e2a2f2c {
    meta:
        description = "Decoded payload with magic bytes 2e2a2f2c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2e2a2f2c"
        confidence = "high"

    strings:
        $magic = { 2e 2a 2f 2c }

    condition:
        $magic
}

rule Payload_Magic_2e2d2221 {
    meta:
        description = "Decoded payload with magic bytes 2e2d2221"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2e2d2221"
        confidence = "high"

    strings:
        $magic = { 2e 2d 22 21 }

    condition:
        $magic
}

rule Payload_Magic_2e2e2163 {
    meta:
        description = "Decoded payload with magic bytes 2e2e2163"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2e2e2163"
        confidence = "high"

    strings:
        $magic = { 2e 2e 21 63 }

    condition:
        $magic
}

rule Payload_Magic_2f2e2023 {
    meta:
        description = "Decoded payload with magic bytes 2f2e2023"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2f2e2023"
        confidence = "high"

    strings:
        $magic = { 2f 2e 20 23 }

    condition:
        $magic
}

rule Payload_Magic_2f2e3130 {
    meta:
        description = "Decoded payload with magic bytes 2f2e3130"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2f2e3130"
        confidence = "high"

    strings:
        $magic = { 2f 2e 31 30 }

    condition:
        $magic
}

rule Payload_Magic_2f2f0a2f {
    meta:
        description = "Decoded payload with magic bytes 2f2f0a2f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "2f2f0a2f"
        confidence = "high"

    strings:
        $magic = { 2f 2f 0a 2f }

    condition:
        $magic
}

rule Payload_Magic_2f607061 {
    meta:
        description = "Decoded payload with magic bytes 2f607061"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "2f607061"
        confidence = "high"

    strings:
        $magic = { 2f 60 70 61 }

    condition:
        $magic
}

rule Payload_Magic_301fc310 {
    meta:
        description = "Decoded payload with magic bytes 301fc310"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "301fc310"
        confidence = "high"

    strings:
        $magic = { 30 1f c3 10 }

    condition:
        $magic
}

rule Payload_Magic_30323820 {
    meta:
        description = "Decoded payload with magic bytes 30323820"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "30323820"
        confidence = "high"

    strings:
        $magic = { 30 32 38 20 }

    condition:
        $magic
}

rule Payload_Magic_30333235 {
    meta:
        description = "Decoded payload with magic bytes 30333235"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30333235"
        confidence = "high"

    strings:
        $magic = { 30 33 32 35 }

    condition:
        $magic
}

rule Payload_Magic_3038310b {
    meta:
        description = "Decoded payload with magic bytes 3038310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3038310b"
        confidence = "high"

    strings:
        $magic = { 30 38 31 0b }

    condition:
        $magic
}

rule Payload_Magic_303b3f3d {
    meta:
        description = "Decoded payload with magic bytes 303b3f3d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "303b3f3d"
        confidence = "high"

    strings:
        $magic = { 30 3b 3f 3d }

    condition:
        $magic
}

rule Payload_Magic_303e4421 {
    meta:
        description = "Decoded payload with magic bytes 303e4421"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "303e4421"
        confidence = "high"

    strings:
        $magic = { 30 3e 44 21 }

    condition:
        $magic
}

rule Payload_Magic_303f3e23 {
    meta:
        description = "Decoded payload with magic bytes 303f3e23"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "303f3e23"
        confidence = "high"

    strings:
        $magic = { 30 3f 3e 23 }

    condition:
        $magic
}

rule Payload_Magic_3040c803 {
    meta:
        description = "Decoded payload with magic bytes 3040c803"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3040c803"
        confidence = "high"

    strings:
        $magic = { 30 40 c8 03 }

    condition:
        $magic
}

rule Payload_Magic_3047310b {
    meta:
        description = "Decoded payload with magic bytes 3047310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3047310b"
        confidence = "high"

    strings:
        $magic = { 30 47 31 0b }

    condition:
        $magic
}

rule Payload_Magic_304a310b {
    meta:
        description = "Decoded payload with magic bytes 304a310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "304a310b"
        confidence = "high"

    strings:
        $magic = { 30 4a 31 0b }

    condition:
        $magic
}

rule Payload_Magic_304b310b {
    meta:
        description = "Decoded payload with magic bytes 304b310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "304b310b"
        confidence = "high"

    strings:
        $magic = { 30 4b 31 0b }

    condition:
        $magic
}

rule Payload_Magic_304d310b {
    meta:
        description = "Decoded payload with magic bytes 304d310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "304d310b"
        confidence = "high"

    strings:
        $magic = { 30 4d 31 0b }

    condition:
        $magic
}

rule Payload_Magic_304e310b {
    meta:
        description = "Decoded payload with magic bytes 304e310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "304e310b"
        confidence = "high"

    strings:
        $magic = { 30 4e 31 0b }

    condition:
        $magic
}

rule Payload_Magic_30503124 {
    meta:
        description = "Decoded payload with magic bytes 30503124"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30503124"
        confidence = "high"

    strings:
        $magic = { 30 50 31 24 }

    condition:
        $magic
}

rule Payload_Magic_3051310b {
    meta:
        description = "Decoded payload with magic bytes 3051310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3051310b"
        confidence = "high"

    strings:
        $magic = { 30 51 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3054310b {
    meta:
        description = "Decoded payload with magic bytes 3054310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3054310b"
        confidence = "high"

    strings:
        $magic = { 30 54 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3056310b {
    meta:
        description = "Decoded payload with magic bytes 3056310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3056310b"
        confidence = "high"

    strings:
        $magic = { 30 56 31 0b }

    condition:
        $magic
}

rule Payload_Magic_305a310b {
    meta:
        description = "Decoded payload with magic bytes 305a310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "305a310b"
        confidence = "high"

    strings:
        $magic = { 30 5a 31 0b }

    condition:
        $magic
}

rule Payload_Magic_305d310b {
    meta:
        description = "Decoded payload with magic bytes 305d310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "305d310b"
        confidence = "high"

    strings:
        $magic = { 30 5d 31 0b }

    condition:
        $magic
}

rule Payload_Magic_305f310b {
    meta:
        description = "Decoded payload with magic bytes 305f310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "305f310b"
        confidence = "high"

    strings:
        $magic = { 30 5f 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3061310b {
    meta:
        description = "Decoded payload with magic bytes 3061310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3061310b"
        confidence = "high"

    strings:
        $magic = { 30 61 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3062310b {
    meta:
        description = "Decoded payload with magic bytes 3062310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3062310b"
        confidence = "high"

    strings:
        $magic = { 30 62 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3063310b {
    meta:
        description = "Decoded payload with magic bytes 3063310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3063310b"
        confidence = "high"

    strings:
        $magic = { 30 63 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3065310b {
    meta:
        description = "Decoded payload with magic bytes 3065310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3065310b"
        confidence = "high"

    strings:
        $magic = { 30 65 31 0b }

    condition:
        $magic
}

rule Payload_Magic_306b310b {
    meta:
        description = "Decoded payload with magic bytes 306b310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "306b310b"
        confidence = "high"

    strings:
        $magic = { 30 6b 31 0b }

    condition:
        $magic
}

rule Payload_Magic_306c310b {
    meta:
        description = "Decoded payload with magic bytes 306c310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "306c310b"
        confidence = "high"

    strings:
        $magic = { 30 6c 31 0b }

    condition:
        $magic
}

rule Payload_Magic_306f310b {
    meta:
        description = "Decoded payload with magic bytes 306f310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "306f310b"
        confidence = "high"

    strings:
        $magic = { 30 6f 31 0b }

    condition:
        $magic
}

rule Payload_Magic_3074310b {
    meta:
        description = "Decoded payload with magic bytes 3074310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3074310b"
        confidence = "high"

    strings:
        $magic = { 30 74 31 0b }

    condition:
        $magic
}

rule Payload_Magic_307a310b {
    meta:
        description = "Decoded payload with magic bytes 307a310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "307a310b"
        confidence = "high"

    strings:
        $magic = { 30 7a 31 0b }

    condition:
        $magic
}

rule Payload_Magic_307e310b {
    meta:
        description = "Decoded payload with magic bytes 307e310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "307e310b"
        confidence = "high"

    strings:
        $magic = { 30 7e 31 0b }

    condition:
        $magic
}

rule Payload_Magic_307f310b {
    meta:
        description = "Decoded payload with magic bytes 307f310b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "307f310b"
        confidence = "high"

    strings:
        $magic = { 30 7f 31 0b }

    condition:
        $magic
}

rule Payload_Magic_30818031 {
    meta:
        description = "Decoded payload with magic bytes 30818031"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818031"
        confidence = "high"

    strings:
        $magic = { 30 81 80 31 }

    condition:
        $magic
}

rule Payload_Magic_30818231 {
    meta:
        description = "Decoded payload with magic bytes 30818231"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818231"
        confidence = "high"

    strings:
        $magic = { 30 81 82 31 }

    condition:
        $magic
}

rule Payload_Magic_30818331 {
    meta:
        description = "Decoded payload with magic bytes 30818331"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818331"
        confidence = "high"

    strings:
        $magic = { 30 81 83 31 }

    condition:
        $magic
}

rule Payload_Magic_30818531 {
    meta:
        description = "Decoded payload with magic bytes 30818531"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818531"
        confidence = "high"

    strings:
        $magic = { 30 81 85 31 }

    condition:
        $magic
}

rule Payload_Magic_30818831 {
    meta:
        description = "Decoded payload with magic bytes 30818831"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818831"
        confidence = "high"

    strings:
        $magic = { 30 81 88 31 }

    condition:
        $magic
}

rule Payload_Magic_30818f31 {
    meta:
        description = "Decoded payload with magic bytes 30818f31"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30818f31"
        confidence = "high"

    strings:
        $magic = { 30 81 8f 31 }

    condition:
        $magic
}

rule Payload_Magic_30819831 {
    meta:
        description = "Decoded payload with magic bytes 30819831"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30819831"
        confidence = "high"

    strings:
        $magic = { 30 81 98 31 }

    condition:
        $magic
}

rule Payload_Magic_30819f30 {
    meta:
        description = "Decoded payload with magic bytes 30819f30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "multi-family"
        magic_bytes = "30819f30"
        confidence = "high"

    strings:
        $magic = { 30 81 9f 30 }

    condition:
        $magic
}

rule Payload_Magic_3081a731 {
    meta:
        description = "Decoded payload with magic bytes 3081a731"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3081a731"
        confidence = "high"

    strings:
        $magic = { 30 81 a7 31 }

    condition:
        $magic
}

rule Payload_Magic_30820122 {
    meta:
        description = "Decoded payload with magic bytes 30820122"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        magic_bytes = "30820122"
        confidence = "high"

    strings:
        $magic = { 30 82 01 22 }

    condition:
        $magic
}

rule Payload_Magic_3082025d {
    meta:
        description = "Decoded payload with magic bytes 3082025d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3082025d"
        confidence = "high"

    strings:
        $magic = { 30 82 02 5d }

    condition:
        $magic
}

rule Payload_Magic_30c30c30 {
    meta:
        description = "Decoded payload with magic bytes 30c30c30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "30c30c30"
        confidence = "high"

    strings:
        $magic = { 30 c3 0c 30 }

    condition:
        $magic
}

rule Payload_Magic_31153013 {
    meta:
        description = "Decoded payload with magic bytes 31153013"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "31153013"
        confidence = "high"

    strings:
        $magic = { 31 15 30 13 }

    condition:
        $magic
}

rule Payload_Magic_3121bf48 {
    meta:
        description = "Decoded payload with magic bytes 3121bf48"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3121bf48"
        confidence = "high"

    strings:
        $magic = { 31 21 bf 48 }

    condition:
        $magic
}

rule Payload_Magic_31303233 {
    meta:
        description = "Decoded payload with magic bytes 31303233"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        magic_bytes = "31303233"
        confidence = "high"

    strings:
        $magic = { 31 30 32 33 }

    condition:
        $magic
}

rule Payload_Magic_31303332 {
    meta:
        description = "Decoded payload with magic bytes 31303332"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "multi-family"
        magic_bytes = "31303332"
        confidence = "high"

    strings:
        $magic = { 31 30 33 32 }

    condition:
        $magic
}

rule Payload_Magic_31303360 {
    meta:
        description = "Decoded payload with magic bytes 31303360"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "31303360"
        confidence = "high"

    strings:
        $magic = { 31 30 33 60 }

    condition:
        $magic
}

rule Payload_Magic_31313232 {
    meta:
        description = "Decoded payload with magic bytes 31313232"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "31313232"
        confidence = "high"

    strings:
        $magic = { 31 31 32 32 }

    condition:
        $magic
}

rule Payload_Magic_31394221 {
    meta:
        description = "Decoded payload with magic bytes 31394221"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "31394221"
        confidence = "high"

    strings:
        $magic = { 31 39 42 21 }

    condition:
        $magic
}

rule Payload_Magic_31792471 {
    meta:
        description = "Decoded payload with magic bytes 31792471"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "31792471"
        confidence = "high"

    strings:
        $magic = { 31 79 24 71 }

    condition:
        $magic
}

rule Payload_Magic_31e279c1 {
    meta:
        description = "Decoded payload with magic bytes 31e279c1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "31e279c1"
        confidence = "high"

    strings:
        $magic = { 31 e2 79 c1 }

    condition:
        $magic
}

rule Payload_Magic_31e76269 {
    meta:
        description = "Decoded payload with magic bytes 31e76269"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "31e76269"
        confidence = "high"

    strings:
        $magic = { 31 e7 62 69 }

    condition:
        $magic
}

rule Payload_Magic_32100402 {
    meta:
        description = "Decoded payload with magic bytes 32100402"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "32100402"
        confidence = "high"

    strings:
        $magic = { 32 10 04 02 }

    condition:
        $magic
}

rule Payload_Magic_32302624 {
    meta:
        description = "Decoded payload with magic bytes 32302624"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "32302624"
        confidence = "high"

    strings:
        $magic = { 32 30 26 24 }

    condition:
        $magic
}

rule Payload_Magic_32313635 {
    meta:
        description = "Decoded payload with magic bytes 32313635"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "32313635"
        confidence = "high"

    strings:
        $magic = { 32 31 36 35 }

    condition:
        $magic
}

rule Payload_Magic_3232707b {
    meta:
        description = "Decoded payload with magic bytes 3232707b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3232707b"
        confidence = "high"

    strings:
        $magic = { 32 32 70 7b }

    condition:
        $magic
}

rule Payload_Magic_32333435 {
    meta:
        description = "Decoded payload with magic bytes 32333435"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "32333435"
        confidence = "high"

    strings:
        $magic = { 32 33 34 35 }

    condition:
        $magic
}

rule Payload_Magic_32353534 {
    meta:
        description = "Decoded payload with magic bytes 32353534"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "32353534"
        confidence = "high"

    strings:
        $magic = { 32 35 35 34 }

    condition:
        $magic
}

rule Payload_Magic_32636072 {
    meta:
        description = "Decoded payload with magic bytes 32636072"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "32636072"
        confidence = "high"

    strings:
        $magic = { 32 63 60 72 }

    condition:
        $magic
}

rule Payload_Magic_32e96d8a {
    meta:
        description = "Decoded payload with magic bytes 32e96d8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        magic_bytes = "32e96d8a"
        confidence = "high"

    strings:
        $magic = { 32 e9 6d 8a }

    condition:
        $magic
}

rule Payload_Magic_33303536 {
    meta:
        description = "Decoded payload with magic bytes 33303536"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "33303536"
        confidence = "high"

    strings:
        $magic = { 33 30 35 36 }

    condition:
        $magic
}

rule Payload_Magic_33333333 {
    meta:
        description = "Decoded payload with magic bytes 33333333"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        magic_bytes = "33333333"
        confidence = "high"

    strings:
        $magic = { 33 33 33 33 }

    condition:
        $magic
}

rule Payload_Magic_340304fc {
    meta:
        description = "Decoded payload with magic bytes 340304fc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "340304fc"
        confidence = "high"

    strings:
        $magic = { 34 03 04 fc }

    condition:
        $magic
}

rule Payload_Magic_34232634 {
    meta:
        description = "Decoded payload with magic bytes 34232634"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "34232634"
        confidence = "high"

    strings:
        $magic = { 34 23 26 34 }

    condition:
        $magic
}

rule Payload_Magic_34313443 {
    meta:
        description = "Decoded payload with magic bytes 34313443"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "34313443"
        confidence = "high"

    strings:
        $magic = { 34 31 34 43 }

    condition:
        $magic
}

rule Payload_Magic_344103fd {
    meta:
        description = "Decoded payload with magic bytes 344103fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "344103fd"
        confidence = "high"

    strings:
        $magic = { 34 41 03 fd }

    condition:
        $magic
}

rule Payload_Magic_3444d208 {
    meta:
        description = "Decoded payload with magic bytes 3444d208"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3444d208"
        confidence = "high"

    strings:
        $magic = { 34 44 d2 08 }

    condition:
        $magic
}

rule Payload_Magic_35223422 {
    meta:
        description = "Decoded payload with magic bytes 35223422"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        magic_bytes = "35223422"
        confidence = "high"

    strings:
        $magic = { 35 22 34 22 }

    condition:
        $magic
}

rule Payload_Magic_35e176d9 {
    meta:
        description = "Decoded payload with magic bytes 35e176d9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "35e176d9"
        confidence = "high"

    strings:
        $magic = { 35 e1 76 d9 }

    condition:
        $magic
}

rule Payload_Magic_35eb70a2 {
    meta:
        description = "Decoded payload with magic bytes 35eb70a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "unknown"
        magic_bytes = "35eb70a2"
        confidence = "high"

    strings:
        $magic = { 35 eb 70 a2 }

    condition:
        $magic
}

rule Payload_Magic_36303d3f {
    meta:
        description = "Decoded payload with magic bytes 36303d3f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "36303d3f"
        confidence = "high"

    strings:
        $magic = { 36 30 3d 3f }

    condition:
        $magic
}

rule Payload_Magic_36317179 {
    meta:
        description = "Decoded payload with magic bytes 36317179"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "36317179"
        confidence = "high"

    strings:
        $magic = { 36 31 71 79 }

    condition:
        $magic
}

rule Payload_Magic_36373435 {
    meta:
        description = "Decoded payload with magic bytes 36373435"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "36373435"
        confidence = "high"

    strings:
        $magic = { 36 37 34 35 }

    condition:
        $magic
}

rule Payload_Magic_363e3e24 {
    meta:
        description = "Decoded payload with magic bytes 363e3e24"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "363e3e24"
        confidence = "high"

    strings:
        $magic = { 36 3e 3e 24 }

    condition:
        $magic
}

rule Payload_Magic_366d4043 {
    meta:
        description = "Decoded payload with magic bytes 366d4043"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "366d4043"
        confidence = "high"

    strings:
        $magic = { 36 6d 40 43 }

    condition:
        $magic
}

rule Payload_Magic_37343532 {
    meta:
        description = "Decoded payload with magic bytes 37343532"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "37343532"
        confidence = "high"

    strings:
        $magic = { 37 34 35 32 }

    condition:
        $magic
}

rule Payload_Magic_38127f34 {
    meta:
        description = "Decoded payload with magic bytes 38127f34"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38127f34"
        confidence = "high"

    strings:
        $magic = { 38 12 7f 34 }

    condition:
        $magic
}

rule Payload_Magic_38127f7e {
    meta:
        description = "Decoded payload with magic bytes 38127f7e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38127f7e"
        confidence = "high"

    strings:
        $magic = { 38 12 7f 7e }

    condition:
        $magic
}

rule Payload_Magic_38248ffc {
    meta:
        description = "Decoded payload with magic bytes 38248ffc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38248ffc"
        confidence = "high"

    strings:
        $magic = { 38 24 8f fc }

    condition:
        $magic
}

rule Payload_Magic_38248ffd {
    meta:
        description = "Decoded payload with magic bytes 38248ffd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38248ffd"
        confidence = "high"

    strings:
        $magic = { 38 24 8f fd }

    condition:
        $magic
}

rule Payload_Magic_38248ffe {
    meta:
        description = "Decoded payload with magic bytes 38248ffe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38248ffe"
        confidence = "high"

    strings:
        $magic = { 38 24 8f fe }

    condition:
        $magic
}

rule Payload_Magic_38f10d49 {
    meta:
        description = "Decoded payload with magic bytes 38f10d49"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "38f10d49"
        confidence = "high"

    strings:
        $magic = { 38 f1 0d 49 }

    condition:
        $magic
}

rule Payload_Magic_3929282e {
    meta:
        description = "Decoded payload with magic bytes 3929282e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3929282e"
        confidence = "high"

    strings:
        $magic = { 39 29 28 2e }

    condition:
        $magic
}

rule Payload_Magic_393a3b3c {
    meta:
        description = "Decoded payload with magic bytes 393a3b3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "393a3b3c"
        confidence = "high"

    strings:
        $magic = { 39 3a 3b 3c }

    condition:
        $magic
}

rule Payload_Magic_3a383720 {
    meta:
        description = "Decoded payload with magic bytes 3a383720"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "3a383720"
        confidence = "high"

    strings:
        $magic = { 3a 38 37 20 }

    condition:
        $magic
}

rule Payload_Magic_3a383e3c {
    meta:
        description = "Decoded payload with magic bytes 3a383e3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3a383e3c"
        confidence = "high"

    strings:
        $magic = { 3a 38 3e 3c }

    condition:
        $magic
}

rule Payload_Magic_3a39383f {
    meta:
        description = "Decoded payload with magic bytes 3a39383f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3a39383f"
        confidence = "high"

    strings:
        $magic = { 3a 39 38 3f }

    condition:
        $magic
}

rule Payload_Magic_3a41edb6 {
    meta:
        description = "Decoded payload with magic bytes 3a41edb6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3a41edb6"
        confidence = "high"

    strings:
        $magic = { 3a 41 ed b6 }

    condition:
        $magic
}

rule Payload_Magic_3a76686f {
    meta:
        description = "Decoded payload with magic bytes 3a76686f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3a76686f"
        confidence = "high"

    strings:
        $magic = { 3a 76 68 6f }

    condition:
        $magic
}

rule Payload_Magic_3a97a749 {
    meta:
        description = "Decoded payload with magic bytes 3a97a749"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3a97a749"
        confidence = "high"

    strings:
        $magic = { 3a 97 a7 49 }

    condition:
        $magic
}

rule Payload_Magic_3b29293f {
    meta:
        description = "Decoded payload with magic bytes 3b29293f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3b29293f"
        confidence = "high"

    strings:
        $magic = { 3b 29 29 3f }

    condition:
        $magic
}

rule Payload_Magic_3b38393e {
    meta:
        description = "Decoded payload with magic bytes 3b38393e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3b38393e"
        confidence = "high"

    strings:
        $magic = { 3b 38 39 3e }

    condition:
        $magic
}

rule Payload_Magic_3b393735 {
    meta:
        description = "Decoded payload with magic bytes 3b393735"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "3b393735"
        confidence = "high"

    strings:
        $magic = { 3b 39 37 35 }

    condition:
        $magic
}

rule Payload_Magic_3b8fa059 {
    meta:
        description = "Decoded payload with magic bytes 3b8fa059"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "3b8fa059"
        confidence = "high"

    strings:
        $magic = { 3b 8f a0 59 }

    condition:
        $magic
}

rule Payload_Magic_3c11168a {
    meta:
        description = "Decoded payload with magic bytes 3c11168a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        magic_bytes = "3c11168a"
        confidence = "high"

    strings:
        $magic = { 3c 11 16 8a }

    condition:
        $magic
}

rule Payload_Magic_3c3d3a3b {
    meta:
        description = "Decoded payload with magic bytes 3c3d3a3b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3c3d3a3b"
        confidence = "high"

    strings:
        $magic = { 3c 3d 3a 3b }

    condition:
        $magic
}

rule Payload_Magic_3c3d3e3f {
    meta:
        description = "Decoded payload with magic bytes 3c3d3e3f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3c3d3e3f"
        confidence = "high"

    strings:
        $magic = { 3c 3d 3e 3f }

    condition:
        $magic
}

rule Payload_Magic_3c3f3e39 {
    meta:
        description = "Decoded payload with magic bytes 3c3f3e39"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3c3f3e39"
        confidence = "high"

    strings:
        $magic = { 3c 3f 3e 39 }

    condition:
        $magic
}

rule Payload_Magic_3c739338 {
    meta:
        description = "Decoded payload with magic bytes 3c739338"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3c739338"
        confidence = "high"

    strings:
        $magic = { 3c 73 93 38 }

    condition:
        $magic
}

rule Payload_Magic_3ca092d7 {
    meta:
        description = "Decoded payload with magic bytes 3ca092d7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ca092d7"
        confidence = "high"

    strings:
        $magic = { 3c a0 92 d7 }

    condition:
        $magic
}

rule Payload_Magic_3ca092e7 {
    meta:
        description = "Decoded payload with magic bytes 3ca092e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ca092e7"
        confidence = "high"

    strings:
        $magic = { 3c a0 92 e7 }

    condition:
        $magic
}

rule Payload_Magic_3ca092ef {
    meta:
        description = "Decoded payload with magic bytes 3ca092ef"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ca092ef"
        confidence = "high"

    strings:
        $magic = { 3c a0 92 ef }

    condition:
        $magic
}

rule Payload_Magic_3ca092f3 {
    meta:
        description = "Decoded payload with magic bytes 3ca092f3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ca092f3"
        confidence = "high"

    strings:
        $magic = { 3c a0 92 f3 }

    condition:
        $magic
}

rule Payload_Magic_3ca118fd {
    meta:
        description = "Decoded payload with magic bytes 3ca118fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ca118fd"
        confidence = "high"

    strings:
        $magic = { 3c a1 18 fd }

    condition:
        $magic
}

rule Payload_Magic_3cb00210 {
    meta:
        description = "Decoded payload with magic bytes 3cb00210"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "3cb00210"
        confidence = "high"

    strings:
        $magic = { 3c b0 02 10 }

    condition:
        $magic
}

rule Payload_Magic_3ce2c809 {
    meta:
        description = "Decoded payload with magic bytes 3ce2c809"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3ce2c809"
        confidence = "high"

    strings:
        $magic = { 3c e2 c8 09 }

    condition:
        $magic
}

rule Payload_Magic_3d139763 {
    meta:
        description = "Decoded payload with magic bytes 3d139763"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "3d139763"
        confidence = "high"

    strings:
        $magic = { 3d 13 97 63 }

    condition:
        $magic
}

rule Payload_Magic_3d20454e {
    meta:
        description = "Decoded payload with magic bytes 3d20454e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "multi-family"
        magic_bytes = "3d20454e"
        confidence = "high"

    strings:
        $magic = { 3d 20 45 4e }

    condition:
        $magic
}

rule Payload_Magic_3d3d3d60 {
    meta:
        description = "Decoded payload with magic bytes 3d3d3d60"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d3d3d60"
        confidence = "high"

    strings:
        $magic = { 3d 3d 3d 60 }

    condition:
        $magic
}

rule Payload_Magic_3d3e433c {
    meta:
        description = "Decoded payload with magic bytes 3d3e433c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3d3e433c"
        confidence = "high"

    strings:
        $magic = { 3d 3e 43 3c }

    condition:
        $magic
}

rule Payload_Magic_3d3e796c {
    meta:
        description = "Decoded payload with magic bytes 3d3e796c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d3e796c"
        confidence = "high"

    strings:
        $magic = { 3d 3e 79 6c }

    condition:
        $magic
}

rule Payload_Magic_3d524e40 {
    meta:
        description = "Decoded payload with magic bytes 3d524e40"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3d524e40"
        confidence = "high"

    strings:
        $magic = { 3d 52 4e 40 }

    condition:
        $magic
}

rule Payload_Magic_3d536462 {
    meta:
        description = "Decoded payload with magic bytes 3d536462"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3d536462"
        confidence = "high"

    strings:
        $magic = { 3d 53 64 62 }

    condition:
        $magic
}

rule Payload_Magic_3d537463 {
    meta:
        description = "Decoded payload with magic bytes 3d537463"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3d537463"
        confidence = "high"

    strings:
        $magic = { 3d 53 74 63 }

    condition:
        $magic
}

rule Payload_Magic_3d602169 {
    meta:
        description = "Decoded payload with magic bytes 3d602169"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "3d602169"
        confidence = "high"

    strings:
        $magic = { 3d 60 21 69 }

    condition:
        $magic
}

rule Payload_Magic_3d603b75 {
    meta:
        description = "Decoded payload with magic bytes 3d603b75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d603b75"
        confidence = "high"

    strings:
        $magic = { 3d 60 3b 75 }

    condition:
        $magic
}

rule Payload_Magic_3d676e6f {
    meta:
        description = "Decoded payload with magic bytes 3d676e6f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3d676e6f"
        confidence = "high"

    strings:
        $magic = { 3d 67 6e 6f }

    condition:
        $magic
}

rule Payload_Magic_3d686f72 {
    meta:
        description = "Decoded payload with magic bytes 3d686f72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3d686f72"
        confidence = "high"

    strings:
        $magic = { 3d 68 6f 72 }

    condition:
        $magic
}

rule Payload_Magic_3d69756c {
    meta:
        description = "Decoded payload with magic bytes 3d69756c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "3d69756c"
        confidence = "high"

    strings:
        $magic = { 3d 69 75 6c }

    condition:
        $magic
}

rule Payload_Magic_3d6c6475 {
    meta:
        description = "Decoded payload with magic bytes 3d6c6475"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "3d6c6475"
        confidence = "high"

    strings:
        $magic = { 3d 6c 64 75 }

    condition:
        $magic
}

rule Payload_Magic_3d6e6767 {
    meta:
        description = "Decoded payload with magic bytes 3d6e6767"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d6e6767"
        confidence = "high"

    strings:
        $magic = { 3d 6e 67 67 }

    condition:
        $magic
}

rule Payload_Magic_3d727578 {
    meta:
        description = "Decoded payload with magic bytes 3d727578"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "unknown"
        magic_bytes = "3d727578"
        confidence = "high"

    strings:
        $magic = { 3d 72 75 78 }

    condition:
        $magic
}

rule Payload_Magic_3d736472 {
    meta:
        description = "Decoded payload with magic bytes 3d736472"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3d736472"
        confidence = "high"

    strings:
        $magic = { 3d 73 64 72 }

    condition:
        $magic
}

rule Payload_Magic_3d763b65 {
    meta:
        description = "Decoded payload with magic bytes 3d763b65"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d763b65"
        confidence = "high"

    strings:
        $magic = { 3d 76 3b 65 }

    condition:
        $magic
}

rule Payload_Magic_3d763b72 {
    meta:
        description = "Decoded payload with magic bytes 3d763b72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3d763b72"
        confidence = "high"

    strings:
        $magic = { 3d 76 3b 72 }

    condition:
        $magic
}

rule Payload_Magic_3da7246a {
    meta:
        description = "Decoded payload with magic bytes 3da7246a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3da7246a"
        confidence = "high"

    strings:
        $magic = { 3d a7 24 6a }

    condition:
        $magic
}

rule Payload_Magic_3e3c4240 {
    meta:
        description = "Decoded payload with magic bytes 3e3c4240"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3e3c4240"
        confidence = "high"

    strings:
        $magic = { 3e 3c 42 40 }

    condition:
        $magic
}

rule Payload_Magic_3e3d4241 {
    meta:
        description = "Decoded payload with magic bytes 3e3d4241"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3e3d4241"
        confidence = "high"

    strings:
        $magic = { 3e 3d 42 41 }

    condition:
        $magic
}

rule Payload_Magic_3e3f4041 {
    meta:
        description = "Decoded payload with magic bytes 3e3f4041"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "3e3f4041"
        confidence = "high"

    strings:
        $magic = { 3e 3f 40 41 }

    condition:
        $magic
}

rule Payload_Magic_3e716170 {
    meta:
        description = "Decoded payload with magic bytes 3e716170"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3e716170"
        confidence = "high"

    strings:
        $magic = { 3e 71 61 70 }

    condition:
        $magic
}

rule Payload_Magic_3ee6e589 {
    meta:
        description = "Decoded payload with magic bytes 3ee6e589"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3ee6e589"
        confidence = "high"

    strings:
        $magic = { 3e e6 e5 89 }

    condition:
        $magic
}

rule Payload_Magic_3f3c7b6e {
    meta:
        description = "Decoded payload with magic bytes 3f3c7b6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        magic_bytes = "3f3c7b6e"
        confidence = "high"

    strings:
        $magic = { 3f 3c 7b 6e }

    condition:
        $magic
}

rule Payload_Magic_3f3d3a38 {
    meta:
        description = "Decoded payload with magic bytes 3f3d3a38"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "3f3d3a38"
        confidence = "high"

    strings:
        $magic = { 3f 3d 3a 38 }

    condition:
        $magic
}

rule Payload_Magic_3f3e2023 {
    meta:
        description = "Decoded payload with magic bytes 3f3e2023"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "3f3e2023"
        confidence = "high"

    strings:
        $magic = { 3f 3e 20 23 }

    condition:
        $magic
}

rule Payload_Magic_3f3f2168 {
    meta:
        description = "Decoded payload with magic bytes 3f3f2168"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3f3f2168"
        confidence = "high"

    strings:
        $magic = { 3f 3f 21 68 }

    condition:
        $magic
}

rule Payload_Magic_3f3f216e {
    meta:
        description = "Decoded payload with magic bytes 3f3f216e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3f3f216e"
        confidence = "high"

    strings:
        $magic = { 3f 3f 21 6e }

    condition:
        $magic
}

rule Payload_Magic_3f3f5255 {
    meta:
        description = "Decoded payload with magic bytes 3f3f5255"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "3f3f5255"
        confidence = "high"

    strings:
        $magic = { 3f 3f 52 55 }

    condition:
        $magic
}

rule Payload_Magic_3f6b776e {
    meta:
        description = "Decoded payload with magic bytes 3f6b776e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        magic_bytes = "3f6b776e"
        confidence = "high"

    strings:
        $magic = { 3f 6b 77 6e }

    condition:
        $magic
}

rule Payload_Magic_40033f22 {
    meta:
        description = "Decoded payload with magic bytes 40033f22"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "40033f22"
        confidence = "high"

    strings:
        $magic = { 40 03 3f 22 }

    condition:
        $magic
}

rule Payload_Magic_4003ccfc {
    meta:
        description = "Decoded payload with magic bytes 4003ccfc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "4003ccfc"
        confidence = "high"

    strings:
        $magic = { 40 03 cc fc }

    condition:
        $magic
}

rule Payload_Magic_4003ccfd {
    meta:
        description = "Decoded payload with magic bytes 4003ccfd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "4003ccfd"
        confidence = "high"

    strings:
        $magic = { 40 03 cc fd }

    condition:
        $magic
}

rule Payload_Magic_40405e68 {
    meta:
        description = "Decoded payload with magic bytes 40405e68"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "40405e68"
        confidence = "high"

    strings:
        $magic = { 40 40 5e 68 }

    condition:
        $magic
}

rule Payload_Magic_40414243 {
    meta:
        description = "Decoded payload with magic bytes 40414243"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "40414243"
        confidence = "high"

    strings:
        $magic = { 40 41 42 43 }

    condition:
        $magic
}

rule Payload_Magic_40434245 {
    meta:
        description = "Decoded payload with magic bytes 40434245"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "multi-family"
        magic_bytes = "40434245"
        confidence = "high"

    strings:
        $magic = { 40 43 42 45 }

    condition:
        $magic
}

rule Payload_Magic_4044522c {
    meta:
        description = "Decoded payload with magic bytes 4044522c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4044522c"
        confidence = "high"

    strings:
        $magic = { 40 44 52 2c }

    condition:
        $magic
}

rule Payload_Magic_40454c6b {
    meta:
        description = "Decoded payload with magic bytes 40454c6b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "40454c6b"
        confidence = "high"

    strings:
        $magic = { 40 45 4c 6b }

    condition:
        $magic
}

rule Payload_Magic_40455128 {
    meta:
        description = "Decoded payload with magic bytes 40455128"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "40455128"
        confidence = "high"

    strings:
        $magic = { 40 45 51 28 }

    condition:
        $magic
}

rule Payload_Magic_4045512b {
    meta:
        description = "Decoded payload with magic bytes 4045512b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4045512b"
        confidence = "high"

    strings:
        $magic = { 40 45 51 2b }

    condition:
        $magic
}

rule Payload_Magic_40555540 {
    meta:
        description = "Decoded payload with magic bytes 40555540"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "40555540"
        confidence = "high"

    strings:
        $magic = { 40 55 55 40 }

    condition:
        $magic
}

rule Payload_Magic_40655768 {
    meta:
        description = "Decoded payload with magic bytes 40655768"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.colorme.game.jisushuzipai"
        magic_bytes = "40655768"
        confidence = "high"

    strings:
        $magic = { 40 65 57 68 }

    condition:
        $magic
}

rule Payload_Magic_406f6573 {
    meta:
        description = "Decoded payload with magic bytes 406f6573"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "unknown"
        magic_bytes = "406f6573"
        confidence = "high"

    strings:
        $magic = { 40 6f 65 73 }

    condition:
        $magic
}

rule Payload_Magic_40716a45 {
    meta:
        description = "Decoded payload with magic bytes 40716a45"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "40716a45"
        confidence = "high"

    strings:
        $magic = { 40 71 6a 45 }

    condition:
        $magic
}

rule Payload_Magic_40716a52 {
    meta:
        description = "Decoded payload with magic bytes 40716a52"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "40716a52"
        confidence = "high"

    strings:
        $magic = { 40 71 6a 52 }

    condition:
        $magic
}

rule Payload_Magic_41533233 {
    meta:
        description = "Decoded payload with magic bytes 41533233"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "41533233"
        confidence = "high"

    strings:
        $magic = { 41 53 32 33 }

    condition:
        $magic
}

rule Payload_Magic_41607171 {
    meta:
        description = "Decoded payload with magic bytes 41607171"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "41607171"
        confidence = "high"

    strings:
        $magic = { 41 60 71 71 }

    condition:
        $magic
}

rule Payload_Magic_416c6267 {
    meta:
        description = "Decoded payload with magic bytes 416c6267"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "416c6267"
        confidence = "high"

    strings:
        $magic = { 41 6c 62 67 }

    condition:
        $magic
}

rule Payload_Magic_417a7b66 {
    meta:
        description = "Decoded payload with magic bytes 417a7b66"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "417a7b66"
        confidence = "high"

    strings:
        $magic = { 41 7a 7b 66 }

    condition:
        $magic
}

rule Payload_Magic_4231d9aa {
    meta:
        description = "Decoded payload with magic bytes 4231d9aa"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "4231d9aa"
        confidence = "high"

    strings:
        $magic = { 42 31 d9 aa }

    condition:
        $magic
}

rule Payload_Magic_424d4851 {
    meta:
        description = "Decoded payload with magic bytes 424d4851"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "424d4851"
        confidence = "high"

    strings:
        $magic = { 42 4d 48 51 }

    condition:
        $magic
}

rule Payload_Magic_424e4c4c {
    meta:
        description = "Decoded payload with magic bytes 424e4c4c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "424e4c4c"
        confidence = "high"

    strings:
        $magic = { 42 4e 4c 4c }

    condition:
        $magic
}

rule Payload_Magic_424e4d4e {
    meta:
        description = "Decoded payload with magic bytes 424e4d4e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "424e4d4e"
        confidence = "high"

    strings:
        $magic = { 42 4e 4d 4e }

    condition:
        $magic
}

rule Payload_Magic_42534440 {
    meta:
        description = "Decoded payload with magic bytes 42534440"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "multi-family"
        magic_bytes = "42534440"
        confidence = "high"

    strings:
        $magic = { 42 53 44 40 }

    condition:
        $magic
}

rule Payload_Magic_42606269 {
    meta:
        description = "Decoded payload with magic bytes 42606269"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "42606269"
        confidence = "high"

    strings:
        $magic = { 42 60 62 69 }

    condition:
        $magic
}

rule Payload_Magic_427d36fb {
    meta:
        description = "Decoded payload with magic bytes 427d36fb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "427d36fb"
        confidence = "high"

    strings:
        $magic = { 42 7d 36 fb }

    condition:
        $magic
}

rule Payload_Magic_43415451 {
    meta:
        description = "Decoded payload with magic bytes 43415451"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "43415451"
        confidence = "high"

    strings:
        $magic = { 43 41 54 51 }

    condition:
        $magic
}

rule Payload_Magic_43606f6f {
    meta:
        description = "Decoded payload with magic bytes 43606f6f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "43606f6f"
        confidence = "high"

    strings:
        $magic = { 43 60 6f 6f }

    condition:
        $magic
}

rule Payload_Magic_43607264 {
    meta:
        description = "Decoded payload with magic bytes 43607264"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "43607264"
        confidence = "high"

    strings:
        $magic = { 43 60 72 64 }

    condition:
        $magic
}

rule Payload_Magic_43634565 {
    meta:
        description = "Decoded payload with magic bytes 43634565"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "43634565"
        confidence = "high"

    strings:
        $magic = { 43 63 45 65 }

    condition:
        $magic
}

rule Payload_Magic_436b7c25 {
    meta:
        description = "Decoded payload with magic bytes 436b7c25"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "436b7c25"
        confidence = "high"

    strings:
        $magic = { 43 6b 7c 25 }

    condition:
        $magic
}

rule Payload_Magic_4374666d {
    meta:
        description = "Decoded payload with magic bytes 4374666d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "4374666d"
        confidence = "high"

    strings:
        $magic = { 43 74 66 6d }

    condition:
        $magic
}

rule Payload_Magic_440343fe {
    meta:
        description = "Decoded payload with magic bytes 440343fe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "440343fe"
        confidence = "high"

    strings:
        $magic = { 44 03 43 fe }

    condition:
        $magic
}

rule Payload_Magic_4444d444 {
    meta:
        description = "Decoded payload with magic bytes 4444d444"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "4444d444"
        confidence = "high"

    strings:
        $magic = { 44 44 d4 44 }

    condition:
        $magic
}

rule Payload_Magic_45203f10 {
    meta:
        description = "Decoded payload with magic bytes 45203f10"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45203f10"
        confidence = "high"

    strings:
        $magic = { 45 20 3f 10 }

    condition:
        $magic
}

rule Payload_Magic_4540542e {
    meta:
        description = "Decoded payload with magic bytes 4540542e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "4540542e"
        confidence = "high"

    strings:
        $magic = { 45 40 54 2e }

    condition:
        $magic
}

rule Payload_Magic_45444354 {
    meta:
        description = "Decoded payload with magic bytes 45444354"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45444354"
        confidence = "high"

    strings:
        $magic = { 45 44 43 54 }

    condition:
        $magic
}

rule Payload_Magic_45444746 {
    meta:
        description = "Decoded payload with magic bytes 45444746"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "45444746"
        confidence = "high"

    strings:
        $magic = { 45 44 47 46 }

    condition:
        $magic
}

rule Payload_Magic_45444d44 {
    meta:
        description = "Decoded payload with magic bytes 45444d44"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45444d44"
        confidence = "high"

    strings:
        $magic = { 45 44 4d 44 }

    condition:
        $magic
}

rule Payload_Magic_454b4347 {
    meta:
        description = "Decoded payload with magic bytes 454b4347"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "454b4347"
        confidence = "high"

    strings:
        $magic = { 45 4b 43 47 }

    condition:
        $magic
}

rule Payload_Magic_45534e51 {
    meta:
        description = "Decoded payload with magic bytes 45534e51"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45534e51"
        confidence = "high"

    strings:
        $magic = { 45 53 4e 51 }

    condition:
        $magic
}

rule Payload_Magic_45687271 {
    meta:
        description = "Decoded payload with magic bytes 45687271"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45687271"
        confidence = "high"

    strings:
        $magic = { 45 68 72 71 }

    condition:
        $magic
}

rule Payload_Magic_45ea68ae {
    meta:
        description = "Decoded payload with magic bytes 45ea68ae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "45ea68ae"
        confidence = "high"

    strings:
        $magic = { 45 ea 68 ae }

    condition:
        $magic
}

rule Payload_Magic_46267426 {
    meta:
        description = "Decoded payload with magic bytes 46267426"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "46267426"
        confidence = "high"

    strings:
        $magic = { 46 26 74 26 }

    condition:
        $magic
}

rule Payload_Magic_4649484b {
    meta:
        description = "Decoded payload with magic bytes 4649484b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4649484b"
        confidence = "high"

    strings:
        $magic = { 46 49 48 4b }

    condition:
        $magic
}

rule Payload_Magic_46647542 {
    meta:
        description = "Decoded payload with magic bytes 46647542"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "46647542"
        confidence = "high"

    strings:
        $magic = { 46 64 75 42 }

    condition:
        $magic
}

rule Payload_Magic_468ba775 {
    meta:
        description = "Decoded payload with magic bytes 468ba775"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "468ba775"
        confidence = "high"

    strings:
        $magic = { 46 8b a7 75 }

    condition:
        $magic
}

rule Payload_Magic_47405d4b {
    meta:
        description = "Decoded payload with magic bytes 47405d4b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "47405d4b"
        confidence = "high"

    strings:
        $magic = { 47 40 5d 4b }

    condition:
        $magic
}

rule Payload_Magic_47534e4c {
    meta:
        description = "Decoded payload with magic bytes 47534e4c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "47534e4c"
        confidence = "high"

    strings:
        $magic = { 47 53 4e 4c }

    condition:
        $magic
}

rule Payload_Magic_4760686d {
    meta:
        description = "Decoded payload with magic bytes 4760686d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4760686d"
        confidence = "high"

    strings:
        $magic = { 47 60 68 6d }

    condition:
        $magic
}

rule Payload_Magic_47686f60 {
    meta:
        description = "Decoded payload with magic bytes 47686f60"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "47686f60"
        confidence = "high"

    strings:
        $magic = { 47 68 6f 60 }

    condition:
        $magic
}

rule Payload_Magic_47726273 {
    meta:
        description = "Decoded payload with magic bytes 47726273"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "47726273"
        confidence = "high"

    strings:
        $magic = { 47 72 62 73 }

    condition:
        $magic
}

rule Payload_Magic_47cfd234 {
    meta:
        description = "Decoded payload with magic bytes 47cfd234"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "47cfd234"
        confidence = "high"

    strings:
        $magic = { 47 cf d2 34 }

    condition:
        $magic
}

rule Payload_Magic_4842442c {
    meta:
        description = "Decoded payload with magic bytes 4842442c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4842442c"
        confidence = "high"

    strings:
        $magic = { 48 42 44 2c }

    condition:
        $magic
}

rule Payload_Magic_484c514e {
    meta:
        description = "Decoded payload with magic bytes 484c514e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "484c514e"
        confidence = "high"

    strings:
        $magic = { 48 4c 51 4e }

    condition:
        $magic
}

rule Payload_Magic_484f474d {
    meta:
        description = "Decoded payload with magic bytes 484f474d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "484f474d"
        confidence = "high"

    strings:
        $magic = { 48 4f 47 4d }

    condition:
        $magic
}

rule Payload_Magic_484f5244 {
    meta:
        description = "Decoded payload with magic bytes 484f5244"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "484f5244"
        confidence = "high"

    strings:
        $magic = { 48 4f 52 44 }

    condition:
        $magic
}

rule Payload_Magic_484f555e {
    meta:
        description = "Decoded payload with magic bytes 484f555e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "484f555e"
        confidence = "high"

    strings:
        $magic = { 48 4f 55 5e }

    condition:
        $magic
}

rule Payload_Magic_4858687b {
    meta:
        description = "Decoded payload with magic bytes 4858687b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "4858687b"
        confidence = "high"

    strings:
        $magic = { 48 58 68 7b }

    condition:
        $magic
}

rule Payload_Magic_486f7275 {
    meta:
        description = "Decoded payload with magic bytes 486f7275"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "486f7275"
        confidence = "high"

    strings:
        $magic = { 48 6f 72 75 }

    condition:
        $magic
}

rule Payload_Magic_486f7760 {
    meta:
        description = "Decoded payload with magic bytes 486f7760"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "486f7760"
        confidence = "high"

    strings:
        $magic = { 48 6f 77 60 }

    condition:
        $magic
}

rule Payload_Magic_48818dfc {
    meta:
        description = "Decoded payload with magic bytes 48818dfc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "48818dfc"
        confidence = "high"

    strings:
        $magic = { 48 81 8d fc }

    condition:
        $magic
}

rule Payload_Magic_4922ff0c {
    meta:
        description = "Decoded payload with magic bytes 4922ff0c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4922ff0c"
        confidence = "high"

    strings:
        $magic = { 49 22 ff 0c }

    condition:
        $magic
}

rule Payload_Magic_4922ff35 {
    meta:
        description = "Decoded payload with magic bytes 4922ff35"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "4922ff35"
        confidence = "high"

    strings:
        $magic = { 49 22 ff 35 }

    condition:
        $magic
}

rule Payload_Magic_4922ff45 {
    meta:
        description = "Decoded payload with magic bytes 4922ff45"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4922ff45"
        confidence = "high"

    strings:
        $magic = { 49 22 ff 45 }

    condition:
        $magic
}

rule Payload_Magic_49338ffc {
    meta:
        description = "Decoded payload with magic bytes 49338ffc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "49338ffc"
        confidence = "high"

    strings:
        $magic = { 49 33 8f fc }

    condition:
        $magic
}

rule Payload_Magic_493bc98e {
    meta:
        description = "Decoded payload with magic bytes 493bc98e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "493bc98e"
        confidence = "high"

    strings:
        $magic = { 49 3b c9 8e }

    condition:
        $magic
}

rule Payload_Magic_49408211 {
    meta:
        description = "Decoded payload with magic bytes 49408211"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "unknown"
        magic_bytes = "49408211"
        confidence = "high"

    strings:
        $magic = { 49 40 82 11 }

    condition:
        $magic
}

rule Payload_Magic_49444045 {
    meta:
        description = "Decoded payload with magic bytes 49444045"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "49444045"
        confidence = "high"

    strings:
        $magic = { 49 44 40 45 }

    condition:
        $magic
}

rule Payload_Magic_49621308 {
    meta:
        description = "Decoded payload with magic bytes 49621308"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "49621308"
        confidence = "high"

    strings:
        $magic = { 49 62 13 08 }

    condition:
        $magic
}

rule Payload_Magic_4967497b {
    meta:
        description = "Decoded payload with magic bytes 4967497b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "4967497b"
        confidence = "high"

    strings:
        $magic = { 49 67 49 7b }

    condition:
        $magic
}

rule Payload_Magic_4973444f {
    meta:
        description = "Decoded payload with magic bytes 4973444f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "4973444f"
        confidence = "high"

    strings:
        $magic = { 49 73 44 4f }

    condition:
        $magic
}

rule Payload_Magic_49e73e59 {
    meta:
        description = "Decoded payload with magic bytes 49e73e59"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "49e73e59"
        confidence = "high"

    strings:
        $magic = { 49 e7 3e 59 }

    condition:
        $magic
}

rule Payload_Magic_49e9edaf {
    meta:
        description = "Decoded payload with magic bytes 49e9edaf"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "49e9edaf"
        confidence = "high"

    strings:
        $magic = { 49 e9 ed af }

    condition:
        $magic
}

rule Payload_Magic_49eb496a {
    meta:
        description = "Decoded payload with magic bytes 49eb496a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "49eb496a"
        confidence = "high"

    strings:
        $magic = { 49 eb 49 6a }

    condition:
        $magic
}

rule Payload_Magic_4a29e095 {
    meta:
        description = "Decoded payload with magic bytes 4a29e095"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4a29e095"
        confidence = "high"

    strings:
        $magic = { 4a 29 e0 95 }

    condition:
        $magic
}

rule Payload_Magic_4a40462e {
    meta:
        description = "Decoded payload with magic bytes 4a40462e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4a40462e"
        confidence = "high"

    strings:
        $magic = { 4a 40 46 2e }

    condition:
        $magic
}

rule Payload_Magic_4b468efa {
    meta:
        description = "Decoded payload with magic bytes 4b468efa"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "4b468efa"
        confidence = "high"

    strings:
        $magic = { 4b 46 8e fa }

    condition:
        $magic
}

rule Payload_Magic_4b495c59 {
    meta:
        description = "Decoded payload with magic bytes 4b495c59"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4b495c59"
        confidence = "high"

    strings:
        $magic = { 4b 49 5c 59 }

    condition:
        $magic
}

rule Payload_Magic_4c444c4e {
    meta:
        description = "Decoded payload with magic bytes 4c444c4e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c444c4e"
        confidence = "high"

    strings:
        $magic = { 4c 44 4c 4e }

    condition:
        $magic
}

rule Payload_Magic_4c4b4947 {
    meta:
        description = "Decoded payload with magic bytes 4c4b4947"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c4b4947"
        confidence = "high"

    strings:
        $magic = { 4c 4b 49 47 }

    condition:
        $magic
}

rule Payload_Magic_4c4b5e4b {
    meta:
        description = "Decoded payload with magic bytes 4c4b5e4b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c4b5e4b"
        confidence = "high"

    strings:
        $magic = { 4c 4b 5e 4b }

    condition:
        $magic
}

rule Payload_Magic_4c4e5b5e {
    meta:
        description = "Decoded payload with magic bytes 4c4e5b5e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c4e5b5e"
        confidence = "high"

    strings:
        $magic = { 4c 4e 5b 5e }

    condition:
        $magic
}

rule Payload_Magic_4c646568 {
    meta:
        description = "Decoded payload with magic bytes 4c646568"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c646568"
        confidence = "high"

    strings:
        $magic = { 4c 64 65 68 }

    condition:
        $magic
}

rule Payload_Magic_4c647569 {
    meta:
        description = "Decoded payload with magic bytes 4c647569"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "4c647569"
        confidence = "high"

    strings:
        $magic = { 4c 64 75 69 }

    condition:
        $magic
}

rule Payload_Magic_4c6e7b68 {
    meta:
        description = "Decoded payload with magic bytes 4c6e7b68"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "12"
        family = "multi-family"
        magic_bytes = "4c6e7b68"
        confidence = "high"

    strings:
        $magic = { 4c 6e 7b 68 }

    condition:
        $magic
}

rule Payload_Magic_4c785173 {
    meta:
        description = "Decoded payload with magic bytes 4c785173"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4c785173"
        confidence = "high"

    strings:
        $magic = { 4c 78 51 73 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf00 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf00"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf00"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 00 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf08 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf08"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 08 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf0c {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf0c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf0c"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 0c }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf10 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf10"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf10"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 10 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf29 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf29"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf29"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 29 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf35 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf35"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "4cb4bf35"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 35 }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf3d {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf3d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf3d"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 3d }

    condition:
        $magic
}

rule Payload_Magic_4cb4bf45 {
    meta:
        description = "Decoded payload with magic bytes 4cb4bf45"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4cb4bf45"
        confidence = "high"

    strings:
        $magic = { 4c b4 bf 45 }

    condition:
        $magic
}

rule Payload_Magic_4ce45110 {
    meta:
        description = "Decoded payload with magic bytes 4ce45110"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "4ce45110"
        confidence = "high"

    strings:
        $magic = { 4c e4 51 10 }

    condition:
        $magic
}

rule Payload_Magic_4d5c4b4f {
    meta:
        description = "Decoded payload with magic bytes 4d5c4b4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "10"
        family = "multi-family"
        magic_bytes = "4d5c4b4f"
        confidence = "high"

    strings:
        $magic = { 4d 5c 4b 4f }

    condition:
        $magic
}

rule Payload_Magic_4d686f6a {
    meta:
        description = "Decoded payload with magic bytes 4d686f6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "4d686f6a"
        confidence = "high"

    strings:
        $magic = { 4d 68 6f 6a }

    condition:
        $magic
}

rule Payload_Magic_4d6f6d66 {
    meta:
        description = "Decoded payload with magic bytes 4d6f6d66"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4d6f6d66"
        confidence = "high"

    strings:
        $magic = { 4d 6f 6d 66 }

    condition:
        $magic
}

rule Payload_Magic_4e1b0a17 {
    meta:
        description = "Decoded payload with magic bytes 4e1b0a17"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "unknown"
        magic_bytes = "4e1b0a17"
        confidence = "high"

    strings:
        $magic = { 4e 1b 0a 17 }

    condition:
        $magic
}

rule Payload_Magic_4e4d4241 {
    meta:
        description = "Decoded payload with magic bytes 4e4d4241"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4e4d4241"
        confidence = "high"

    strings:
        $magic = { 4e 4d 42 41 }

    condition:
        $magic
}

rule Payload_Magic_4e8a0c6a {
    meta:
        description = "Decoded payload with magic bytes 4e8a0c6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "4e8a0c6a"
        confidence = "high"

    strings:
        $magic = { 4e 8a 0c 6a }

    condition:
        $magic
}

rule Payload_Magic_4f404a2e {
    meta:
        description = "Decoded payload with magic bytes 4f404a2e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4f404a2e"
        confidence = "high"

    strings:
        $magic = { 4f 40 4a 2e }

    condition:
        $magic
}

rule Payload_Magic_4f527532 {
    meta:
        description = "Decoded payload with magic bytes 4f527532"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4f527532"
        confidence = "high"

    strings:
        $magic = { 4f 52 75 32 }

    condition:
        $magic
}

rule Payload_Magic_4f544d4d {
    meta:
        description = "Decoded payload with magic bytes 4f544d4d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "4f544d4d"
        confidence = "high"

    strings:
        $magic = { 4f 54 4d 4d }

    condition:
        $magic
}

rule Payload_Magic_4f6e4c6e {
    meta:
        description = "Decoded payload with magic bytes 4f6e4c6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "4f6e4c6e"
        confidence = "high"

    strings:
        $magic = { 4f 6e 4c 6e }

    condition:
        $magic
}

rule Payload_Magic_4f6e7568 {
    meta:
        description = "Decoded payload with magic bytes 4f6e7568"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "4f6e7568"
        confidence = "high"

    strings:
        $magic = { 4f 6e 75 68 }

    condition:
        $magic
}

rule Payload_Magic_504f2c68 {
    meta:
        description = "Decoded payload with magic bytes 504f2c68"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "504f2c68"
        confidence = "high"

    strings:
        $magic = { 50 4f 2c 68 }

    condition:
        $magic
}

rule Payload_Magic_50515253 {
    meta:
        description = "Decoded payload with magic bytes 50515253"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "50515253"
        confidence = "high"

    strings:
        $magic = { 50 51 52 53 }

    condition:
        $magic
}

rule Payload_Magic_50525456 {
    meta:
        description = "Decoded payload with magic bytes 50525456"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "50525456"
        confidence = "high"

    strings:
        $magic = { 50 52 54 56 }

    condition:
        $magic
}

rule Payload_Magic_50d10d09 {
    meta:
        description = "Decoded payload with magic bytes 50d10d09"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "50d10d09"
        confidence = "high"

    strings:
        $magic = { 50 d1 0d 09 }

    condition:
        $magic
}

rule Payload_Magic_50d1173c {
    meta:
        description = "Decoded payload with magic bytes 50d1173c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "unknown"
        magic_bytes = "50d1173c"
        confidence = "high"

    strings:
        $magic = { 50 d1 17 3c }

    condition:
        $magic
}

rule Payload_Magic_51534046 {
    meta:
        description = "Decoded payload with magic bytes 51534046"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "51534046"
        confidence = "high"

    strings:
        $magic = { 51 53 40 46 }

    condition:
        $magic
}

rule Payload_Magic_51545950 {
    meta:
        description = "Decoded payload with magic bytes 51545950"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "51545950"
        confidence = "high"

    strings:
        $magic = { 51 54 59 50 }

    condition:
        $magic
}

rule Payload_Magic_51696e75 {
    meta:
        description = "Decoded payload with magic bytes 51696e75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "51696e75"
        confidence = "high"

    strings:
        $magic = { 51 69 6e 75 }

    condition:
        $magic
}

rule Payload_Magic_52444d44 {
    meta:
        description = "Decoded payload with magic bytes 52444d44"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "multi-family"
        magic_bytes = "52444d44"
        confidence = "high"

    strings:
        $magic = { 52 44 4d 44 }

    condition:
        $magic
}

rule Payload_Magic_52494030 {
    meta:
        description = "Decoded payload with magic bytes 52494030"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "52494030"
        confidence = "high"

    strings:
        $magic = { 52 49 40 30 }

    condition:
        $magic
}

rule Payload_Magic_52494034 {
    meta:
        description = "Decoded payload with magic bytes 52494034"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "52494034"
        confidence = "high"

    strings:
        $magic = { 52 49 40 34 }

    condition:
        $magic
}

rule Payload_Magic_52515655 {
    meta:
        description = "Decoded payload with magic bytes 52515655"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "52515655"
        confidence = "high"

    strings:
        $magic = { 52 51 56 55 }

    condition:
        $magic
}

rule Payload_Magic_52567f7a {
    meta:
        description = "Decoded payload with magic bytes 52567f7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "52567f7a"
        confidence = "high"

    strings:
        $magic = { 52 56 7f 7a }

    condition:
        $magic
}

rule Payload_Magic_52646d64 {
    meta:
        description = "Decoded payload with magic bytes 52646d64"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "52646d64"
        confidence = "high"

    strings:
        $magic = { 52 64 6d 64 }

    condition:
        $magic
}

rule Payload_Magic_52696c69 {
    meta:
        description = "Decoded payload with magic bytes 52696c69"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "52696c69"
        confidence = "high"

    strings:
        $magic = { 52 69 6c 69 }

    condition:
        $magic
}

rule Payload_Magic_526e6268 {
    meta:
        description = "Decoded payload with magic bytes 526e6268"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "526e6268"
        confidence = "high"

    strings:
        $magic = { 52 6e 62 68 }

    condition:
        $magic
}

rule Payload_Magic_53444f45 {
    meta:
        description = "Decoded payload with magic bytes 53444f45"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "53444f45"
        confidence = "high"

    strings:
        $magic = { 53 44 4f 45 }

    condition:
        $magic
}

rule Payload_Magic_5344514d {
    meta:
        description = "Decoded payload with magic bytes 5344514d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "5344514d"
        confidence = "high"

    strings:
        $magic = { 53 44 51 4d }

    condition:
        $magic
}

rule Payload_Magic_54222598 {
    meta:
        description = "Decoded payload with magic bytes 54222598"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "54222598"
        confidence = "high"

    strings:
        $magic = { 54 22 25 98 }

    condition:
        $magic
}

rule Payload_Magic_546f6063 {
    meta:
        description = "Decoded payload with magic bytes 546f6063"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "546f6063"
        confidence = "high"

    strings:
        $magic = { 54 6f 60 63 }

    condition:
        $magic
}

rule Payload_Magic_55515f7e {
    meta:
        description = "Decoded payload with magic bytes 55515f7e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "55515f7e"
        confidence = "high"

    strings:
        $magic = { 55 51 5f 7e }

    condition:
        $magic
}

rule Payload_Magic_55787164 {
    meta:
        description = "Decoded payload with magic bytes 55787164"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "55787164"
        confidence = "high"

    strings:
        $magic = { 55 78 71 64 }

    condition:
        $magic
}

rule Payload_Magic_56494453 {
    meta:
        description = "Decoded payload with magic bytes 56494453"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "56494453"
        confidence = "high"

    strings:
        $magic = { 56 49 44 53 }

    condition:
        $magic
}

rule Payload_Magic_56632254 {
    meta:
        description = "Decoded payload with magic bytes 56632254"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "56632254"
        confidence = "high"

    strings:
        $magic = { 56 63 22 54 }

    condition:
        $magic
}

rule Payload_Magic_56e9e095 {
    meta:
        description = "Decoded payload with magic bytes 56e9e095"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "56e9e095"
        confidence = "high"

    strings:
        $magic = { 56 e9 e0 95 }

    condition:
        $magic
}

rule Payload_Magic_57404d48 {
    meta:
        description = "Decoded payload with magic bytes 57404d48"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "57404d48"
        confidence = "high"

    strings:
        $magic = { 57 40 4d 48 }

    condition:
        $magic
}

rule Payload_Magic_57484021 {
    meta:
        description = "Decoded payload with magic bytes 57484021"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "57484021"
        confidence = "high"

    strings:
        $magic = { 57 48 40 21 }

    condition:
        $magic
}

rule Payload_Magic_57494554 {
    meta:
        description = "Decoded payload with magic bytes 57494554"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        magic_bytes = "57494554"
        confidence = "high"

    strings:
        $magic = { 57 49 45 54 }

    condition:
        $magic
}

rule Payload_Magic_5750777f {
    meta:
        description = "Decoded payload with magic bytes 5750777f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5750777f"
        confidence = "high"

    strings:
        $magic = { 57 50 77 7f }

    condition:
        $magic
}

rule Payload_Magic_58021320 {
    meta:
        description = "Decoded payload with magic bytes 58021320"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "unknown"
        magic_bytes = "58021320"
        confidence = "high"

    strings:
        $magic = { 58 02 13 20 }

    condition:
        $magic
}

rule Payload_Magic_58573033 {
    meta:
        description = "Decoded payload with magic bytes 58573033"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "58573033"
        confidence = "high"

    strings:
        $magic = { 58 57 30 33 }

    condition:
        $magic
}

rule Payload_Magic_58595a5b {
    meta:
        description = "Decoded payload with magic bytes 58595a5b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "58595a5b"
        confidence = "high"

    strings:
        $magic = { 58 59 5a 5b }

    condition:
        $magic
}

rule Payload_Magic_58721311 {
    meta:
        description = "Decoded payload with magic bytes 58721311"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "58721311"
        confidence = "high"

    strings:
        $magic = { 58 72 13 11 }

    condition:
        $magic
}

rule Payload_Magic_59464b5c {
    meta:
        description = "Decoded payload with magic bytes 59464b5c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "59464b5c"
        confidence = "high"

    strings:
        $magic = { 59 46 4b 5c }

    condition:
        $magic
}

rule Payload_Magic_595b4e4b {
    meta:
        description = "Decoded payload with magic bytes 595b4e4b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "595b4e4b"
        confidence = "high"

    strings:
        $magic = { 59 5b 4e 4b }

    condition:
        $magic
}

rule Payload_Magic_59677a66 {
    meta:
        description = "Decoded payload with magic bytes 59677a66"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "59677a66"
        confidence = "high"

    strings:
        $magic = { 59 67 7a 66 }

    condition:
        $magic
}

rule Payload_Magic_59a91e7e {
    meta:
        description = "Decoded payload with magic bytes 59a91e7e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "59a91e7e"
        confidence = "high"

    strings:
        $magic = { 59 a9 1e 7e }

    condition:
        $magic
}

rule Payload_Magic_5a325c21 {
    meta:
        description = "Decoded payload with magic bytes 5a325c21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "5a325c21"
        confidence = "high"

    strings:
        $magic = { 5a 32 5c 21 }

    condition:
        $magic
}

rule Payload_Magic_5a335c21 {
    meta:
        description = "Decoded payload with magic bytes 5a335c21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "5a335c21"
        confidence = "high"

    strings:
        $magic = { 5a 33 5c 21 }

    condition:
        $magic
}

rule Payload_Magic_5a464b40 {
    meta:
        description = "Decoded payload with magic bytes 5a464b40"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5a464b40"
        confidence = "high"

    strings:
        $magic = { 5a 46 4b 40 }

    condition:
        $magic
}

rule Payload_Magic_5a4f2928 {
    meta:
        description = "Decoded payload with magic bytes 5a4f2928"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5a4f2928"
        confidence = "high"

    strings:
        $magic = { 5a 4f 29 28 }

    condition:
        $magic
}

rule Payload_Magic_5a5b5859 {
    meta:
        description = "Decoded payload with magic bytes 5a5b5859"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "5a5b5859"
        confidence = "high"

    strings:
        $magic = { 5a 5b 58 59 }

    condition:
        $magic
}

rule Payload_Magic_5a5e5e55 {
    meta:
        description = "Decoded payload with magic bytes 5a5e5e55"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a5e5e55"
        confidence = "high"

    strings:
        $magic = { 5a 5e 5e 55 }

    condition:
        $magic
}

rule Payload_Magic_5a606362 {
    meta:
        description = "Decoded payload with magic bytes 5a606362"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "5a606362"
        confidence = "high"

    strings:
        $magic = { 5a 60 63 62 }

    condition:
        $magic
}

rule Payload_Magic_5a676d6e {
    meta:
        description = "Decoded payload with magic bytes 5a676d6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a676d6e"
        confidence = "high"

    strings:
        $magic = { 5a 67 6d 6e }

    condition:
        $magic
}

rule Payload_Magic_5a69606f {
    meta:
        description = "Decoded payload with magic bytes 5a69606f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a69606f"
        confidence = "high"

    strings:
        $magic = { 5a 69 60 6f }

    condition:
        $magic
}

rule Payload_Magic_5a697575 {
    meta:
        description = "Decoded payload with magic bytes 5a697575"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a697575"
        confidence = "high"

    strings:
        $magic = { 5a 69 75 75 }

    condition:
        $magic
}

rule Payload_Magic_5a737260 {
    meta:
        description = "Decoded payload with magic bytes 5a737260"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a737260"
        confidence = "high"

    strings:
        $magic = { 5a 73 72 60 }

    condition:
        $magic
}

rule Payload_Magic_5a75686c {
    meta:
        description = "Decoded payload with magic bytes 5a75686c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5a75686c"
        confidence = "high"

    strings:
        $magic = { 5a 75 68 6c }

    condition:
        $magic
}

rule Payload_Magic_5b5e4a4f {
    meta:
        description = "Decoded payload with magic bytes 5b5e4a4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "multi-family"
        magic_bytes = "5b5e4a4f"
        confidence = "high"

    strings:
        $magic = { 5b 5e 4a 4f }

    condition:
        $magic
}

rule Payload_Magic_5c5c5e54 {
    meta:
        description = "Decoded payload with magic bytes 5c5c5e54"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "5c5c5e54"
        confidence = "high"

    strings:
        $magic = { 5c 5c 5e 54 }

    condition:
        $magic
}

rule Payload_Magic_5c5d5253 {
    meta:
        description = "Decoded payload with magic bytes 5c5d5253"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5c5d5253"
        confidence = "high"

    strings:
        $magic = { 5c 5d 52 53 }

    condition:
        $magic
}

rule Payload_Magic_5c5d5a5b {
    meta:
        description = "Decoded payload with magic bytes 5c5d5a5b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5c5d5a5b"
        confidence = "high"

    strings:
        $magic = { 5c 5d 5a 5b }

    condition:
        $magic
}

rule Payload_Magic_5c5d5e5f {
    meta:
        description = "Decoded payload with magic bytes 5c5d5e5f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "5c5d5e5f"
        confidence = "high"

    strings:
        $magic = { 5c 5d 5e 5f }

    condition:
        $magic
}

rule Payload_Magic_5d4b424b {
    meta:
        description = "Decoded payload with magic bytes 5d4b424b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "multi-family"
        magic_bytes = "5d4b424b"
        confidence = "high"

    strings:
        $magic = { 5d 4b 42 4b }

    condition:
        $magic
}

rule Payload_Magic_5d5a5b40 {
    meta:
        description = "Decoded payload with magic bytes 5d5a5b40"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5d5a5b40"
        confidence = "high"

    strings:
        $magic = { 5d 5a 5b 40 }

    condition:
        $magic
}

rule Payload_Magic_5d632979 {
    meta:
        description = "Decoded payload with magic bytes 5d632979"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5d632979"
        confidence = "high"

    strings:
        $magic = { 5d 63 29 79 }

    condition:
        $magic
}

rule Payload_Magic_5d75d75c {
    meta:
        description = "Decoded payload with magic bytes 5d75d75c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5d75d75c"
        confidence = "high"

    strings:
        $magic = { 5d 75 d7 5c }

    condition:
        $magic
}

rule Payload_Magic_5e522a4f {
    meta:
        description = "Decoded payload with magic bytes 5e522a4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "5e522a4f"
        confidence = "high"

    strings:
        $magic = { 5e 52 2a 4f }

    condition:
        $magic
}

rule Payload_Magic_5e55242f {
    meta:
        description = "Decoded payload with magic bytes 5e55242f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "5e55242f"
        confidence = "high"

    strings:
        $magic = { 5e 55 24 2f }

    condition:
        $magic
}

rule Payload_Magic_5e5b3039 {
    meta:
        description = "Decoded payload with magic bytes 5e5b3039"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5e5b3039"
        confidence = "high"

    strings:
        $magic = { 5e 5b 30 39 }

    condition:
        $magic
}

rule Payload_Magic_5e5b3331 {
    meta:
        description = "Decoded payload with magic bytes 5e5b3331"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b3331"
        confidence = "high"

    strings:
        $magic = { 5e 5b 33 31 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f30 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f30"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "5e5b4f30"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 30 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f32 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f32"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "5e5b4f32"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 32 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f33 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f33"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b4f33"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 33 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f34 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f34"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b4f34"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 34 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f35 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f35"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5e5b4f35"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 35 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f36 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f36"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "5e5b4f36"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 36 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f37 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f37"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5e5b4f37"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 37 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f38 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f38"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "5e5b4f38"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 38 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f39 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f39"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b4f39"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 39 }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f4a {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f4a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        magic_bytes = "5e5b4f4a"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 4a }

    condition:
        $magic
}

rule Payload_Magic_5e5b4f52 {
    meta:
        description = "Decoded payload with magic bytes 5e5b4f52"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "5e5b4f52"
        confidence = "high"

    strings:
        $magic = { 5e 5b 4f 52 }

    condition:
        $magic
}

rule Payload_Magic_5e5b5275 {
    meta:
        description = "Decoded payload with magic bytes 5e5b5275"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "5e5b5275"
        confidence = "high"

    strings:
        $magic = { 5e 5b 52 75 }

    condition:
        $magic
}

rule Payload_Magic_5e5b5569 {
    meta:
        description = "Decoded payload with magic bytes 5e5b5569"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b5569"
        confidence = "high"

    strings:
        $magic = { 5e 5b 55 69 }

    condition:
        $magic
}

rule Payload_Magic_5e5b5b4f {
    meta:
        description = "Decoded payload with magic bytes 5e5b5b4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "5e5b5b4f"
        confidence = "high"

    strings:
        $magic = { 5e 5b 5b 4f }

    condition:
        $magic
}

rule Payload_Magic_5e5d2221 {
    meta:
        description = "Decoded payload with magic bytes 5e5d2221"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5e5d2221"
        confidence = "high"

    strings:
        $magic = { 5e 5d 22 21 }

    condition:
        $magic
}

rule Payload_Magic_5e636062 {
    meta:
        description = "Decoded payload with magic bytes 5e636062"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5e636062"
        confidence = "high"

    strings:
        $magic = { 5e 63 60 62 }

    condition:
        $magic
}

rule Payload_Magic_5e657b24 {
    meta:
        description = "Decoded payload with magic bytes 5e657b24"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "5e657b24"
        confidence = "high"

    strings:
        $magic = { 5e 65 7b 24 }

    condition:
        $magic
}

rule Payload_Magic_5f763333 {
    meta:
        description = "Decoded payload with magic bytes 5f763333"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5f763333"
        confidence = "high"

    strings:
        $magic = { 5f 76 33 33 }

    condition:
        $magic
}

rule Payload_Magic_5f9d3d57 {
    meta:
        description = "Decoded payload with magic bytes 5f9d3d57"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3d57"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d 57 }

    condition:
        $magic
}

rule Payload_Magic_5f9d3d6a {
    meta:
        description = "Decoded payload with magic bytes 5f9d3d6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3d6a"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d 6a }

    condition:
        $magic
}

rule Payload_Magic_5f9d3dbf {
    meta:
        description = "Decoded payload with magic bytes 5f9d3dbf"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3dbf"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d bf }

    condition:
        $magic
}

rule Payload_Magic_5f9d3dfc {
    meta:
        description = "Decoded payload with magic bytes 5f9d3dfc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3dfc"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d fc }

    condition:
        $magic
}

rule Payload_Magic_5f9d3dfd {
    meta:
        description = "Decoded payload with magic bytes 5f9d3dfd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3dfd"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d fd }

    condition:
        $magic
}

rule Payload_Magic_5f9d3dfe {
    meta:
        description = "Decoded payload with magic bytes 5f9d3dfe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "5f9d3dfe"
        confidence = "high"

    strings:
        $magic = { 5f 9d 3d fe }

    condition:
        $magic
}

rule Payload_Magic_5fe1edb6 {
    meta:
        description = "Decoded payload with magic bytes 5fe1edb6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "5fe1edb6"
        confidence = "high"

    strings:
        $magic = { 5f e1 ed b6 }

    condition:
        $magic
}

rule Payload_Magic_60214568 {
    meta:
        description = "Decoded payload with magic bytes 60214568"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "60214568"
        confidence = "high"

    strings:
        $magic = { 60 21 45 68 }

    condition:
        $magic
}

rule Payload_Magic_60217264 {
    meta:
        description = "Decoded payload with magic bytes 60217264"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "60217264"
        confidence = "high"

    strings:
        $magic = { 60 21 72 64 }

    condition:
        $magic
}

rule Payload_Magic_60636265 {
    meta:
        description = "Decoded payload with magic bytes 60636265"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "multi-family"
        magic_bytes = "60636265"
        confidence = "high"

    strings:
        $magic = { 60 63 62 65 }

    condition:
        $magic
}

rule Payload_Magic_60696460 {
    meta:
        description = "Decoded payload with magic bytes 60696460"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "60696460"
        confidence = "high"

    strings:
        $magic = { 60 69 64 60 }

    condition:
        $magic
}

rule Payload_Magic_60727264 {
    meta:
        description = "Decoded payload with magic bytes 60727264"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "60727264"
        confidence = "high"

    strings:
        $magic = { 60 72 72 64 }

    condition:
        $magic
}

rule Payload_Magic_60757564 {
    meta:
        description = "Decoded payload with magic bytes 60757564"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "60757564"
        confidence = "high"

    strings:
        $magic = { 60 75 75 64 }

    condition:
        $magic
}

rule Payload_Magic_61406d6d {
    meta:
        description = "Decoded payload with magic bytes 61406d6d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "61406d6d"
        confidence = "high"

    strings:
        $magic = { 61 40 6d 6d }

    condition:
        $magic
}

rule Payload_Magic_61606b76 {
    meta:
        description = "Decoded payload with magic bytes 61606b76"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "61606b76"
        confidence = "high"

    strings:
        $magic = { 61 60 6b 76 }

    condition:
        $magic
}

rule Payload_Magic_61636d6e {
    meta:
        description = "Decoded payload with magic bytes 61636d6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "61636d6e"
        confidence = "high"

    strings:
        $magic = { 61 63 6d 6e }

    condition:
        $magic
}

rule Payload_Magic_616e6472 {
    meta:
        description = "Decoded payload with magic bytes 616e6472"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "616e6472"
        confidence = "high"

    strings:
        $magic = { 61 6e 64 72 }

    condition:
        $magic
}

rule Payload_Magic_61746564 {
    meta:
        description = "Decoded payload with magic bytes 61746564"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "61746564"
        confidence = "high"

    strings:
        $magic = { 61 74 65 64 }

    condition:
        $magic
}

rule Payload_Magic_617c6769 {
    meta:
        description = "Decoded payload with magic bytes 617c6769"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "617c6769"
        confidence = "high"

    strings:
        $magic = { 61 7c 67 69 }

    condition:
        $magic
}

rule Payload_Magic_61856b1c {
    meta:
        description = "Decoded payload with magic bytes 61856b1c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "61856b1c"
        confidence = "high"

    strings:
        $magic = { 61 85 6b 1c }

    condition:
        $magic
}

rule Payload_Magic_626c606a {
    meta:
        description = "Decoded payload with magic bytes 626c606a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "626c606a"
        confidence = "high"

    strings:
        $magic = { 62 6c 60 6a }

    condition:
        $magic
}

rule Payload_Magic_626d606f {
    meta:
        description = "Decoded payload with magic bytes 626d606f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "626d606f"
        confidence = "high"

    strings:
        $magic = { 62 6d 60 6f }

    condition:
        $magic
}

rule Payload_Magic_626e6f72 {
    meta:
        description = "Decoded payload with magic bytes 626e6f72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "626e6f72"
        confidence = "high"

    strings:
        $magic = { 62 6e 6f 72 }

    condition:
        $magic
}

rule Payload_Magic_63464762 {
    meta:
        description = "Decoded payload with magic bytes 63464762"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "63464762"
        confidence = "high"

    strings:
        $magic = { 63 46 47 62 }

    condition:
        $magic
}

rule Payload_Magic_63606166 {
    meta:
        description = "Decoded payload with magic bytes 63606166"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "63606166"
        confidence = "high"

    strings:
        $magic = { 63 60 61 66 }

    condition:
        $magic
}

rule Payload_Magic_63607372 {
    meta:
        description = "Decoded payload with magic bytes 63607372"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "63607372"
        confidence = "high"

    strings:
        $magic = { 63 60 73 72 }

    condition:
        $magic
}

rule Payload_Magic_636d7b7c {
    meta:
        description = "Decoded payload with magic bytes 636d7b7c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        magic_bytes = "636d7b7c"
        confidence = "high"

    strings:
        $magic = { 63 6d 7b 7c }

    condition:
        $magic
}

rule Payload_Magic_636f6d2e {
    meta:
        description = "Decoded payload with magic bytes 636f6d2e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        magic_bytes = "636f6d2e"
        confidence = "high"

    strings:
        $magic = { 63 6f 6d 2e }

    condition:
        $magic
}

rule Payload_Magic_6374663b {
    meta:
        description = "Decoded payload with magic bytes 6374663b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6374663b"
        confidence = "high"

    strings:
        $magic = { 63 74 66 3b }

    condition:
        $magic
}

rule Payload_Magic_6374686d {
    meta:
        description = "Decoded payload with magic bytes 6374686d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6374686d"
        confidence = "high"

    strings:
        $magic = { 63 74 68 6d }

    condition:
        $magic
}

rule Payload_Magic_63776462 {
    meta:
        description = "Decoded payload with magic bytes 63776462"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "63776462"
        confidence = "high"

    strings:
        $magic = { 63 77 64 62 }

    condition:
        $magic
}

rule Payload_Magic_64616c76 {
    meta:
        description = "Decoded payload with magic bytes 64616c76"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "64616c76"
        confidence = "high"

    strings:
        $magic = { 64 61 6c 76 }

    condition:
        $magic
}

rule Payload_Magic_65607560 {
    meta:
        description = "Decoded payload with magic bytes 65607560"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "65607560"
        confidence = "high"

    strings:
        $magic = { 65 60 75 60 }

    condition:
        $magic
}

rule Payload_Magic_65646d64 {
    meta:
        description = "Decoded payload with magic bytes 65646d64"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        magic_bytes = "65646d64"
        confidence = "high"

    strings:
        $magic = { 65 64 6d 64 }

    condition:
        $magic
}

rule Payload_Magic_656e456e {
    meta:
        description = "Decoded payload with magic bytes 656e456e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "656e456e"
        confidence = "high"

    strings:
        $magic = { 65 6e 45 6e }

    condition:
        $magic
}

rule Payload_Magic_656e6472 {
    meta:
        description = "Decoded payload with magic bytes 656e6472"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "656e6472"
        confidence = "high"

    strings:
        $magic = { 65 6e 64 72 }

    condition:
        $magic
}

rule Payload_Magic_6574606d {
    meta:
        description = "Decoded payload with magic bytes 6574606d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6574606d"
        confidence = "high"

    strings:
        $magic = { 65 74 60 6d }

    condition:
        $magic
}

rule Payload_Magic_66626221 {
    meta:
        description = "Decoded payload with magic bytes 66626221"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "66626221"
        confidence = "high"

    strings:
        $magic = { 66 62 62 21 }

    condition:
        $magic
}

rule Payload_Magic_67323232 {
    meta:
        description = "Decoded payload with magic bytes 67323232"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "67323232"
        confidence = "high"

    strings:
        $magic = { 67 32 32 32 }

    condition:
        $magic
}

rule Payload_Magic_67584c41 {
    meta:
        description = "Decoded payload with magic bytes 67584c41"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "67584c41"
        confidence = "high"

    strings:
        $magic = { 67 58 4c 41 }

    condition:
        $magic
}

rule Payload_Magic_676d6e60 {
    meta:
        description = "Decoded payload with magic bytes 676d6e60"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "676d6e60"
        confidence = "high"

    strings:
        $magic = { 67 6d 6e 60 }

    condition:
        $magic
}

rule Payload_Magic_676e7321 {
    meta:
        description = "Decoded payload with magic bytes 676e7321"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "676e7321"
        confidence = "high"

    strings:
        $magic = { 67 6e 73 21 }

    condition:
        $magic
}

rule Payload_Magic_67707567 {
    meta:
        description = "Decoded payload with magic bytes 67707567"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "67707567"
        confidence = "high"

    strings:
        $magic = { 67 70 75 67 }

    condition:
        $magic
}

rule Payload_Magic_6779605e {
    meta:
        description = "Decoded payload with magic bytes 6779605e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6779605e"
        confidence = "high"

    strings:
        $magic = { 67 79 60 5e }

    condition:
        $magic
}

rule Payload_Magic_677c302b {
    meta:
        description = "Decoded payload with magic bytes 677c302b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "677c302b"
        confidence = "high"

    strings:
        $magic = { 67 7c 30 2b }

    condition:
        $magic
}

rule Payload_Magic_6857434e {
    meta:
        description = "Decoded payload with magic bytes 6857434e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "6857434e"
        confidence = "high"

    strings:
        $magic = { 68 57 43 4e }

    condition:
        $magic
}

rule Payload_Magic_68637463 {
    meta:
        description = "Decoded payload with magic bytes 68637463"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "68637463"
        confidence = "high"

    strings:
        $magic = { 68 63 74 63 }

    condition:
        $magic
}

rule Payload_Magic_68672129 {
    meta:
        description = "Decoded payload with magic bytes 68672129"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "68672129"
        confidence = "high"

    strings:
        $magic = { 68 67 21 29 }

    condition:
        $magic
}

rule Payload_Magic_686f7264 {
    meta:
        description = "Decoded payload with magic bytes 686f7264"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "686f7264"
        confidence = "high"

    strings:
        $magic = { 68 6f 72 64 }

    condition:
        $magic
}

rule Payload_Magic_686f7564 {
    meta:
        description = "Decoded payload with magic bytes 686f7564"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "686f7564"
        confidence = "high"

    strings:
        $magic = { 68 6f 75 64 }

    condition:
        $magic
}

rule Payload_Magic_6872556e {
    meta:
        description = "Decoded payload with magic bytes 6872556e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6872556e"
        confidence = "high"

    strings:
        $magic = { 68 72 55 6e }

    condition:
        $magic
}

rule Payload_Magic_68747470 {
    meta:
        description = "Decoded payload with magic bytes 68747470"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "68747470"
        confidence = "high"

    strings:
        $magic = { 68 74 74 70 }

    condition:
        $magic
}

rule Payload_Magic_69206d20 {
    meta:
        description = "Decoded payload with magic bytes 69206d20"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69206d20"
        confidence = "high"

    strings:
        $magic = { 69 20 6d 20 }

    condition:
        $magic
}

rule Payload_Magic_69606f65 {
    meta:
        description = "Decoded payload with magic bytes 69606f65"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "69606f65"
        confidence = "high"

    strings:
        $magic = { 69 60 6f 65 }

    condition:
        $magic
}

rule Payload_Magic_69682120 {
    meta:
        description = "Decoded payload with magic bytes 69682120"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69682120"
        confidence = "high"

    strings:
        $magic = { 69 68 21 20 }

    condition:
        $magic
}

rule Payload_Magic_69686669 {
    meta:
        description = "Decoded payload with magic bytes 69686669"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69686669"
        confidence = "high"

    strings:
        $magic = { 69 68 66 69 }

    condition:
        $magic
}

rule Payload_Magic_696d6560 {
    meta:
        description = "Decoded payload with magic bytes 696d6560"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "696d6560"
        confidence = "high"

    strings:
        $magic = { 69 6d 65 60 }

    condition:
        $magic
}

rule Payload_Magic_69757571 {
    meta:
        description = "Decoded payload with magic bytes 69757571"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "8"
        family = "multi-family"
        magic_bytes = "69757571"
        confidence = "high"

    strings:
        $magic = { 69 75 75 71 }

    condition:
        $magic
}

rule Payload_Magic_69af3b71 {
    meta:
        description = "Decoded payload with magic bytes 69af3b71"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69af3b71"
        confidence = "high"

    strings:
        $magic = { 69 af 3b 71 }

    condition:
        $magic
}

rule Payload_Magic_69b71d79 {
    meta:
        description = "Decoded payload with magic bytes 69b71d79"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69b71d79"
        confidence = "high"

    strings:
        $magic = { 69 b7 1d 79 }

    condition:
        $magic
}

rule Payload_Magic_69c71eb2 {
    meta:
        description = "Decoded payload with magic bytes 69c71eb2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "69c71eb2"
        confidence = "high"

    strings:
        $magic = { 69 c7 1e b2 }

    condition:
        $magic
}

rule Payload_Magic_69c728ba {
    meta:
        description = "Decoded payload with magic bytes 69c728ba"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "69c728ba"
        confidence = "high"

    strings:
        $magic = { 69 c7 28 ba }

    condition:
        $magic
}

rule Payload_Magic_69c7a29e {
    meta:
        description = "Decoded payload with magic bytes 69c7a29e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "69c7a29e"
        confidence = "high"

    strings:
        $magic = { 69 c7 a2 9e }

    condition:
        $magic
}

rule Payload_Magic_69d753ad {
    meta:
        description = "Decoded payload with magic bytes 69d753ad"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "69d753ad"
        confidence = "high"

    strings:
        $magic = { 69 d7 53 ad }

    condition:
        $magic
}

rule Payload_Magic_69eb3ed7 {
    meta:
        description = "Decoded payload with magic bytes 69eb3ed7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "69eb3ed7"
        confidence = "high"

    strings:
        $magic = { 69 eb 3e d7 }

    condition:
        $magic
}

rule Payload_Magic_69eb3edb {
    meta:
        description = "Decoded payload with magic bytes 69eb3edb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "69eb3edb"
        confidence = "high"

    strings:
        $magic = { 69 eb 3e db }

    condition:
        $magic
}

rule Payload_Magic_6a55414c {
    meta:
        description = "Decoded payload with magic bytes 6a55414c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6a55414c"
        confidence = "high"

    strings:
        $magic = { 6a 55 41 4c }

    condition:
        $magic
}

rule Payload_Magic_6a5968c0 {
    meta:
        description = "Decoded payload with magic bytes 6a5968c0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6a5968c0"
        confidence = "high"

    strings:
        $magic = { 6a 59 68 c0 }

    condition:
        $magic
}

rule Payload_Magic_6a5968c1 {
    meta:
        description = "Decoded payload with magic bytes 6a5968c1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6a5968c1"
        confidence = "high"

    strings:
        $magic = { 6a 59 68 c1 }

    condition:
        $magic
}

rule Payload_Magic_6a617661 {
    meta:
        description = "Decoded payload with magic bytes 6a617661"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6a617661"
        confidence = "high"

    strings:
        $magic = { 6a 61 76 61 }

    condition:
        $magic
}

rule Payload_Magic_6a776ba2 {
    meta:
        description = "Decoded payload with magic bytes 6a776ba2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "6a776ba2"
        confidence = "high"

    strings:
        $magic = { 6a 77 6b a2 }

    condition:
        $magic
}

rule Payload_Magic_6a97b51c {
    meta:
        description = "Decoded payload with magic bytes 6a97b51c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6a97b51c"
        confidence = "high"

    strings:
        $magic = { 6a 97 b5 1c }

    condition:
        $magic
}

rule Payload_Magic_6abb7faa {
    meta:
        description = "Decoded payload with magic bytes 6abb7faa"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "6abb7faa"
        confidence = "high"

    strings:
        $magic = { 6a bb 7f aa }

    condition:
        $magic
}

rule Payload_Magic_6ac9f5fe {
    meta:
        description = "Decoded payload with magic bytes 6ac9f5fe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "6ac9f5fe"
        confidence = "high"

    strings:
        $magic = { 6a c9 f5 fe }

    condition:
        $magic
}

rule Payload_Magic_6aeb61a2 {
    meta:
        description = "Decoded payload with magic bytes 6aeb61a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "6aeb61a2"
        confidence = "high"

    strings:
        $magic = { 6a eb 61 a2 }

    condition:
        $magic
}

rule Payload_Magic_6aeb6872 {
    meta:
        description = "Decoded payload with magic bytes 6aeb6872"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6aeb6872"
        confidence = "high"

    strings:
        $magic = { 6a eb 68 72 }

    condition:
        $magic
}

rule Payload_Magic_6af6ad6a {
    meta:
        description = "Decoded payload with magic bytes 6af6ad6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6af6ad6a"
        confidence = "high"

    strings:
        $magic = { 6a f6 ad 6a }

    condition:
        $magic
}

rule Payload_Magic_6b607760 {
    meta:
        description = "Decoded payload with magic bytes 6b607760"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "multi-family"
        magic_bytes = "6b607760"
        confidence = "high"

    strings:
        $magic = { 6b 60 77 60 }

    condition:
        $magic
}

rule Payload_Magic_6b786b60 {
    meta:
        description = "Decoded payload with magic bytes 6b786b60"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6b786b60"
        confidence = "high"

    strings:
        $magic = { 6b 78 6b 60 }

    condition:
        $magic
}

rule Payload_Magic_6bad7f03 {
    meta:
        description = "Decoded payload with magic bytes 6bad7f03"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "6bad7f03"
        confidence = "high"

    strings:
        $magic = { 6b ad 7f 03 }

    condition:
        $magic
}

rule Payload_Magic_6c456464 {
    meta:
        description = "Decoded payload with magic bytes 6c456464"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6c456464"
        confidence = "high"

    strings:
        $magic = { 6c 45 64 64 }

    condition:
        $magic
}

rule Payload_Magic_6c632d24 {
    meta:
        description = "Decoded payload with magic bytes 6c632d24"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "6c632d24"
        confidence = "high"

    strings:
        $magic = { 6c 63 2d 24 }

    condition:
        $magic
}

rule Payload_Magic_6c682c3f {
    meta:
        description = "Decoded payload with magic bytes 6c682c3f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6c682c3f"
        confidence = "high"

    strings:
        $magic = { 6c 68 2c 3f }

    condition:
        $magic
}

rule Payload_Magic_6c6e6368 {
    meta:
        description = "Decoded payload with magic bytes 6c6e6368"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6c6e6368"
        confidence = "high"

    strings:
        $magic = { 6c 6e 63 68 }

    condition:
        $magic
}

rule Payload_Magic_6c6e746f {
    meta:
        description = "Decoded payload with magic bytes 6c6e746f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6c6e746f"
        confidence = "high"

    strings:
        $magic = { 6c 6e 74 6f }

    condition:
        $magic
}

rule Payload_Magic_6c70606f {
    meta:
        description = "Decoded payload with magic bytes 6c70606f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6c70606f"
        confidence = "high"

    strings:
        $magic = { 6c 70 60 6f }

    condition:
        $magic
}

rule Payload_Magic_6c776e6e {
    meta:
        description = "Decoded payload with magic bytes 6c776e6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6c776e6e"
        confidence = "high"

    strings:
        $magic = { 6c 77 6e 6e }

    condition:
        $magic
}

rule Payload_Magic_6d656071 {
    meta:
        description = "Decoded payload with magic bytes 6d656071"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6d656071"
        confidence = "high"

    strings:
        $magic = { 6d 65 60 71 }

    condition:
        $magic
}

rule Payload_Magic_6d6e6633 {
    meta:
        description = "Decoded payload with magic bytes 6d6e6633"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6d6e6633"
        confidence = "high"

    strings:
        $magic = { 6d 6e 66 33 }

    condition:
        $magic
}

rule Payload_Magic_6da72482 {
    meta:
        description = "Decoded payload with magic bytes 6da72482"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6da72482"
        confidence = "high"

    strings:
        $magic = { 6d a7 24 82 }

    condition:
        $magic
}

rule Payload_Magic_6dbf39eb {
    meta:
        description = "Decoded payload with magic bytes 6dbf39eb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6dbf39eb"
        confidence = "high"

    strings:
        $magic = { 6d bf 39 eb }

    condition:
        $magic
}

rule Payload_Magic_6e29dd3e {
    meta:
        description = "Decoded payload with magic bytes 6e29dd3e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6e29dd3e"
        confidence = "high"

    strings:
        $magic = { 6e 29 dd 3e }

    condition:
        $magic
}

rule Payload_Magic_6e2c6260 {
    meta:
        description = "Decoded payload with magic bytes 6e2c6260"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6e2c6260"
        confidence = "high"

    strings:
        $magic = { 6e 2c 62 60 }

    condition:
        $magic
}

rule Payload_Magic_6e456479 {
    meta:
        description = "Decoded payload with magic bytes 6e456479"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6e456479"
        confidence = "high"

    strings:
        $magic = { 6e 45 64 79 }

    condition:
        $magic
}

rule Payload_Magic_6e4b6274 {
    meta:
        description = "Decoded payload with magic bytes 6e4b6274"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "6e4b6274"
        confidence = "high"

    strings:
        $magic = { 6e 4b 62 74 }

    condition:
        $magic
}

rule Payload_Magic_6e6f5364 {
    meta:
        description = "Decoded payload with magic bytes 6e6f5364"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "6e6f5364"
        confidence = "high"

    strings:
        $magic = { 6e 6f 53 64 }

    condition:
        $magic
}

rule Payload_Magic_6e6f7071 {
    meta:
        description = "Decoded payload with magic bytes 6e6f7071"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "6e6f7071"
        confidence = "high"

    strings:
        $magic = { 6e 6f 70 71 }

    condition:
        $magic
}

rule Payload_Magic_6f46f8e3 {
    meta:
        description = "Decoded payload with magic bytes 6f46f8e3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6f46f8e3"
        confidence = "high"

    strings:
        $magic = { 6f 46 f8 e3 }

    condition:
        $magic
}

rule Payload_Magic_6f647364 {
    meta:
        description = "Decoded payload with magic bytes 6f647364"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "6f647364"
        confidence = "high"

    strings:
        $magic = { 6f 64 73 64 }

    condition:
        $magic
}

rule Payload_Magic_6f6d6560 {
    meta:
        description = "Decoded payload with magic bytes 6f6d6560"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6f6d6560"
        confidence = "high"

    strings:
        $magic = { 6f 6d 65 60 }

    condition:
        $magic
}

rule Payload_Magic_6f77dbdf {
    meta:
        description = "Decoded payload with magic bytes 6f77dbdf"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6f77dbdf"
        confidence = "high"

    strings:
        $magic = { 6f 77 db df }

    condition:
        $magic
}

rule Payload_Magic_6f7df5d9 {
    meta:
        description = "Decoded payload with magic bytes 6f7df5d9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6f7df5d9"
        confidence = "high"

    strings:
        $magic = { 6f 7d f5 d9 }

    condition:
        $magic
}

rule Payload_Magic_6fc69d7f {
    meta:
        description = "Decoded payload with magic bytes 6fc69d7f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6fc69d7f"
        confidence = "high"

    strings:
        $magic = { 6f c6 9d 7f }

    condition:
        $magic
}

rule Payload_Magic_6fcebd73 {
    meta:
        description = "Decoded payload with magic bytes 6fcebd73"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "6fcebd73"
        confidence = "high"

    strings:
        $magic = { 6f ce bd 73 }

    condition:
        $magic
}

rule Payload_Magic_70207320 {
    meta:
        description = "Decoded payload with magic bytes 70207320"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "70207320"
        confidence = "high"

    strings:
        $magic = { 70 20 73 20 }

    condition:
        $magic
}

rule Payload_Magic_71465249 {
    meta:
        description = "Decoded payload with magic bytes 71465249"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "71465249"
        confidence = "high"

    strings:
        $magic = { 71 46 52 49 }

    condition:
        $magic
}

rule Payload_Magic_715e6b33 {
    meta:
        description = "Decoded payload with magic bytes 715e6b33"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "715e6b33"
        confidence = "high"

    strings:
        $magic = { 71 5e 6b 33 }

    condition:
        $magic
}

rule Payload_Magic_71606c62 {
    meta:
        description = "Decoded payload with magic bytes 71606c62"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "71606c62"
        confidence = "high"

    strings:
        $magic = { 71 60 6c 62 }

    condition:
        $magic
}

rule Payload_Magic_71736462 {
    meta:
        description = "Decoded payload with magic bytes 71736462"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.qingk.fdovdtvswosuscouwofotferesxrquer"
        magic_bytes = "71736462"
        confidence = "high"

    strings:
        $magic = { 71 73 64 62 }

    condition:
        $magic
}

rule Payload_Magic_7174636d {
    meta:
        description = "Decoded payload with magic bytes 7174636d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7174636d"
        confidence = "high"

    strings:
        $magic = { 71 74 63 6d }

    condition:
        $magic
}

rule Payload_Magic_71a9654a {
    meta:
        description = "Decoded payload with magic bytes 71a9654a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "71a9654a"
        confidence = "high"

    strings:
        $magic = { 71 a9 65 4a }

    condition:
        $magic
}

rule Payload_Magic_71a9dc7a {
    meta:
        description = "Decoded payload with magic bytes 71a9dc7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "71a9dc7a"
        confidence = "high"

    strings:
        $magic = { 71 a9 dc 7a }

    condition:
        $magic
}

rule Payload_Magic_71eaed89 {
    meta:
        description = "Decoded payload with magic bytes 71eaed89"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "71eaed89"
        confidence = "high"

    strings:
        $magic = { 71 ea ed 89 }

    condition:
        $magic
}

rule Payload_Magic_71eb2c6a {
    meta:
        description = "Decoded payload with magic bytes 71eb2c6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "71eb2c6a"
        confidence = "high"

    strings:
        $magic = { 71 eb 2c 6a }

    condition:
        $magic
}

rule Payload_Magic_71ff3c71 {
    meta:
        description = "Decoded payload with magic bytes 71ff3c71"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "71ff3c71"
        confidence = "high"

    strings:
        $magic = { 71 ff 3c 71 }

    condition:
        $magic
}

rule Payload_Magic_7216ab69 {
    meta:
        description = "Decoded payload with magic bytes 7216ab69"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7216ab69"
        confidence = "high"

    strings:
        $magic = { 72 16 ab 69 }

    condition:
        $magic
}

rule Payload_Magic_72179c92 {
    meta:
        description = "Decoded payload with magic bytes 72179c92"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "72179c92"
        confidence = "high"

    strings:
        $magic = { 72 17 9c 92 }

    condition:
        $magic
}

rule Payload_Magic_722a617a {
    meta:
        description = "Decoded payload with magic bytes 722a617a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "722a617a"
        confidence = "high"

    strings:
        $magic = { 72 2a 61 7a }

    condition:
        $magic
}

rule Payload_Magic_722c3f65 {
    meta:
        description = "Decoded payload with magic bytes 722c3f65"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "722c3f65"
        confidence = "high"

    strings:
        $magic = { 72 2c 3f 65 }

    condition:
        $magic
}

rule Payload_Magic_72627673 {
    meta:
        description = "Decoded payload with magic bytes 72627673"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        magic_bytes = "72627673"
        confidence = "high"

    strings:
        $magic = { 72 62 76 73 }

    condition:
        $magic
}

rule Payload_Magic_72646272 {
    meta:
        description = "Decoded payload with magic bytes 72646272"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "72646272"
        confidence = "high"

    strings:
        $magic = { 72 64 62 72 }

    condition:
        $magic
}

rule Payload_Magic_7264754d {
    meta:
        description = "Decoded payload with magic bytes 7264754d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7264754d"
        confidence = "high"

    strings:
        $magic = { 72 64 75 4d }

    condition:
        $magic
}

rule Payload_Magic_72696073 {
    meta:
        description = "Decoded payload with magic bytes 72696073"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "72696073"
        confidence = "high"

    strings:
        $magic = { 72 69 60 73 }

    condition:
        $magic
}

rule Payload_Magic_72747164 {
    meta:
        description = "Decoded payload with magic bytes 72747164"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "72747164"
        confidence = "high"

    strings:
        $magic = { 72 74 71 64 }

    condition:
        $magic
}

rule Payload_Magic_72756073 {
    meta:
        description = "Decoded payload with magic bytes 72756073"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "72756073"
        confidence = "high"

    strings:
        $magic = { 72 75 60 73 }

    condition:
        $magic
}

rule Payload_Magic_72776277 {
    meta:
        description = "Decoded payload with magic bytes 72776277"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "72776277"
        confidence = "high"

    strings:
        $magic = { 72 77 62 77 }

    condition:
        $magic
}

rule Payload_Magic_7277765d {
    meta:
        description = "Decoded payload with magic bytes 7277765d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7277765d"
        confidence = "high"

    strings:
        $magic = { 72 77 76 5d }

    condition:
        $magic
}

rule Payload_Magic_7289bfb2 {
    meta:
        description = "Decoded payload with magic bytes 7289bfb2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7289bfb2"
        confidence = "high"

    strings:
        $magic = { 72 89 bf b2 }

    condition:
        $magic
}

rule Payload_Magic_7289bfb5 {
    meta:
        description = "Decoded payload with magic bytes 7289bfb5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "7289bfb5"
        confidence = "high"

    strings:
        $magic = { 72 89 bf b5 }

    condition:
        $magic
}

rule Payload_Magic_72ba2cb0 {
    meta:
        description = "Decoded payload with magic bytes 72ba2cb0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "72ba2cb0"
        confidence = "high"

    strings:
        $magic = { 72 ba 2c b0 }

    condition:
        $magic
}

rule Payload_Magic_73606f66 {
    meta:
        description = "Decoded payload with magic bytes 73606f66"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "73606f66"
        confidence = "high"

    strings:
        $magic = { 73 60 6f 66 }

    condition:
        $magic
}

rule Payload_Magic_73647074 {
    meta:
        description = "Decoded payload with magic bytes 73647074"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "73647074"
        confidence = "high"

    strings:
        $magic = { 73 64 70 74 }

    condition:
        $magic
}

rule Payload_Magic_73686669 {
    meta:
        description = "Decoded payload with magic bytes 73686669"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "73686669"
        confidence = "high"

    strings:
        $magic = { 73 68 66 69 }

    condition:
        $magic
}

rule Payload_Magic_737e6670 {
    meta:
        description = "Decoded payload with magic bytes 737e6670"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "737e6670"
        confidence = "high"

    strings:
        $magic = { 73 7e 66 70 }

    condition:
        $magic
}

rule Payload_Magic_737f5ce9 {
    meta:
        description = "Decoded payload with magic bytes 737f5ce9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "737f5ce9"
        confidence = "high"

    strings:
        $magic = { 73 7f 5c e9 }

    condition:
        $magic
}

rule Payload_Magic_746f6867 {
    meta:
        description = "Decoded payload with magic bytes 746f6867"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "746f6867"
        confidence = "high"

    strings:
        $magic = { 74 6f 68 67 }

    condition:
        $magic
}

rule Payload_Magic_74716560 {
    meta:
        description = "Decoded payload with magic bytes 74716560"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "74716560"
        confidence = "high"

    strings:
        $magic = { 74 71 65 60 }

    condition:
        $magic
}

rule Payload_Magic_75216960 {
    meta:
        description = "Decoded payload with magic bytes 75216960"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "75216960"
        confidence = "high"

    strings:
        $magic = { 75 21 69 60 }

    condition:
        $magic
}

rule Payload_Magic_75647975 {
    meta:
        description = "Decoded payload with magic bytes 75647975"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "75647975"
        confidence = "high"

    strings:
        $magic = { 75 64 79 75 }

    condition:
        $magic
}

rule Payload_Magic_756c7177 {
    meta:
        description = "Decoded payload with magic bytes 756c7177"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "756c7177"
        confidence = "high"

    strings:
        $magic = { 75 6c 71 77 }

    condition:
        $magic
}

rule Payload_Magic_7573606f {
    meta:
        description = "Decoded payload with magic bytes 7573606f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7573606f"
        confidence = "high"

    strings:
        $magic = { 75 73 60 6f }

    condition:
        $magic
}

rule Payload_Magic_75a96f8a {
    meta:
        description = "Decoded payload with magic bytes 75a96f8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "75a96f8a"
        confidence = "high"

    strings:
        $magic = { 75 a9 6f 8a }

    condition:
        $magic
}

rule Payload_Magic_75e734d7 {
    meta:
        description = "Decoded payload with magic bytes 75e734d7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "75e734d7"
        confidence = "high"

    strings:
        $magic = { 75 e7 34 d7 }

    condition:
        $magic
}

rule Payload_Magic_75eb2d8a {
    meta:
        description = "Decoded payload with magic bytes 75eb2d8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "75eb2d8a"
        confidence = "high"

    strings:
        $magic = { 75 eb 2d 8a }

    condition:
        $magic
}

rule Payload_Magic_75ec42ad {
    meta:
        description = "Decoded payload with magic bytes 75ec42ad"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "75ec42ad"
        confidence = "high"

    strings:
        $magic = { 75 ec 42 ad }

    condition:
        $magic
}

rule Payload_Magic_7614a29e {
    meta:
        description = "Decoded payload with magic bytes 7614a29e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7614a29e"
        confidence = "high"

    strings:
        $magic = { 76 14 a2 9e }

    condition:
        $magic
}

rule Payload_Magic_762b296a {
    meta:
        description = "Decoded payload with magic bytes 762b296a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "762b296a"
        confidence = "high"

    strings:
        $magic = { 76 2b 29 6a }

    condition:
        $magic
}

rule Payload_Magic_762b2995 {
    meta:
        description = "Decoded payload with magic bytes 762b2995"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "762b2995"
        confidence = "high"

    strings:
        $magic = { 76 2b 29 95 }

    condition:
        $magic
}

rule Payload_Magic_768c27fe {
    meta:
        description = "Decoded payload with magic bytes 768c27fe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "768c27fe"
        confidence = "high"

    strings:
        $magic = { 76 8c 27 fe }

    condition:
        $magic
}

rule Payload_Magic_7763735e {
    meta:
        description = "Decoded payload with magic bytes 7763735e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7763735e"
        confidence = "high"

    strings:
        $magic = { 77 63 73 5e }

    condition:
        $magic
}

rule Payload_Magic_77674835 {
    meta:
        description = "Decoded payload with magic bytes 77674835"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "77674835"
        confidence = "high"

    strings:
        $magic = { 77 67 48 35 }

    condition:
        $magic
}

rule Payload_Magic_7768bf00 {
    meta:
        description = "Decoded payload with magic bytes 7768bf00"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf00"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 00 }

    condition:
        $magic
}

rule Payload_Magic_7768bf01 {
    meta:
        description = "Decoded payload with magic bytes 7768bf01"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf01"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 01 }

    condition:
        $magic
}

rule Payload_Magic_7768bf08 {
    meta:
        description = "Decoded payload with magic bytes 7768bf08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf08"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 08 }

    condition:
        $magic
}

rule Payload_Magic_7768bf11 {
    meta:
        description = "Decoded payload with magic bytes 7768bf11"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf11"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 11 }

    condition:
        $magic
}

rule Payload_Magic_7768bf21 {
    meta:
        description = "Decoded payload with magic bytes 7768bf21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf21"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 21 }

    condition:
        $magic
}

rule Payload_Magic_7768bf38 {
    meta:
        description = "Decoded payload with magic bytes 7768bf38"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf38"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 38 }

    condition:
        $magic
}

rule Payload_Magic_7768bf3c {
    meta:
        description = "Decoded payload with magic bytes 7768bf3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7768bf3c"
        confidence = "high"

    strings:
        $magic = { 77 68 bf 3c }

    condition:
        $magic
}

rule Payload_Magic_776e6865 {
    meta:
        description = "Decoded payload with magic bytes 776e6865"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "776e6865"
        confidence = "high"

    strings:
        $magic = { 77 6e 68 65 }

    condition:
        $magic
}

rule Payload_Magic_77772e64 {
    meta:
        description = "Decoded payload with magic bytes 77772e64"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "77772e64"
        confidence = "high"

    strings:
        $magic = { 77 77 2e 64 }

    condition:
        $magic
}

rule Payload_Magic_78dc0e54 {
    meta:
        description = "Decoded payload with magic bytes 78dc0e54"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "78dc0e54"
        confidence = "high"

    strings:
        $magic = { 78 dc 0e 54 }

    condition:
        $magic
}

rule Payload_Magic_795e5750 {
    meta:
        description = "Decoded payload with magic bytes 795e5750"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "795e5750"
        confidence = "high"

    strings:
        $magic = { 79 5e 57 50 }

    condition:
        $magic
}

rule Payload_Magic_7972683b {
    meta:
        description = "Decoded payload with magic bytes 7972683b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7972683b"
        confidence = "high"

    strings:
        $magic = { 79 72 68 3b }

    condition:
        $magic
}

rule Payload_Magic_79c76c6b {
    meta:
        description = "Decoded payload with magic bytes 79c76c6b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "79c76c6b"
        confidence = "high"

    strings:
        $magic = { 79 c7 6c 6b }

    condition:
        $magic
}

rule Payload_Magic_7a5d2364 {
    meta:
        description = "Decoded payload with magic bytes 7a5d2364"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7a5d2364"
        confidence = "high"

    strings:
        $magic = { 7a 5d 23 64 }

    condition:
        $magic
}

rule Payload_Magic_7a6a6dcb {
    meta:
        description = "Decoded payload with magic bytes 7a6a6dcb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7a6a6dcb"
        confidence = "high"

    strings:
        $magic = { 7a 6a 6d cb }

    condition:
        $magic
}

rule Payload_Magic_7a769b95 {
    meta:
        description = "Decoded payload with magic bytes 7a769b95"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "7a769b95"
        confidence = "high"

    strings:
        $magic = { 7a 76 9b 95 }

    condition:
        $magic
}

rule Payload_Magic_7a78229d {
    meta:
        description = "Decoded payload with magic bytes 7a78229d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7a78229d"
        confidence = "high"

    strings:
        $magic = { 7a 78 22 9d }

    condition:
        $magic
}

rule Payload_Magic_7a797473 {
    meta:
        description = "Decoded payload with magic bytes 7a797473"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "7a797473"
        confidence = "high"

    strings:
        $magic = { 7a 79 74 73 }

    condition:
        $magic
}

rule Payload_Magic_7a797877 {
    meta:
        description = "Decoded payload with magic bytes 7a797877"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "7a797877"
        confidence = "high"

    strings:
        $magic = { 7a 79 78 77 }

    condition:
        $magic
}

rule Payload_Magic_7af7a7b4 {
    meta:
        description = "Decoded payload with magic bytes 7af7a7b4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7af7a7b4"
        confidence = "high"

    strings:
        $magic = { 7a f7 a7 b4 }

    condition:
        $magic
}

rule Payload_Magic_7b0a2020 {
    meta:
        description = "Decoded payload with magic bytes 7b0a2020"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "7b0a2020"
        confidence = "high"

    strings:
        $magic = { 7b 0a 20 20 }

    condition:
        $magic
}

rule Payload_Magic_7b8e37ed {
    meta:
        description = "Decoded payload with magic bytes 7b8e37ed"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7b8e37ed"
        confidence = "high"

    strings:
        $magic = { 7b 8e 37 ed }

    condition:
        $magic
}

rule Payload_Magic_7bd7bae3 {
    meta:
        description = "Decoded payload with magic bytes 7bd7bae3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7bd7bae3"
        confidence = "high"

    strings:
        $magic = { 7b d7 ba e3 }

    condition:
        $magic
}

rule Payload_Magic_7c1e9f6c {
    meta:
        description = "Decoded payload with magic bytes 7c1e9f6c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "7c1e9f6c"
        confidence = "high"

    strings:
        $magic = { 7c 1e 9f 6c }

    condition:
        $magic
}

rule Payload_Magic_7c404342 {
    meta:
        description = "Decoded payload with magic bytes 7c404342"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "7c404342"
        confidence = "high"

    strings:
        $magic = { 7c 40 43 42 }

    condition:
        $magic
}

rule Payload_Magic_7c4f4e4f {
    meta:
        description = "Decoded payload with magic bytes 7c4f4e4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "7c4f4e4f"
        confidence = "high"

    strings:
        $magic = { 7c 4f 4e 4f }

    condition:
        $magic
}

rule Payload_Magic_7c607272 {
    meta:
        description = "Decoded payload with magic bytes 7c607272"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7c607272"
        confidence = "high"

    strings:
        $magic = { 7c 60 72 72 }

    condition:
        $magic
}

rule Payload_Magic_7c636261 {
    meta:
        description = "Decoded payload with magic bytes 7c636261"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.omg.wappfame.hbtx"
        magic_bytes = "7c636261"
        confidence = "high"

    strings:
        $magic = { 7c 63 62 61 }

    condition:
        $magic
}

rule Payload_Magic_7c6b6d61 {
    meta:
        description = "Decoded payload with magic bytes 7c6b6d61"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7c6b6d61"
        confidence = "high"

    strings:
        $magic = { 7c 6b 6d 61 }

    condition:
        $magic
}

rule Payload_Magic_7c7b7974 {
    meta:
        description = "Decoded payload with magic bytes 7c7b7974"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7c7b7974"
        confidence = "high"

    strings:
        $magic = { 7c 7b 79 74 }

    condition:
        $magic
}

rule Payload_Magic_7c7c7f7e {
    meta:
        description = "Decoded payload with magic bytes 7c7c7f7e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7c7c7f7e"
        confidence = "high"

    strings:
        $magic = { 7c 7c 7f 7e }

    condition:
        $magic
}

rule Payload_Magic_7c7d4243 {
    meta:
        description = "Decoded payload with magic bytes 7c7d4243"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7c7d4243"
        confidence = "high"

    strings:
        $magic = { 7c 7d 42 43 }

    condition:
        $magic
}

rule Payload_Magic_7c7e787a {
    meta:
        description = "Decoded payload with magic bytes 7c7e787a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "7c7e787a"
        confidence = "high"

    strings:
        $magic = { 7c 7e 78 7a }

    condition:
        $magic
}

rule Payload_Magic_7d6d6560 {
    meta:
        description = "Decoded payload with magic bytes 7d6d6560"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7d6d6560"
        confidence = "high"

    strings:
        $magic = { 7d 6d 65 60 }

    condition:
        $magic
}

rule Payload_Magic_7da72c8a {
    meta:
        description = "Decoded payload with magic bytes 7da72c8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "7da72c8a"
        confidence = "high"

    strings:
        $magic = { 7d a7 2c 8a }

    condition:
        $magic
}

rule Payload_Magic_7dc6baf3 {
    meta:
        description = "Decoded payload with magic bytes 7dc6baf3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7dc6baf3"
        confidence = "high"

    strings:
        $magic = { 7d c6 ba f3 }

    condition:
        $magic
}

rule Payload_Magic_7ddedfe7 {
    meta:
        description = "Decoded payload with magic bytes 7ddedfe7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7ddedfe7"
        confidence = "high"

    strings:
        $magic = { 7d de df e7 }

    condition:
        $magic
}

rule Payload_Magic_7ded1ef3 {
    meta:
        description = "Decoded payload with magic bytes 7ded1ef3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7ded1ef3"
        confidence = "high"

    strings:
        $magic = { 7d ed 1e f3 }

    condition:
        $magic
}

rule Payload_Magic_7e29dd07 {
    meta:
        description = "Decoded payload with magic bytes 7e29dd07"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7e29dd07"
        confidence = "high"

    strings:
        $magic = { 7e 29 dd 07 }

    condition:
        $magic
}

rule Payload_Magic_7e29dd4e {
    meta:
        description = "Decoded payload with magic bytes 7e29dd4e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "7e29dd4e"
        confidence = "high"

    strings:
        $magic = { 7e 29 dd 4e }

    condition:
        $magic
}

rule Payload_Magic_7e29e2b2 {
    meta:
        description = "Decoded payload with magic bytes 7e29e2b2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7e29e2b2"
        confidence = "high"

    strings:
        $magic = { 7e 29 e2 b2 }

    condition:
        $magic
}

rule Payload_Magic_7e2aecb6 {
    meta:
        description = "Decoded payload with magic bytes 7e2aecb6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "7e2aecb6"
        confidence = "high"

    strings:
        $magic = { 7e 2a ec b6 }

    condition:
        $magic
}

rule Payload_Magic_7e7d7c43 {
    meta:
        description = "Decoded payload with magic bytes 7e7d7c43"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7e7d7c43"
        confidence = "high"

    strings:
        $magic = { 7e 7d 7c 43 }

    condition:
        $magic
}

rule Payload_Magic_7e8ade8a {
    meta:
        description = "Decoded payload with magic bytes 7e8ade8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7e8ade8a"
        confidence = "high"

    strings:
        $magic = { 7e 8a de 8a }

    condition:
        $magic
}

rule Payload_Magic_7f7b6b7c {
    meta:
        description = "Decoded payload with magic bytes 7f7b6b7c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7f7b6b7c"
        confidence = "high"

    strings:
        $magic = { 7f 7b 6b 7c }

    condition:
        $magic
}

rule Payload_Magic_7f7c7d7a {
    meta:
        description = "Decoded payload with magic bytes 7f7c7d7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "7f7c7d7a"
        confidence = "high"

    strings:
        $magic = { 7f 7c 7d 7a }

    condition:
        $magic
}

rule Payload_Magic_7fb7b56b {
    meta:
        description = "Decoded payload with magic bytes 7fb7b56b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7fb7b56b"
        confidence = "high"

    strings:
        $magic = { 7f b7 b5 6b }

    condition:
        $magic
}

rule Payload_Magic_7fcd7cdf {
    meta:
        description = "Decoded payload with magic bytes 7fcd7cdf"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "7fcd7cdf"
        confidence = "high"

    strings:
        $magic = { 7f cd 7c df }

    condition:
        $magic
}

rule Payload_Magic_81eb4096 {
    meta:
        description = "Decoded payload with magic bytes 81eb4096"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "81eb4096"
        confidence = "high"

    strings:
        $magic = { 81 eb 40 96 }

    condition:
        $magic
}

rule Payload_Magic_81eb40a6 {
    meta:
        description = "Decoded payload with magic bytes 81eb40a6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "81eb40a6"
        confidence = "high"

    strings:
        $magic = { 81 eb 40 a6 }

    condition:
        $magic
}

rule Payload_Magic_81eb42ba {
    meta:
        description = "Decoded payload with magic bytes 81eb42ba"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "81eb42ba"
        confidence = "high"

    strings:
        $magic = { 81 eb 42 ba }

    condition:
        $magic
}

rule Payload_Magic_81eb449a {
    meta:
        description = "Decoded payload with magic bytes 81eb449a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "81eb449a"
        confidence = "high"

    strings:
        $magic = { 81 eb 44 9a }

    condition:
        $magic
}

rule Payload_Magic_82010100 {
    meta:
        description = "Decoded payload with magic bytes 82010100"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "82010100"
        confidence = "high"

    strings:
        $magic = { 82 01 01 00 }

    condition:
        $magic
}

rule Payload_Magic_85a9657b {
    meta:
        description = "Decoded payload with magic bytes 85a9657b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "85a9657b"
        confidence = "high"

    strings:
        $magic = { 85 a9 65 7b }

    condition:
        $magic
}

rule Payload_Magic_8628da72 {
    meta:
        description = "Decoded payload with magic bytes 8628da72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "8628da72"
        confidence = "high"

    strings:
        $magic = { 86 28 da 72 }

    condition:
        $magic
}

rule Payload_Magic_86cdcd84 {
    meta:
        description = "Decoded payload with magic bytes 86cdcd84"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "86cdcd84"
        confidence = "high"

    strings:
        $magic = { 86 cd cd 84 }

    condition:
        $magic
}

rule Payload_Magic_86db6976 {
    meta:
        description = "Decoded payload with magic bytes 86db6976"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "86db6976"
        confidence = "high"

    strings:
        $magic = { 86 db 69 76 }

    condition:
        $magic
}

rule Payload_Magic_87381889 {
    meta:
        description = "Decoded payload with magic bytes 87381889"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "87381889"
        confidence = "high"

    strings:
        $magic = { 87 38 18 89 }

    condition:
        $magic
}

rule Payload_Magic_89504e47 {
    meta:
        description = "Decoded payload with magic bytes 89504e47"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "6"
        family = "multi-family"
        magic_bytes = "89504e47"
        confidence = "high"

    strings:
        $magic = { 89 50 4e 47 }

    condition:
        $magic
}

rule Payload_Magic_89d7a7b6 {
    meta:
        description = "Decoded payload with magic bytes 89d7a7b6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89d7a7b6"
        confidence = "high"

    strings:
        $magic = { 89 d7 a7 b6 }

    condition:
        $magic
}

rule Payload_Magic_89df86a2 {
    meta:
        description = "Decoded payload with magic bytes 89df86a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df86a2"
        confidence = "high"

    strings:
        $magic = { 89 df 86 a2 }

    condition:
        $magic
}

rule Payload_Magic_89df9a71 {
    meta:
        description = "Decoded payload with magic bytes 89df9a71"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df9a71"
        confidence = "high"

    strings:
        $magic = { 89 df 9a 71 }

    condition:
        $magic
}

rule Payload_Magic_89df9a96 {
    meta:
        description = "Decoded payload with magic bytes 89df9a96"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df9a96"
        confidence = "high"

    strings:
        $magic = { 89 df 9a 96 }

    condition:
        $magic
}

rule Payload_Magic_89df9c85 {
    meta:
        description = "Decoded payload with magic bytes 89df9c85"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df9c85"
        confidence = "high"

    strings:
        $magic = { 89 df 9c 85 }

    condition:
        $magic
}

rule Payload_Magic_89df9c99 {
    meta:
        description = "Decoded payload with magic bytes 89df9c99"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df9c99"
        confidence = "high"

    strings:
        $magic = { 89 df 9c 99 }

    condition:
        $magic
}

rule Payload_Magic_89df9cb7 {
    meta:
        description = "Decoded payload with magic bytes 89df9cb7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89df9cb7"
        confidence = "high"

    strings:
        $magic = { 89 df 9c b7 }

    condition:
        $magic
}

rule Payload_Magic_89dfa17b {
    meta:
        description = "Decoded payload with magic bytes 89dfa17b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfa17b"
        confidence = "high"

    strings:
        $magic = { 89 df a1 7b }

    condition:
        $magic
}

rule Payload_Magic_89dfa2b7 {
    meta:
        description = "Decoded payload with magic bytes 89dfa2b7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfa2b7"
        confidence = "high"

    strings:
        $magic = { 89 df a2 b7 }

    condition:
        $magic
}

rule Payload_Magic_89dfa6a1 {
    meta:
        description = "Decoded payload with magic bytes 89dfa6a1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfa6a1"
        confidence = "high"

    strings:
        $magic = { 89 df a6 a1 }

    condition:
        $magic
}

rule Payload_Magic_89dfa975 {
    meta:
        description = "Decoded payload with magic bytes 89dfa975"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfa975"
        confidence = "high"

    strings:
        $magic = { 89 df a9 75 }

    condition:
        $magic
}

rule Payload_Magic_89dfa992 {
    meta:
        description = "Decoded payload with magic bytes 89dfa992"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfa992"
        confidence = "high"

    strings:
        $magic = { 89 df a9 92 }

    condition:
        $magic
}

rule Payload_Magic_89dfaa72 {
    meta:
        description = "Decoded payload with magic bytes 89dfaa72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfaa72"
        confidence = "high"

    strings:
        $magic = { 89 df aa 72 }

    condition:
        $magic
}

rule Payload_Magic_89dfab7a {
    meta:
        description = "Decoded payload with magic bytes 89dfab7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfab7a"
        confidence = "high"

    strings:
        $magic = { 89 df ab 7a }

    condition:
        $magic
}

rule Payload_Magic_89dfac9a {
    meta:
        description = "Decoded payload with magic bytes 89dfac9a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "89dfac9a"
        confidence = "high"

    strings:
        $magic = { 89 df ac 9a }

    condition:
        $magic
}

rule Payload_Magic_8a09e8ad {
    meta:
        description = "Decoded payload with magic bytes 8a09e8ad"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8a09e8ad"
        confidence = "high"

    strings:
        $magic = { 8a 09 e8 ad }

    condition:
        $magic
}

rule Payload_Magic_8a78626e {
    meta:
        description = "Decoded payload with magic bytes 8a78626e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8a78626e"
        confidence = "high"

    strings:
        $magic = { 8a 78 62 6e }

    condition:
        $magic
}

rule Payload_Magic_8a78ad89 {
    meta:
        description = "Decoded payload with magic bytes 8a78ad89"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "8a78ad89"
        confidence = "high"

    strings:
        $magic = { 8a 78 ad 89 }

    condition:
        $magic
}

rule Payload_Magic_8a7b1e72 {
    meta:
        description = "Decoded payload with magic bytes 8a7b1e72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "8a7b1e72"
        confidence = "high"

    strings:
        $magic = { 8a 7b 1e 72 }

    condition:
        $magic
}

rule Payload_Magic_8a7b5e9e {
    meta:
        description = "Decoded payload with magic bytes 8a7b5e9e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "8a7b5e9e"
        confidence = "high"

    strings:
        $magic = { 8a 7b 5e 9e }

    condition:
        $magic
}

rule Payload_Magic_8a7b5eae {
    meta:
        description = "Decoded payload with magic bytes 8a7b5eae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8a7b5eae"
        confidence = "high"

    strings:
        $magic = { 8a 7b 5e ae }

    condition:
        $magic
}

rule Payload_Magic_8ac131b5 {
    meta:
        description = "Decoded payload with magic bytes 8ac131b5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "8ac131b5"
        confidence = "high"

    strings:
        $magic = { 8a c1 31 b5 }

    condition:
        $magic
}

rule Payload_Magic_8acb2e8a {
    meta:
        description = "Decoded payload with magic bytes 8acb2e8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8acb2e8a"
        confidence = "high"

    strings:
        $magic = { 8a cb 2e 8a }

    condition:
        $magic
}

rule Payload_Magic_8acfdf8a {
    meta:
        description = "Decoded payload with magic bytes 8acfdf8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "8acfdf8a"
        confidence = "high"

    strings:
        $magic = { 8a cf df 8a }

    condition:
        $magic
}

rule Payload_Magic_8af7617f {
    meta:
        description = "Decoded payload with magic bytes 8af7617f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "8af7617f"
        confidence = "high"

    strings:
        $magic = { 8a f7 61 7f }

    condition:
        $magic
}

rule Payload_Magic_8b66bf00 {
    meta:
        description = "Decoded payload with magic bytes 8b66bf00"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b66bf00"
        confidence = "high"

    strings:
        $magic = { 8b 66 bf 00 }

    condition:
        $magic
}

rule Payload_Magic_8b677f00 {
    meta:
        description = "Decoded payload with magic bytes 8b677f00"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f00"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 00 }

    condition:
        $magic
}

rule Payload_Magic_8b677f01 {
    meta:
        description = "Decoded payload with magic bytes 8b677f01"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f01"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 01 }

    condition:
        $magic
}

rule Payload_Magic_8b677f08 {
    meta:
        description = "Decoded payload with magic bytes 8b677f08"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f08"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 08 }

    condition:
        $magic
}

rule Payload_Magic_8b677f11 {
    meta:
        description = "Decoded payload with magic bytes 8b677f11"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f11"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 11 }

    condition:
        $magic
}

rule Payload_Magic_8b677f21 {
    meta:
        description = "Decoded payload with magic bytes 8b677f21"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f21"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 21 }

    condition:
        $magic
}

rule Payload_Magic_8b677f38 {
    meta:
        description = "Decoded payload with magic bytes 8b677f38"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f38"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 38 }

    condition:
        $magic
}

rule Payload_Magic_8b677f3c {
    meta:
        description = "Decoded payload with magic bytes 8b677f3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8b677f3c"
        confidence = "high"

    strings:
        $magic = { 8b 67 7f 3c }

    condition:
        $magic
}

rule Payload_Magic_8dabdafe {
    meta:
        description = "Decoded payload with magic bytes 8dabdafe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "8dabdafe"
        confidence = "high"

    strings:
        $magic = { 8d ab da fe }

    condition:
        $magic
}

rule Payload_Magic_8eeae2b1 {
    meta:
        description = "Decoded payload with magic bytes 8eeae2b1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "8eeae2b1"
        confidence = "high"

    strings:
        $magic = { 8e ea e2 b1 }

    condition:
        $magic
}

rule Payload_Magic_92233720 {
    meta:
        description = "Decoded payload with magic bytes 92233720"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "92233720"
        confidence = "high"

    strings:
        $magic = { 92 23 37 20 }

    condition:
        $magic
}

rule Payload_Magic_927a3095 {
    meta:
        description = "Decoded payload with magic bytes 927a3095"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "927a3095"
        confidence = "high"

    strings:
        $magic = { 92 7a 30 95 }

    condition:
        $magic
}

rule Payload_Magic_95ab2dfe {
    meta:
        description = "Decoded payload with magic bytes 95ab2dfe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "95ab2dfe"
        confidence = "high"

    strings:
        $magic = { 95 ab 2d fe }

    condition:
        $magic
}

rule Payload_Magic_95e79e79 {
    meta:
        description = "Decoded payload with magic bytes 95e79e79"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "95e79e79"
        confidence = "high"

    strings:
        $magic = { 95 e7 9e 79 }

    condition:
        $magic
}

rule Payload_Magic_96869d31 {
    meta:
        description = "Decoded payload with magic bytes 96869d31"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "96869d31"
        confidence = "high"

    strings:
        $magic = { 96 86 9d 31 }

    condition:
        $magic
}

rule Payload_Magic_9774d56d {
    meta:
        description = "Decoded payload with magic bytes 9774d56d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "9774d56d"
        confidence = "high"

    strings:
        $magic = { 97 74 d5 6d }

    condition:
        $magic
}

rule Payload_Magic_98071c7a {
    meta:
        description = "Decoded payload with magic bytes 98071c7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "98071c7a"
        confidence = "high"

    strings:
        $magic = { 98 07 1c 7a }

    condition:
        $magic
}

rule Payload_Magic_98fae457 {
    meta:
        description = "Decoded payload with magic bytes 98fae457"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "98fae457"
        confidence = "high"

    strings:
        $magic = { 98 fa e4 57 }

    condition:
        $magic
}

rule Payload_Magic_99179cad {
    meta:
        description = "Decoded payload with magic bytes 99179cad"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "99179cad"
        confidence = "high"

    strings:
        $magic = { 99 17 9c ad }

    condition:
        $magic
}

rule Payload_Magic_99a8a53e {
    meta:
        description = "Decoded payload with magic bytes 99a8a53e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "99a8a53e"
        confidence = "high"

    strings:
        $magic = { 99 a8 a5 3e }

    condition:
        $magic
}

rule Payload_Magic_99a9da81 {
    meta:
        description = "Decoded payload with magic bytes 99a9da81"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "99a9da81"
        confidence = "high"

    strings:
        $magic = { 99 a9 da 81 }

    condition:
        $magic
}

rule Payload_Magic_99ac446a {
    meta:
        description = "Decoded payload with magic bytes 99ac446a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "99ac446a"
        confidence = "high"

    strings:
        $magic = { 99 ac 44 6a }

    condition:
        $magic
}

rule Payload_Magic_99ac45a2 {
    meta:
        description = "Decoded payload with magic bytes 99ac45a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "99ac45a2"
        confidence = "high"

    strings:
        $magic = { 99 ac 45 a2 }

    condition:
        $magic
}

rule Payload_Magic_99dd968a {
    meta:
        description = "Decoded payload with magic bytes 99dd968a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "99dd968a"
        confidence = "high"

    strings:
        $magic = { 99 dd 96 8a }

    condition:
        $magic
}

rule Payload_Magic_99de168a {
    meta:
        description = "Decoded payload with magic bytes 99de168a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "99de168a"
        confidence = "high"

    strings:
        $magic = { 99 de 16 8a }

    condition:
        $magic
}

rule Payload_Magic_99de568a {
    meta:
        description = "Decoded payload with magic bytes 99de568a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "99de568a"
        confidence = "high"

    strings:
        $magic = { 99 de 56 8a }

    condition:
        $magic
}

rule Payload_Magic_99de7f6e {
    meta:
        description = "Decoded payload with magic bytes 99de7f6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "99de7f6e"
        confidence = "high"

    strings:
        $magic = { 99 de 7f 6e }

    condition:
        $magic
}

rule Payload_Magic_9a86dc96 {
    meta:
        description = "Decoded payload with magic bytes 9a86dc96"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "9a86dc96"
        confidence = "high"

    strings:
        $magic = { 9a 86 dc 96 }

    condition:
        $magic
}

rule Payload_Magic_9a9fed9a {
    meta:
        description = "Decoded payload with magic bytes 9a9fed9a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "9a9fed9a"
        confidence = "high"

    strings:
        $magic = { 9a 9f ed 9a }

    condition:
        $magic
}

rule Payload_Magic_9dab62bd {
    meta:
        description = "Decoded payload with magic bytes 9dab62bd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "9dab62bd"
        confidence = "high"

    strings:
        $magic = { 9d ab 62 bd }

    condition:
        $magic
}

rule Payload_Magic_9de828b6 {
    meta:
        description = "Decoded payload with magic bytes 9de828b6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "9de828b6"
        confidence = "high"

    strings:
        $magic = { 9d e8 28 b6 }

    condition:
        $magic
}

rule Payload_Magic_9deb70a2 {
    meta:
        description = "Decoded payload with magic bytes 9deb70a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        magic_bytes = "9deb70a2"
        confidence = "high"

    strings:
        $magic = { 9d eb 70 a2 }

    condition:
        $magic
}

rule Payload_Magic_9deb7fb2 {
    meta:
        description = "Decoded payload with magic bytes 9deb7fb2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "9deb7fb2"
        confidence = "high"

    strings:
        $magic = { 9d eb 7f b2 }

    condition:
        $magic
}

rule Payload_Magic_9e89dca2 {
    meta:
        description = "Decoded payload with magic bytes 9e89dca2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "9e89dca2"
        confidence = "high"

    strings:
        $magic = { 9e 89 dc a2 }

    condition:
        $magic
}

rule Payload_Magic_a155339d {
    meta:
        description = "Decoded payload with magic bytes a155339d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "a155339d"
        confidence = "high"

    strings:
        $magic = { a1 55 33 9d }

    condition:
        $magic
}

rule Payload_Magic_a270a89d {
    meta:
        description = "Decoded payload with magic bytes a270a89d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "a270a89d"
        confidence = "high"

    strings:
        $magic = { a2 70 a8 9d }

    condition:
        $magic
}

rule Payload_Magic_a270ab79 {
    meta:
        description = "Decoded payload with magic bytes a270ab79"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "a270ab79"
        confidence = "high"

    strings:
        $magic = { a2 70 ab 79 }

    condition:
        $magic
}

rule Payload_Magic_a27a1f7d {
    meta:
        description = "Decoded payload with magic bytes a27a1f7d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a27a1f7d"
        confidence = "high"

    strings:
        $magic = { a2 7a 1f 7d }

    condition:
        $magic
}

rule Payload_Magic_a2b81a9e {
    meta:
        description = "Decoded payload with magic bytes a2b81a9e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a2b81a9e"
        confidence = "high"

    strings:
        $magic = { a2 b8 1a 9e }

    condition:
        $magic
}

rule Payload_Magic_a2f7abae {
    meta:
        description = "Decoded payload with magic bytes a2f7abae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "a2f7abae"
        confidence = "high"

    strings:
        $magic = { a2 f7 ab ae }

    condition:
        $magic
}

rule Payload_Magic_a5a81ead {
    meta:
        description = "Decoded payload with magic bytes a5a81ead"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a5a81ead"
        confidence = "high"

    strings:
        $magic = { a5 a8 1e ad }

    condition:
        $magic
}

rule Payload_Magic_a5b7968a {
    meta:
        description = "Decoded payload with magic bytes a5b7968a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a5b7968a"
        confidence = "high"

    strings:
        $magic = { a5 b7 96 8a }

    condition:
        $magic
}

rule Payload_Magic_a5c3dab6 {
    meta:
        description = "Decoded payload with magic bytes a5c3dab6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a5c3dab6"
        confidence = "high"

    strings:
        $magic = { a5 c3 da b6 }

    condition:
        $magic
}

rule Payload_Magic_a61cac89 {
    meta:
        description = "Decoded payload with magic bytes a61cac89"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a61cac89"
        confidence = "high"

    strings:
        $magic = { a6 1c ac 89 }

    condition:
        $magic
}

rule Payload_Magic_a62968b4 {
    meta:
        description = "Decoded payload with magic bytes a62968b4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a62968b4"
        confidence = "high"

    strings:
        $magic = { a6 29 68 b4 }

    condition:
        $magic
}

rule Payload_Magic_a6472cef {
    meta:
        description = "Decoded payload with magic bytes a6472cef"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a6472cef"
        confidence = "high"

    strings:
        $magic = { a6 47 2c ef }

    condition:
        $magic
}

rule Payload_Magic_a6896273 {
    meta:
        description = "Decoded payload with magic bytes a6896273"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a6896273"
        confidence = "high"

    strings:
        $magic = { a6 89 62 73 }

    condition:
        $magic
}

rule Payload_Magic_a6b79f7a {
    meta:
        description = "Decoded payload with magic bytes a6b79f7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a6b79f7a"
        confidence = "high"

    strings:
        $magic = { a6 b7 9f 7a }

    condition:
        $magic
}

rule Payload_Magic_a6b79ffe {
    meta:
        description = "Decoded payload with magic bytes a6b79ffe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "a6b79ffe"
        confidence = "high"

    strings:
        $magic = { a6 b7 9f fe }

    condition:
        $magic
}

rule Payload_Magic_a6b8af6a {
    meta:
        description = "Decoded payload with magic bytes a6b8af6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "a6b8af6a"
        confidence = "high"

    strings:
        $magic = { a6 b8 af 6a }

    condition:
        $magic
}

rule Payload_Magic_a6bf923c {
    meta:
        description = "Decoded payload with magic bytes a6bf923c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "a6bf923c"
        confidence = "high"

    strings:
        $magic = { a6 bf 92 3c }

    condition:
        $magic
}

rule Payload_Magic_a6e6e589 {
    meta:
        description = "Decoded payload with magic bytes a6e6e589"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "a6e6e589"
        confidence = "high"

    strings:
        $magic = { a6 e6 e5 89 }

    condition:
        $magic
}

rule Payload_Magic_ab61069c {
    meta:
        description = "Decoded payload with magic bytes ab61069c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "ab61069c"
        confidence = "high"

    strings:
        $magic = { ab 61 06 9c }

    condition:
        $magic
}

rule Payload_Magic_ada85c6e {
    meta:
        description = "Decoded payload with magic bytes ada85c6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "ada85c6e"
        confidence = "high"

    strings:
        $magic = { ad a8 5c 6e }

    condition:
        $magic
}

rule Payload_Magic_ade9629e {
    meta:
        description = "Decoded payload with magic bytes ade9629e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "ade9629e"
        confidence = "high"

    strings:
        $magic = { ad e9 62 9e }

    condition:
        $magic
}

rule Payload_Magic_adeaae7a {
    meta:
        description = "Decoded payload with magic bytes adeaae7a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "adeaae7a"
        confidence = "high"

    strings:
        $magic = { ad ea ae 7a }

    condition:
        $magic
}

rule Payload_Magic_aebaebae {
    meta:
        description = "Decoded payload with magic bytes aebaebae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "aebaebae"
        confidence = "high"

    strings:
        $magic = { ae ba eb ae }

    condition:
        $magic
}

rule Payload_Magic_aec68e00 {
    meta:
        description = "Decoded payload with magic bytes aec68e00"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "aec68e00"
        confidence = "high"

    strings:
        $magic = { ae c6 8e 00 }

    condition:
        $magic
}

rule Payload_Magic_b1abde05 {
    meta:
        description = "Decoded payload with magic bytes b1abde05"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b1abde05"
        confidence = "high"

    strings:
        $magic = { b1 ab de 05 }

    condition:
        $magic
}

rule Payload_Magic_b1e6ab72 {
    meta:
        description = "Decoded payload with magic bytes b1e6ab72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b1e6ab72"
        confidence = "high"

    strings:
        $magic = { b1 e6 ab 72 }

    condition:
        $magic
}

rule Payload_Magic_b1e95e72 {
    meta:
        description = "Decoded payload with magic bytes b1e95e72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b1e95e72"
        confidence = "high"

    strings:
        $magic = { b1 e9 5e 72 }

    condition:
        $magic
}

rule Payload_Magic_b1e9dd22 {
    meta:
        description = "Decoded payload with magic bytes b1e9dd22"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b1e9dd22"
        confidence = "high"

    strings:
        $magic = { b1 e9 dd 22 }

    condition:
        $magic
}

rule Payload_Magic_b1eb427b {
    meta:
        description = "Decoded payload with magic bytes b1eb427b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b1eb427b"
        confidence = "high"

    strings:
        $magic = { b1 eb 42 7b }

    condition:
        $magic
}

rule Payload_Magic_b1eb4286 {
    meta:
        description = "Decoded payload with magic bytes b1eb4286"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b1eb4286"
        confidence = "high"

    strings:
        $magic = { b1 eb 42 86 }

    condition:
        $magic
}

rule Payload_Magic_b1eb43a2 {
    meta:
        description = "Decoded payload with magic bytes b1eb43a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b1eb43a2"
        confidence = "high"

    strings:
        $magic = { b1 eb 43 a2 }

    condition:
        $magic
}

rule Payload_Magic_b1eb47a2 {
    meta:
        description = "Decoded payload with magic bytes b1eb47a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b1eb47a2"
        confidence = "high"

    strings:
        $magic = { b1 eb 47 a2 }

    condition:
        $magic
}

rule Payload_Magic_b1eb4dba {
    meta:
        description = "Decoded payload with magic bytes b1eb4dba"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b1eb4dba"
        confidence = "high"

    strings:
        $magic = { b1 eb 4d ba }

    condition:
        $magic
}

rule Payload_Magic_b1eb517a {
    meta:
        description = "Decoded payload with magic bytes b1eb517a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b1eb517a"
        confidence = "high"

    strings:
        $magic = { b1 eb 51 7a }

    condition:
        $magic
}

rule Payload_Magic_b1eb54b1 {
    meta:
        description = "Decoded payload with magic bytes b1eb54b1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "b1eb54b1"
        confidence = "high"

    strings:
        $magic = { b1 eb 54 b1 }

    condition:
        $magic
}

rule Payload_Magic_b1eb5cb7 {
    meta:
        description = "Decoded payload with magic bytes b1eb5cb7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b1eb5cb7"
        confidence = "high"

    strings:
        $magic = { b1 eb 5c b7 }

    condition:
        $magic
}

rule Payload_Magic_b1eb7e6e {
    meta:
        description = "Decoded payload with magic bytes b1eb7e6e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b1eb7e6e"
        confidence = "high"

    strings:
        $magic = { b1 eb 7e 6e }

    condition:
        $magic
}

rule Payload_Magic_b216968a {
    meta:
        description = "Decoded payload with magic bytes b216968a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b216968a"
        confidence = "high"

    strings:
        $magic = { b2 16 96 8a }

    condition:
        $magic
}

rule Payload_Magic_b216b6db {
    meta:
        description = "Decoded payload with magic bytes b216b6db"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b216b6db"
        confidence = "high"

    strings:
        $magic = { b2 16 b6 db }

    condition:
        $magic
}

rule Payload_Magic_b216b6e7 {
    meta:
        description = "Decoded payload with magic bytes b216b6e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b216b6e7"
        confidence = "high"

    strings:
        $magic = { b2 16 b6 e7 }

    condition:
        $magic
}

rule Payload_Magic_b216b7f3 {
    meta:
        description = "Decoded payload with magic bytes b216b7f3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b216b7f3"
        confidence = "high"

    strings:
        $magic = { b2 16 b7 f3 }

    condition:
        $magic
}

rule Payload_Magic_b216b9d7 {
    meta:
        description = "Decoded payload with magic bytes b216b9d7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b216b9d7"
        confidence = "high"

    strings:
        $magic = { b2 16 b9 d7 }

    condition:
        $magic
}

rule Payload_Magic_b21a2e95 {
    meta:
        description = "Decoded payload with magic bytes b21a2e95"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b21a2e95"
        confidence = "high"

    strings:
        $magic = { b2 1a 2e 95 }

    condition:
        $magic
}

rule Payload_Magic_b229a995 {
    meta:
        description = "Decoded payload with magic bytes b229a995"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b229a995"
        confidence = "high"

    strings:
        $magic = { b2 29 a9 95 }

    condition:
        $magic
}

rule Payload_Magic_b229e095 {
    meta:
        description = "Decoded payload with magic bytes b229e095"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b229e095"
        confidence = "high"

    strings:
        $magic = { b2 29 e0 95 }

    condition:
        $magic
}

rule Payload_Magic_b287247a {
    meta:
        description = "Decoded payload with magic bytes b287247a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b287247a"
        confidence = "high"

    strings:
        $magic = { b2 87 24 7a }

    condition:
        $magic
}

rule Payload_Magic_b2a95c8a {
    meta:
        description = "Decoded payload with magic bytes b2a95c8a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b2a95c8a"
        confidence = "high"

    strings:
        $magic = { b2 a9 5c 8a }

    condition:
        $magic
}

rule Payload_Magic_b2a962b5 {
    meta:
        description = "Decoded payload with magic bytes b2a962b5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b2a962b5"
        confidence = "high"

    strings:
        $magic = { b2 a9 62 b5 }

    condition:
        $magic
}

rule Payload_Magic_b2d6abb4 {
    meta:
        description = "Decoded payload with magic bytes b2d6abb4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b2d6abb4"
        confidence = "high"

    strings:
        $magic = { b2 d6 ab b4 }

    condition:
        $magic
}

rule Payload_Magic_b2dadab5 {
    meta:
        description = "Decoded payload with magic bytes b2dadab5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b2dadab5"
        confidence = "high"

    strings:
        $magic = { b2 da da b5 }

    condition:
        $magic
}

rule Payload_Magic_b2e6e379 {
    meta:
        description = "Decoded payload with magic bytes b2e6e379"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b2e6e379"
        confidence = "high"

    strings:
        $magic = { b2 e6 e3 79 }

    condition:
        $magic
}

rule Payload_Magic_b2ea69a2 {
    meta:
        description = "Decoded payload with magic bytes b2ea69a2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "b2ea69a2"
        confidence = "high"

    strings:
        $magic = { b2 ea 69 a2 }

    condition:
        $magic
}

rule Payload_Magic_b423bb4c {
    meta:
        description = "Decoded payload with magic bytes b423bb4c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b423bb4c"
        confidence = "high"

    strings:
        $magic = { b4 23 bb 4c }

    condition:
        $magic
}

rule Payload_Magic_b5bb3f76 {
    meta:
        description = "Decoded payload with magic bytes b5bb3f76"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b5bb3f76"
        confidence = "high"

    strings:
        $magic = { b5 bb 3f 76 }

    condition:
        $magic
}

rule Payload_Magic_b5bb3f7b {
    meta:
        description = "Decoded payload with magic bytes b5bb3f7b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b5bb3f7b"
        confidence = "high"

    strings:
        $magic = { b5 bb 3f 7b }

    condition:
        $magic
}

rule Payload_Magic_b5e9a9fe {
    meta:
        description = "Decoded payload with magic bytes b5e9a9fe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b5e9a9fe"
        confidence = "high"

    strings:
        $magic = { b5 e9 a9 fe }

    condition:
        $magic
}

rule Payload_Magic_b5eb2dfe {
    meta:
        description = "Decoded payload with magic bytes b5eb2dfe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b5eb2dfe"
        confidence = "high"

    strings:
        $magic = { b5 eb 2d fe }

    condition:
        $magic
}

rule Payload_Magic_b5ec6d12 {
    meta:
        description = "Decoded payload with magic bytes b5ec6d12"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "b5ec6d12"
        confidence = "high"

    strings:
        $magic = { b5 ec 6d 12 }

    condition:
        $magic
}

rule Payload_Magic_b629e47a {
    meta:
        description = "Decoded payload with magic bytes b629e47a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "b629e47a"
        confidence = "high"

    strings:
        $magic = { b6 29 e4 7a }

    condition:
        $magic
}

rule Payload_Magic_b65b157a {
    meta:
        description = "Decoded payload with magic bytes b65b157a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        magic_bytes = "b65b157a"
        confidence = "high"

    strings:
        $magic = { b6 5b 15 7a }

    condition:
        $magic
}

rule Payload_Magic_b68a6272 {
    meta:
        description = "Decoded payload with magic bytes b68a6272"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "b68a6272"
        confidence = "high"

    strings:
        $magic = { b6 8a 62 72 }

    condition:
        $magic
}

rule Payload_Magic_ba67a783 {
    meta:
        description = "Decoded payload with magic bytes ba67a783"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "ba67a783"
        confidence = "high"

    strings:
        $magic = { ba 67 a7 83 }

    condition:
        $magic
}

rule Payload_Magic_bac7bf9e {
    meta:
        description = "Decoded payload with magic bytes bac7bf9e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "bac7bf9e"
        confidence = "high"

    strings:
        $magic = { ba c7 bf 9e }

    condition:
        $magic
}

rule Payload_Magic_bf7fe991 {
    meta:
        description = "Decoded payload with magic bytes bf7fe991"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "bf7fe991"
        confidence = "high"

    strings:
        $magic = { bf 7f e9 91 }

    condition:
        $magic
}

rule Payload_Magic_c1aa7ec2 {
    meta:
        description = "Decoded payload with magic bytes c1aa7ec2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "c1aa7ec2"
        confidence = "high"

    strings:
        $magic = { c1 aa 7e c2 }

    condition:
        $magic
}

rule Payload_Magic_c6858e06 {
    meta:
        description = "Decoded payload with magic bytes c6858e06"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "c6858e06"
        confidence = "high"

    strings:
        $magic = { c6 85 8e 06 }

    condition:
        $magic
}

rule Payload_Magic_c79d3452 {
    meta:
        description = "Decoded payload with magic bytes c79d3452"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "c79d3452"
        confidence = "high"

    strings:
        $magic = { c7 9d 34 52 }

    condition:
        $magic
}

rule Payload_Magic_c79d3d4e {
    meta:
        description = "Decoded payload with magic bytes c79d3d4e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "c79d3d4e"
        confidence = "high"

    strings:
        $magic = { c7 9d 3d 4e }

    condition:
        $magic
}

rule Payload_Magic_cb26ff9d {
    meta:
        description = "Decoded payload with magic bytes cb26ff9d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "cb26ff9d"
        confidence = "high"

    strings:
        $magic = { cb 26 ff 9d }

    condition:
        $magic
}

rule Payload_Magic_d34d04d0 {
    meta:
        description = "Decoded payload with magic bytes d34d04d0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d34d04d0"
        confidence = "high"

    strings:
        $magic = { d3 4d 04 d0 }

    condition:
        $magic
}

rule Payload_Magic_d35db7e3 {
    meta:
        description = "Decoded payload with magic bytes d35db7e3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "13"
        family = "multi-family"
        magic_bytes = "d35db7e3"
        confidence = "high"

    strings:
        $magic = { d3 5d b7 e3 }

    condition:
        $magic
}

rule Payload_Magic_d39d7de7 {
    meta:
        description = "Decoded payload with magic bytes d39d7de7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d39d7de7"
        confidence = "high"

    strings:
        $magic = { d3 9d 7d e7 }

    condition:
        $magic
}

rule Payload_Magic_d5897d3c {
    meta:
        description = "Decoded payload with magic bytes d5897d3c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "d5897d3c"
        confidence = "high"

    strings:
        $magic = { d5 89 7d 3c }

    condition:
        $magic
}

rule Payload_Magic_d71edefd {
    meta:
        description = "Decoded payload with magic bytes d71edefd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "d71edefd"
        confidence = "high"

    strings:
        $magic = { d7 1e de fd }

    condition:
        $magic
}

rule Payload_Magic_d7407b07 {
    meta:
        description = "Decoded payload with magic bytes d7407b07"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d7407b07"
        confidence = "high"

    strings:
        $magic = { d7 40 7b 07 }

    condition:
        $magic
}

rule Payload_Magic_d740b414 {
    meta:
        description = "Decoded payload with magic bytes d740b414"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d740b414"
        confidence = "high"

    strings:
        $magic = { d7 40 b4 14 }

    condition:
        $magic
}

rule Payload_Magic_d7413bdb {
    meta:
        description = "Decoded payload with magic bytes d7413bdb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d7413bdb"
        confidence = "high"

    strings:
        $magic = { d7 41 3b db }

    condition:
        $magic
}

rule Payload_Magic_d74dc500 {
    meta:
        description = "Decoded payload with magic bytes d74dc500"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d74dc500"
        confidence = "high"

    strings:
        $magic = { d7 4d c5 00 }

    condition:
        $magic
}

rule Payload_Magic_d74e7708 {
    meta:
        description = "Decoded payload with magic bytes d74e7708"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d74e7708"
        confidence = "high"

    strings:
        $magic = { d7 4e 77 08 }

    condition:
        $magic
}

rule Payload_Magic_d75f37f7 {
    meta:
        description = "Decoded payload with magic bytes d75f37f7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d75f37f7"
        confidence = "high"

    strings:
        $magic = { d7 5f 37 f7 }

    condition:
        $magic
}

rule Payload_Magic_d76df8e7 {
    meta:
        description = "Decoded payload with magic bytes d76df8e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "d76df8e7"
        confidence = "high"

    strings:
        $magic = { d7 6d f8 e7 }

    condition:
        $magic
}

rule Payload_Magic_d80034e7 {
    meta:
        description = "Decoded payload with magic bytes d80034e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "d80034e7"
        confidence = "high"

    strings:
        $magic = { d8 00 34 e7 }

    condition:
        $magic
}

rule Payload_Magic_db2939fd {
    meta:
        description = "Decoded payload with magic bytes db2939fd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "db2939fd"
        confidence = "high"

    strings:
        $magic = { db 29 39 fd }

    condition:
        $magic
}

rule Payload_Magic_db807b07 {
    meta:
        description = "Decoded payload with magic bytes db807b07"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "db807b07"
        confidence = "high"

    strings:
        $magic = { db 80 7b 07 }

    condition:
        $magic
}

rule Payload_Magic_dbf3aef2 {
    meta:
        description = "Decoded payload with magic bytes dbf3aef2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "dbf3aef2"
        confidence = "high"

    strings:
        $magic = { db f3 ae f2 }

    condition:
        $magic
}

rule Payload_Magic_dddf387f {
    meta:
        description = "Decoded payload with magic bytes dddf387f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "dddf387f"
        confidence = "high"

    strings:
        $magic = { dd df 38 7f }

    condition:
        $magic
}

rule Payload_Magic_de2da774 {
    meta:
        description = "Decoded payload with magic bytes de2da774"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "de2da774"
        confidence = "high"

    strings:
        $magic = { de 2d a7 74 }

    condition:
        $magic
}

rule Payload_Magic_df279122 {
    meta:
        description = "Decoded payload with magic bytes df279122"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "df279122"
        confidence = "high"

    strings:
        $magic = { df 27 91 22 }

    condition:
        $magic
}

rule Payload_Magic_df4e3900 {
    meta:
        description = "Decoded payload with magic bytes df4e3900"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "df4e3900"
        confidence = "high"

    strings:
        $magic = { df 4e 39 00 }

    condition:
        $magic
}

rule Payload_Magic_df4e3bd1 {
    meta:
        description = "Decoded payload with magic bytes df4e3bd1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "df4e3bd1"
        confidence = "high"

    strings:
        $magic = { df 4e 3b d1 }

    condition:
        $magic
}

rule Payload_Magic_df4f3a77 {
    meta:
        description = "Decoded payload with magic bytes df4f3a77"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "df4f3a77"
        confidence = "high"

    strings:
        $magic = { df 4f 3a 77 }

    condition:
        $magic
}

rule Payload_Magic_dfad7b75 {
    meta:
        description = "Decoded payload with magic bytes dfad7b75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "dfad7b75"
        confidence = "high"

    strings:
        $magic = { df ad 7b 75 }

    condition:
        $magic
}

rule Payload_Magic_e03ebde8 {
    meta:
        description = "Decoded payload with magic bytes e03ebde8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e03ebde8"
        confidence = "high"

    strings:
        $magic = { e0 3e bd e8 }

    condition:
        $magic
}

rule Payload_Magic_e1f7b7e3 {
    meta:
        description = "Decoded payload with magic bytes e1f7b7e3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e1f7b7e3"
        confidence = "high"

    strings:
        $magic = { e1 f7 b7 e3 }

    condition:
        $magic
}

rule Payload_Magic_e1fdfaed {
    meta:
        description = "Decoded payload with magic bytes e1fdfaed"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e1fdfaed"
        confidence = "high"

    strings:
        $magic = { e1 fd fa ed }

    condition:
        $magic
}

rule Payload_Magic_e1febbeb {
    meta:
        description = "Decoded payload with magic bytes e1febbeb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e1febbeb"
        confidence = "high"

    strings:
        $magic = { e1 fe bb eb }

    condition:
        $magic
}

rule Payload_Magic_e34f7d07 {
    meta:
        description = "Decoded payload with magic bytes e34f7d07"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e34f7d07"
        confidence = "high"

    strings:
        $magic = { e3 4f 7d 07 }

    condition:
        $magic
}

rule Payload_Magic_e3675e6d {
    meta:
        description = "Decoded payload with magic bytes e3675e6d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e3675e6d"
        confidence = "high"

    strings:
        $magic = { e3 67 5e 6d }

    condition:
        $magic
}

rule Payload_Magic_e42ea0e2 {
    meta:
        description = "Decoded payload with magic bytes e42ea0e2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "e42ea0e2"
        confidence = "high"

    strings:
        $magic = { e4 2e a0 e2 }

    condition:
        $magic
}

rule Payload_Magic_e44e4204 {
    meta:
        description = "Decoded payload with magic bytes e44e4204"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e44e4204"
        confidence = "high"

    strings:
        $magic = { e4 4e 42 04 }

    condition:
        $magic
}

rule Payload_Magic_e484b2e8 {
    meta:
        description = "Decoded payload with magic bytes e484b2e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e484b2e8"
        confidence = "high"

    strings:
        $magic = { e4 84 b2 e8 }

    condition:
        $magic
}

rule Payload_Magic_e489b6e7 {
    meta:
        description = "Decoded payload with magic bytes e489b6e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.perfectlove"
        magic_bytes = "e489b6e7"
        confidence = "high"

    strings:
        $magic = { e4 89 b6 e7 }

    condition:
        $magic
}

rule Payload_Magic_e48ba1e9 {
    meta:
        description = "Decoded payload with magic bytes e48ba1e9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e48ba1e9"
        confidence = "high"

    strings:
        $magic = { e4 8b a1 e9 }

    condition:
        $magic
}

rule Payload_Magic_e48e8ae6 {
    meta:
        description = "Decoded payload with magic bytes e48e8ae6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e48e8ae6"
        confidence = "high"

    strings:
        $magic = { e4 8e 8a e6 }

    condition:
        $magic
}

rule Payload_Magic_e491aee4 {
    meta:
        description = "Decoded payload with magic bytes e491aee4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e491aee4"
        confidence = "high"

    strings:
        $magic = { e4 91 ae e4 }

    condition:
        $magic
}

rule Payload_Magic_e4af88e9 {
    meta:
        description = "Decoded payload with magic bytes e4af88e9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e4af88e9"
        confidence = "high"

    strings:
        $magic = { e4 af 88 e9 }

    condition:
        $magic
}

rule Payload_Magic_e4b6b3e6 {
    meta:
        description = "Decoded payload with magic bytes e4b6b3e6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e4b6b3e6"
        confidence = "high"

    strings:
        $magic = { e4 b6 b3 e6 }

    condition:
        $magic
}

rule Payload_Magic_e4bc92e4 {
    meta:
        description = "Decoded payload with magic bytes e4bc92e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e4bc92e4"
        confidence = "high"

    strings:
        $magic = { e4 bc 92 e4 }

    condition:
        $magic
}

rule Payload_Magic_e4bd81e4 {
    meta:
        description = "Decoded payload with magic bytes e4bd81e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e4bd81e4"
        confidence = "high"

    strings:
        $magic = { e4 bd 81 e4 }

    condition:
        $magic
}

rule Payload_Magic_e5a73adf {
    meta:
        description = "Decoded payload with magic bytes e5a73adf"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e5a73adf"
        confidence = "high"

    strings:
        $magic = { e5 a7 3a df }

    condition:
        $magic
}

rule Payload_Magic_e5b9ace7 {
    meta:
        description = "Decoded payload with magic bytes e5b9ace7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e5b9ace7"
        confidence = "high"

    strings:
        $magic = { e5 b9 ac e7 }

    condition:
        $magic
}

rule Payload_Magic_e5bca1e6 {
    meta:
        description = "Decoded payload with magic bytes e5bca1e6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e5bca1e6"
        confidence = "high"

    strings:
        $magic = { e5 bc a1 e6 }

    condition:
        $magic
}

rule Payload_Magic_e5bca1e7 {
    meta:
        description = "Decoded payload with magic bytes e5bca1e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e5bca1e7"
        confidence = "high"

    strings:
        $magic = { e5 bc a1 e7 }

    condition:
        $magic
}

rule Payload_Magic_e5bcbee6 {
    meta:
        description = "Decoded payload with magic bytes e5bcbee6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e5bcbee6"
        confidence = "high"

    strings:
        $magic = { e5 bc be e6 }

    condition:
        $magic
}

rule Payload_Magic_e5bdb6f3 {
    meta:
        description = "Decoded payload with magic bytes e5bdb6f3"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e5bdb6f3"
        confidence = "high"

    strings:
        $magic = { e5 bd b6 f3 }

    condition:
        $magic
}

rule Payload_Magic_e5dd3beb {
    meta:
        description = "Decoded payload with magic bytes e5dd3beb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e5dd3beb"
        confidence = "high"

    strings:
        $magic = { e5 dd 3b eb }

    condition:
        $magic
}

rule Payload_Magic_e68889e7 {
    meta:
        description = "Decoded payload with magic bytes e68889e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e68889e7"
        confidence = "high"

    strings:
        $magic = { e6 88 89 e7 }

    condition:
        $magic
}

rule Payload_Magic_e695a9e5 {
    meta:
        description = "Decoded payload with magic bytes e695a9e5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e695a9e5"
        confidence = "high"

    strings:
        $magic = { e6 95 a9 e5 }

    condition:
        $magic
}

rule Payload_Magic_e6ba8ee4 {
    meta:
        description = "Decoded payload with magic bytes e6ba8ee4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e6ba8ee4"
        confidence = "high"

    strings:
        $magic = { e6 ba 8e e4 }

    condition:
        $magic
}

rule Payload_Magic_e6bc90e6 {
    meta:
        description = "Decoded payload with magic bytes e6bc90e6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e6bc90e6"
        confidence = "high"

    strings:
        $magic = { e6 bc 90 e6 }

    condition:
        $magic
}

rule Payload_Magic_e6e36ee6 {
    meta:
        description = "Decoded payload with magic bytes e6e36ee6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "e6e36ee6"
        confidence = "high"

    strings:
        $magic = { e6 e3 6e e6 }

    condition:
        $magic
}

rule Payload_Magic_e77eb769 {
    meta:
        description = "Decoded payload with magic bytes e77eb769"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e77eb769"
        confidence = "high"

    strings:
        $magic = { e7 7e b7 69 }

    condition:
        $magic
}

rule Payload_Magic_e78487e7 {
    meta:
        description = "Decoded payload with magic bytes e78487e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e78487e7"
        confidence = "high"

    strings:
        $magic = { e7 84 87 e7 }

    condition:
        $magic
}

rule Payload_Magic_e789b5e4 {
    meta:
        description = "Decoded payload with magic bytes e789b5e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        magic_bytes = "e789b5e4"
        confidence = "high"

    strings:
        $magic = { e7 89 b5 e4 }

    condition:
        $magic
}

rule Payload_Magic_e78fa4e7 {
    meta:
        description = "Decoded payload with magic bytes e78fa4e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e78fa4e7"
        confidence = "high"

    strings:
        $magic = { e7 8f a4 e7 }

    condition:
        $magic
}

rule Payload_Magic_e799aee4 {
    meta:
        description = "Decoded payload with magic bytes e799aee4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        magic_bytes = "e799aee4"
        confidence = "high"

    strings:
        $magic = { e7 99 ae e4 }

    condition:
        $magic
}

rule Payload_Magic_e79d8ce4 {
    meta:
        description = "Decoded payload with magic bytes e79d8ce4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "e79d8ce4"
        confidence = "high"

    strings:
        $magic = { e7 9d 8c e4 }

    condition:
        $magic
}

rule Payload_Magic_e79f85e8 {
    meta:
        description = "Decoded payload with magic bytes e79f85e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e79f85e8"
        confidence = "high"

    strings:
        $magic = { e7 9f 85 e8 }

    condition:
        $magic
}

rule Payload_Magic_e7b3a0e7 {
    meta:
        description = "Decoded payload with magic bytes e7b3a0e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e7b3a0e7"
        confidence = "high"

    strings:
        $magic = { e7 b3 a0 e7 }

    condition:
        $magic
}

rule Payload_Magic_e7ca91bb {
    meta:
        description = "Decoded payload with magic bytes e7ca91bb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e7ca91bb"
        confidence = "high"

    strings:
        $magic = { e7 ca 91 bb }

    condition:
        $magic
}

rule Payload_Magic_e886bbef {
    meta:
        description = "Decoded payload with magic bytes e886bbef"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e886bbef"
        confidence = "high"

    strings:
        $magic = { e8 86 bb ef }

    condition:
        $magic
}

rule Payload_Magic_e894b6e8 {
    meta:
        description = "Decoded payload with magic bytes e894b6e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        magic_bytes = "e894b6e8"
        confidence = "high"

    strings:
        $magic = { e8 94 b6 e8 }

    condition:
        $magic
}

rule Payload_Magic_e89d81e9 {
    meta:
        description = "Decoded payload with magic bytes e89d81e9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        magic_bytes = "e89d81e9"
        confidence = "high"

    strings:
        $magic = { e8 9d 81 e9 }

    condition:
        $magic
}

rule Payload_Magic_e8b0bb23 {
    meta:
        description = "Decoded payload with magic bytes e8b0bb23"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "e8b0bb23"
        confidence = "high"

    strings:
        $magic = { e8 b0 bb 23 }

    condition:
        $magic
}

rule Payload_Magic_e9aea4e7 {
    meta:
        description = "Decoded payload with magic bytes e9aea4e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e9aea4e7"
        confidence = "high"

    strings:
        $magic = { e9 ae a4 e7 }

    condition:
        $magic
}

rule Payload_Magic_e9aeb6e4 {
    meta:
        description = "Decoded payload with magic bytes e9aeb6e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e9aeb6e4"
        confidence = "high"

    strings:
        $magic = { e9 ae b6 e4 }

    condition:
        $magic
}

rule Payload_Magic_e9aeb6e7 {
    meta:
        description = "Decoded payload with magic bytes e9aeb6e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e9aeb6e7"
        confidence = "high"

    strings:
        $magic = { e9 ae b6 e7 }

    condition:
        $magic
}

rule Payload_Magic_e9bd7b77 {
    meta:
        description = "Decoded payload with magic bytes e9bd7b77"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e9bd7b77"
        confidence = "high"

    strings:
        $magic = { e9 bd 7b 77 }

    condition:
        $magic
}

rule Payload_Magic_e9be99e7 {
    meta:
        description = "Decoded payload with magic bytes e9be99e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "e9be99e7"
        confidence = "high"

    strings:
        $magic = { e9 be 99 e7 }

    condition:
        $magic
}

rule Payload_Magic_e9bf1c7f {
    meta:
        description = "Decoded payload with magic bytes e9bf1c7f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "e9bf1c7f"
        confidence = "high"

    strings:
        $magic = { e9 bf 1c 7f }

    condition:
        $magic
}

rule Payload_Magic_eb475c77 {
    meta:
        description = "Decoded payload with magic bytes eb475c77"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "eb475c77"
        confidence = "high"

    strings:
        $magic = { eb 47 5c 77 }

    condition:
        $magic
}

rule Payload_Magic_ebbf38ef {
    meta:
        description = "Decoded payload with magic bytes ebbf38ef"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "ebbf38ef"
        confidence = "high"

    strings:
        $magic = { eb bf 38 ef }

    condition:
        $magic
}

rule Payload_Magic_eda7bde9 {
    meta:
        description = "Decoded payload with magic bytes eda7bde9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "eda7bde9"
        confidence = "high"

    strings:
        $magic = { ed a7 bd e9 }

    condition:
        $magic
}

rule Payload_Magic_eebd88e7 {
    meta:
        description = "Decoded payload with magic bytes eebd88e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        magic_bytes = "eebd88e7"
        confidence = "high"

    strings:
        $magic = { ee bd 88 e7 }

    condition:
        $magic
}

rule Payload_Magic_ef5d7af5 {
    meta:
        description = "Decoded payload with magic bytes ef5d7af5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "ef5d7af5"
        confidence = "high"

    strings:
        $magic = { ef 5d 7a f5 }

    condition:
        $magic
}

rule Payload_Magic_ef7eb77b {
    meta:
        description = "Decoded payload with magic bytes ef7eb77b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "ef7eb77b"
        confidence = "high"

    strings:
        $magic = { ef 7e b7 7b }

    condition:
        $magic
}

rule Payload_Magic_ef80f9f4 {
    meta:
        description = "Decoded payload with magic bytes ef80f9f4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "ef80f9f4"
        confidence = "high"

    strings:
        $magic = { ef 80 f9 f4 }

    condition:
        $magic
}

rule Payload_Magic_efb13607 {
    meta:
        description = "Decoded payload with magic bytes efb13607"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "efb13607"
        confidence = "high"

    strings:
        $magic = { ef b1 36 07 }

    condition:
        $magic
}

rule Payload_Magic_efb7747f {
    meta:
        description = "Decoded payload with magic bytes efb7747f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "efb7747f"
        confidence = "high"

    strings:
        $magic = { ef b7 74 7f }

    condition:
        $magic
}

rule Payload_Magic_f1ce4851 {
    meta:
        description = "Decoded payload with magic bytes f1ce4851"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "f1ce4851"
        confidence = "high"

    strings:
        $magic = { f1 ce 48 51 }

    condition:
        $magic
}

rule Payload_Magic_f1de75e7 {
    meta:
        description = "Decoded payload with magic bytes f1de75e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f1de75e7"
        confidence = "high"

    strings:
        $magic = { f1 de 75 e7 }

    condition:
        $magic
}

rule Payload_Magic_f2b18e99 {
    meta:
        description = "Decoded payload with magic bytes f2b18e99"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "f2b18e99"
        confidence = "high"

    strings:
        $magic = { f2 b1 8e 99 }

    condition:
        $magic
}

rule Payload_Magic_f39136e4 {
    meta:
        description = "Decoded payload with magic bytes f39136e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f39136e4"
        confidence = "high"

    strings:
        $magic = { f3 91 36 e4 }

    condition:
        $magic
}

rule Payload_Magic_f43105dc {
    meta:
        description = "Decoded payload with magic bytes f43105dc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f43105dc"
        confidence = "high"

    strings:
        $magic = { f4 31 05 dc }

    condition:
        $magic
}

rule Payload_Magic_f5b6b8f1 {
    meta:
        description = "Decoded payload with magic bytes f5b6b8f1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f5b6b8f1"
        confidence = "high"

    strings:
        $magic = { f5 b6 b8 f1 }

    condition:
        $magic
}

rule Payload_Magic_f5c75b77 {
    meta:
        description = "Decoded payload with magic bytes f5c75b77"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f5c75b77"
        confidence = "high"

    strings:
        $magic = { f5 c7 5b 77 }

    condition:
        $magic
}

rule Payload_Magic_f7410017 {
    meta:
        description = "Decoded payload with magic bytes f7410017"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f7410017"
        confidence = "high"

    strings:
        $magic = { f7 41 00 17 }

    condition:
        $magic
}

rule Payload_Magic_f74d3aeb {
    meta:
        description = "Decoded payload with magic bytes f74d3aeb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f74d3aeb"
        confidence = "high"

    strings:
        $magic = { f7 4d 3a eb }

    condition:
        $magic
}

rule Payload_Magic_f75eb67d {
    meta:
        description = "Decoded payload with magic bytes f75eb67d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f75eb67d"
        confidence = "high"

    strings:
        $magic = { f7 5e b6 7d }

    condition:
        $magic
}

rule Payload_Magic_f79e3be5 {
    meta:
        description = "Decoded payload with magic bytes f79e3be5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f79e3be5"
        confidence = "high"

    strings:
        $magic = { f7 9e 3b e5 }

    condition:
        $magic
}

rule Payload_Magic_f7ad9e75 {
    meta:
        description = "Decoded payload with magic bytes f7ad9e75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f7ad9e75"
        confidence = "high"

    strings:
        $magic = { f7 ad 9e 75 }

    condition:
        $magic
}

rule Payload_Magic_f7adf8d5 {
    meta:
        description = "Decoded payload with magic bytes f7adf8d5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f7adf8d5"
        confidence = "high"

    strings:
        $magic = { f7 ad f8 d5 }

    condition:
        $magic
}

rule Payload_Magic_f7beb4e7 {
    meta:
        description = "Decoded payload with magic bytes f7beb4e7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f7beb4e7"
        confidence = "high"

    strings:
        $magic = { f7 be b4 e7 }

    condition:
        $magic
}

rule Payload_Magic_f7ce410f {
    meta:
        description = "Decoded payload with magic bytes f7ce410f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "f7ce410f"
        confidence = "high"

    strings:
        $magic = { f7 ce 41 0f }

    condition:
        $magic
}

rule Payload_Magic_fbc3fe5c {
    meta:
        description = "Decoded payload with magic bytes fbc3fe5c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fbc3fe5c"
        confidence = "high"

    strings:
        $magic = { fb c3 fe 5c }

    condition:
        $magic
}

rule Payload_Magic_fbefbe4f {
    meta:
        description = "Decoded payload with magic bytes fbefbe4f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fbefbe4f"
        confidence = "high"

    strings:
        $magic = { fb ef be 4f }

    condition:
        $magic
}

rule Payload_Magic_fbefbefb {
    meta:
        description = "Decoded payload with magic bytes fbefbefb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fbefbefb"
        confidence = "high"

    strings:
        $magic = { fb ef be fb }

    condition:
        $magic
}

rule Payload_Magic_fbfd76df {
    meta:
        description = "Decoded payload with magic bytes fbfd76df"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "fbfd76df"
        confidence = "high"

    strings:
        $magic = { fb fd 76 df }

    condition:
        $magic
}

rule Payload_Magic_fc238d17 {
    meta:
        description = "Decoded payload with magic bytes fc238d17"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fc238d17"
        confidence = "high"

    strings:
        $magic = { fc 23 8d 17 }

    condition:
        $magic
}

rule Payload_Magic_fd934a4a {
    meta:
        description = "Decoded payload with magic bytes fd934a4a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd934a4a"
        confidence = "high"

    strings:
        $magic = { fd 93 4a 4a }

    condition:
        $magic
}

rule Payload_Magic_fd934ad7 {
    meta:
        description = "Decoded payload with magic bytes fd934ad7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd934ad7"
        confidence = "high"

    strings:
        $magic = { fd 93 4a d7 }

    condition:
        $magic
}

rule Payload_Magic_fd934adb {
    meta:
        description = "Decoded payload with magic bytes fd934adb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd934adb"
        confidence = "high"

    strings:
        $magic = { fd 93 4a db }

    condition:
        $magic
}

rule Payload_Magic_fd934ae9 {
    meta:
        description = "Decoded payload with magic bytes fd934ae9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd934ae9"
        confidence = "high"

    strings:
        $magic = { fd 93 4a e9 }

    condition:
        $magic
}

rule Payload_Magic_fd934aea {
    meta:
        description = "Decoded payload with magic bytes fd934aea"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd934aea"
        confidence = "high"

    strings:
        $magic = { fd 93 4a ea }

    condition:
        $magic
}

rule Payload_Magic_fd934aed {
    meta:
        description = "Decoded payload with magic bytes fd934aed"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd934aed"
        confidence = "high"

    strings:
        $magic = { fd 93 4a ed }

    condition:
        $magic
}

rule Payload_Magic_fd934af4 {
    meta:
        description = "Decoded payload with magic bytes fd934af4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd934af4"
        confidence = "high"

    strings:
        $magic = { fd 93 4a f4 }

    condition:
        $magic
}

rule Payload_Magic_fd934af6 {
    meta:
        description = "Decoded payload with magic bytes fd934af6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd934af6"
        confidence = "high"

    strings:
        $magic = { fd 93 4a f6 }

    condition:
        $magic
}

rule Payload_Magic_fd934af7 {
    meta:
        description = "Decoded payload with magic bytes fd934af7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd934af7"
        confidence = "high"

    strings:
        $magic = { fd 93 4a f7 }

    condition:
        $magic
}

rule Payload_Magic_fd9352b7 {
    meta:
        description = "Decoded payload with magic bytes fd9352b7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        magic_bytes = "fd9352b7"
        confidence = "high"

    strings:
        $magic = { fd 93 52 b7 }

    condition:
        $magic
}

rule Payload_Magic_fd935529 {
    meta:
        description = "Decoded payload with magic bytes fd935529"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd935529"
        confidence = "high"

    strings:
        $magic = { fd 93 55 29 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d0 {
    meta:
        description = "Decoded payload with magic bytes fd9375d0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d0"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d0 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d1 {
    meta:
        description = "Decoded payload with magic bytes fd9375d1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d1"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d1 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d4 {
    meta:
        description = "Decoded payload with magic bytes fd9375d4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d4"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d4 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d5 {
    meta:
        description = "Decoded payload with magic bytes fd9375d5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d5"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d5 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d6 {
    meta:
        description = "Decoded payload with magic bytes fd9375d6"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd9375d6"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d6 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d8 {
    meta:
        description = "Decoded payload with magic bytes fd9375d8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d8"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d8 }

    condition:
        $magic
}

rule Payload_Magic_fd9375d9 {
    meta:
        description = "Decoded payload with magic bytes fd9375d9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375d9"
        confidence = "high"

    strings:
        $magic = { fd 93 75 d9 }

    condition:
        $magic
}

rule Payload_Magic_fd9375da {
    meta:
        description = "Decoded payload with magic bytes fd9375da"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd9375da"
        confidence = "high"

    strings:
        $magic = { fd 93 75 da }

    condition:
        $magic
}

rule Payload_Magic_fd9375dc {
    meta:
        description = "Decoded payload with magic bytes fd9375dc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375dc"
        confidence = "high"

    strings:
        $magic = { fd 93 75 dc }

    condition:
        $magic
}

rule Payload_Magic_fd9375dd {
    meta:
        description = "Decoded payload with magic bytes fd9375dd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375dd"
        confidence = "high"

    strings:
        $magic = { fd 93 75 dd }

    condition:
        $magic
}

rule Payload_Magic_fd9375e0 {
    meta:
        description = "Decoded payload with magic bytes fd9375e0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375e0"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e0 }

    condition:
        $magic
}

rule Payload_Magic_fd9375e1 {
    meta:
        description = "Decoded payload with magic bytes fd9375e1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd9375e1"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e1 }

    condition:
        $magic
}

rule Payload_Magic_fd9375e4 {
    meta:
        description = "Decoded payload with magic bytes fd9375e4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375e4"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e4 }

    condition:
        $magic
}

rule Payload_Magic_fd9375e5 {
    meta:
        description = "Decoded payload with magic bytes fd9375e5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375e5"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e5 }

    condition:
        $magic
}

rule Payload_Magic_fd9375e8 {
    meta:
        description = "Decoded payload with magic bytes fd9375e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375e8"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e8 }

    condition:
        $magic
}

rule Payload_Magic_fd9375e9 {
    meta:
        description = "Decoded payload with magic bytes fd9375e9"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375e9"
        confidence = "high"

    strings:
        $magic = { fd 93 75 e9 }

    condition:
        $magic
}

rule Payload_Magic_fd9375ec {
    meta:
        description = "Decoded payload with magic bytes fd9375ec"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9375ec"
        confidence = "high"

    strings:
        $magic = { fd 93 75 ec }

    condition:
        $magic
}

rule Payload_Magic_fd9375f0 {
    meta:
        description = "Decoded payload with magic bytes fd9375f0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375f0"
        confidence = "high"

    strings:
        $magic = { fd 93 75 f0 }

    condition:
        $magic
}

rule Payload_Magic_fd9375f4 {
    meta:
        description = "Decoded payload with magic bytes fd9375f4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9375f4"
        confidence = "high"

    strings:
        $magic = { fd 93 75 f4 }

    condition:
        $magic
}

rule Payload_Magic_fd9376d0 {
    meta:
        description = "Decoded payload with magic bytes fd9376d0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        magic_bytes = "fd9376d0"
        confidence = "high"

    strings:
        $magic = { fd 93 76 d0 }

    condition:
        $magic
}

rule Payload_Magic_fd9376d1 {
    meta:
        description = "Decoded payload with magic bytes fd9376d1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376d1"
        confidence = "high"

    strings:
        $magic = { fd 93 76 d1 }

    condition:
        $magic
}

rule Payload_Magic_fd9376d4 {
    meta:
        description = "Decoded payload with magic bytes fd9376d4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd9376d4"
        confidence = "high"

    strings:
        $magic = { fd 93 76 d4 }

    condition:
        $magic
}

rule Payload_Magic_fd9376d5 {
    meta:
        description = "Decoded payload with magic bytes fd9376d5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376d5"
        confidence = "high"

    strings:
        $magic = { fd 93 76 d5 }

    condition:
        $magic
}

rule Payload_Magic_fd9376d8 {
    meta:
        description = "Decoded payload with magic bytes fd9376d8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376d8"
        confidence = "high"

    strings:
        $magic = { fd 93 76 d8 }

    condition:
        $magic
}

rule Payload_Magic_fd9376dc {
    meta:
        description = "Decoded payload with magic bytes fd9376dc"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd9376dc"
        confidence = "high"

    strings:
        $magic = { fd 93 76 dc }

    condition:
        $magic
}

rule Payload_Magic_fd9376e0 {
    meta:
        description = "Decoded payload with magic bytes fd9376e0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376e0"
        confidence = "high"

    strings:
        $magic = { fd 93 76 e0 }

    condition:
        $magic
}

rule Payload_Magic_fd9376e8 {
    meta:
        description = "Decoded payload with magic bytes fd9376e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376e8"
        confidence = "high"

    strings:
        $magic = { fd 93 76 e8 }

    condition:
        $magic
}

rule Payload_Magic_fd9376ec {
    meta:
        description = "Decoded payload with magic bytes fd9376ec"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376ec"
        confidence = "high"

    strings:
        $magic = { fd 93 76 ec }

    condition:
        $magic
}

rule Payload_Magic_fd9376ed {
    meta:
        description = "Decoded payload with magic bytes fd9376ed"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376ed"
        confidence = "high"

    strings:
        $magic = { fd 93 76 ed }

    condition:
        $magic
}

rule Payload_Magic_fd9376f4 {
    meta:
        description = "Decoded payload with magic bytes fd9376f4"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9376f4"
        confidence = "high"

    strings:
        $magic = { fd 93 76 f4 }

    condition:
        $magic
}

rule Payload_Magic_fd9376f7 {
    meta:
        description = "Decoded payload with magic bytes fd9376f7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd9376f7"
        confidence = "high"

    strings:
        $magic = { fd 93 76 f7 }

    condition:
        $magic
}

rule Payload_Magic_fd93776a {
    meta:
        description = "Decoded payload with magic bytes fd93776a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd93776a"
        confidence = "high"

    strings:
        $magic = { fd 93 77 6a }

    condition:
        $magic
}

rule Payload_Magic_fd93779d {
    meta:
        description = "Decoded payload with magic bytes fd93779d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd93779d"
        confidence = "high"

    strings:
        $magic = { fd 93 77 9d }

    condition:
        $magic
}

rule Payload_Magic_fd9377ae {
    meta:
        description = "Decoded payload with magic bytes fd9377ae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9377ae"
        confidence = "high"

    strings:
        $magic = { fd 93 77 ae }

    condition:
        $magic
}

rule Payload_Magic_fd9377d0 {
    meta:
        description = "Decoded payload with magic bytes fd9377d0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9377d0"
        confidence = "high"

    strings:
        $magic = { fd 93 77 d0 }

    condition:
        $magic
}

rule Payload_Magic_fd9377d7 {
    meta:
        description = "Decoded payload with magic bytes fd9377d7"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd9377d7"
        confidence = "high"

    strings:
        $magic = { fd 93 77 d7 }

    condition:
        $magic
}

rule Payload_Magic_fd9377d8 {
    meta:
        description = "Decoded payload with magic bytes fd9377d8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9377d8"
        confidence = "high"

    strings:
        $magic = { fd 93 77 d8 }

    condition:
        $magic
}

rule Payload_Magic_fd9377e8 {
    meta:
        description = "Decoded payload with magic bytes fd9377e8"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9377e8"
        confidence = "high"

    strings:
        $magic = { fd 93 77 e8 }

    condition:
        $magic
}

rule Payload_Magic_fd9377f0 {
    meta:
        description = "Decoded payload with magic bytes fd9377f0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9377f0"
        confidence = "high"

    strings:
        $magic = { fd 93 77 f0 }

    condition:
        $magic
}

rule Payload_Magic_fd93780c {
    meta:
        description = "Decoded payload with magic bytes fd93780c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd93780c"
        confidence = "high"

    strings:
        $magic = { fd 93 78 0c }

    condition:
        $magic
}

rule Payload_Magic_fd937830 {
    meta:
        description = "Decoded payload with magic bytes fd937830"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937830"
        confidence = "high"

    strings:
        $magic = { fd 93 78 30 }

    condition:
        $magic
}

rule Payload_Magic_fd937909 {
    meta:
        description = "Decoded payload with magic bytes fd937909"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd937909"
        confidence = "high"

    strings:
        $magic = { fd 93 79 09 }

    condition:
        $magic
}

rule Payload_Magic_fd937945 {
    meta:
        description = "Decoded payload with magic bytes fd937945"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937945"
        confidence = "high"

    strings:
        $magic = { fd 93 79 45 }

    condition:
        $magic
}

rule Payload_Magic_fd937999 {
    meta:
        description = "Decoded payload with magic bytes fd937999"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937999"
        confidence = "high"

    strings:
        $magic = { fd 93 79 99 }

    condition:
        $magic
}

rule Payload_Magic_fd937a4d {
    meta:
        description = "Decoded payload with magic bytes fd937a4d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd937a4d"
        confidence = "high"

    strings:
        $magic = { fd 93 7a 4d }

    condition:
        $magic
}

rule Payload_Magic_fd937a5c {
    meta:
        description = "Decoded payload with magic bytes fd937a5c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937a5c"
        confidence = "high"

    strings:
        $magic = { fd 93 7a 5c }

    condition:
        $magic
}

rule Payload_Magic_fd937a82 {
    meta:
        description = "Decoded payload with magic bytes fd937a82"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd937a82"
        confidence = "high"

    strings:
        $magic = { fd 93 7a 82 }

    condition:
        $magic
}

rule Payload_Magic_fd937a91 {
    meta:
        description = "Decoded payload with magic bytes fd937a91"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937a91"
        confidence = "high"

    strings:
        $magic = { fd 93 7a 91 }

    condition:
        $magic
}

rule Payload_Magic_fd937b48 {
    meta:
        description = "Decoded payload with magic bytes fd937b48"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937b48"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 48 }

    condition:
        $magic
}

rule Payload_Magic_fd937b4a {
    meta:
        description = "Decoded payload with magic bytes fd937b4a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937b4a"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 4a }

    condition:
        $magic
}

rule Payload_Magic_fd937b5c {
    meta:
        description = "Decoded payload with magic bytes fd937b5c"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937b5c"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 5c }

    condition:
        $magic
}

rule Payload_Magic_fd937b6a {
    meta:
        description = "Decoded payload with magic bytes fd937b6a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937b6a"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 6a }

    condition:
        $magic
}

rule Payload_Magic_fd937b72 {
    meta:
        description = "Decoded payload with magic bytes fd937b72"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd937b72"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 72 }

    condition:
        $magic
}

rule Payload_Magic_fd937b9a {
    meta:
        description = "Decoded payload with magic bytes fd937b9a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd937b9a"
        confidence = "high"

    strings:
        $magic = { fd 93 7b 9a }

    condition:
        $magic
}

rule Payload_Magic_fd937bae {
    meta:
        description = "Decoded payload with magic bytes fd937bae"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937bae"
        confidence = "high"

    strings:
        $magic = { fd 93 7b ae }

    condition:
        $magic
}

rule Payload_Magic_fd937bb1 {
    meta:
        description = "Decoded payload with magic bytes fd937bb1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937bb1"
        confidence = "high"

    strings:
        $magic = { fd 93 7b b1 }

    condition:
        $magic
}

rule Payload_Magic_fd937bb2 {
    meta:
        description = "Decoded payload with magic bytes fd937bb2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937bb2"
        confidence = "high"

    strings:
        $magic = { fd 93 7b b2 }

    condition:
        $magic
}

rule Payload_Magic_fd937c0e {
    meta:
        description = "Decoded payload with magic bytes fd937c0e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937c0e"
        confidence = "high"

    strings:
        $magic = { fd 93 7c 0e }

    condition:
        $magic
}

rule Payload_Magic_fd937c4a {
    meta:
        description = "Decoded payload with magic bytes fd937c4a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937c4a"
        confidence = "high"

    strings:
        $magic = { fd 93 7c 4a }

    condition:
        $magic
}

rule Payload_Magic_fd937c58 {
    meta:
        description = "Decoded payload with magic bytes fd937c58"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd937c58"
        confidence = "high"

    strings:
        $magic = { fd 93 7c 58 }

    condition:
        $magic
}

rule Payload_Magic_fd937d0a {
    meta:
        description = "Decoded payload with magic bytes fd937d0a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937d0a"
        confidence = "high"

    strings:
        $magic = { fd 93 7d 0a }

    condition:
        $magic
}

rule Payload_Magic_fd937d14 {
    meta:
        description = "Decoded payload with magic bytes fd937d14"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937d14"
        confidence = "high"

    strings:
        $magic = { fd 93 7d 14 }

    condition:
        $magic
}

rule Payload_Magic_fd937d35 {
    meta:
        description = "Decoded payload with magic bytes fd937d35"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937d35"
        confidence = "high"

    strings:
        $magic = { fd 93 7d 35 }

    condition:
        $magic
}

rule Payload_Magic_fd937d4a {
    meta:
        description = "Decoded payload with magic bytes fd937d4a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937d4a"
        confidence = "high"

    strings:
        $magic = { fd 93 7d 4a }

    condition:
        $magic
}

rule Payload_Magic_fd937d51 {
    meta:
        description = "Decoded payload with magic bytes fd937d51"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd937d51"
        confidence = "high"

    strings:
        $magic = { fd 93 7d 51 }

    condition:
        $magic
}

rule Payload_Magic_fd937db2 {
    meta:
        description = "Decoded payload with magic bytes fd937db2"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd937db2"
        confidence = "high"

    strings:
        $magic = { fd 93 7d b2 }

    condition:
        $magic
}

rule Payload_Magic_fd937db5 {
    meta:
        description = "Decoded payload with magic bytes fd937db5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd937db5"
        confidence = "high"

    strings:
        $magic = { fd 93 7d b5 }

    condition:
        $magic
}

rule Payload_Magic_fd937dff {
    meta:
        description = "Decoded payload with magic bytes fd937dff"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd937dff"
        confidence = "high"

    strings:
        $magic = { fd 93 7d ff }

    condition:
        $magic
}

rule Payload_Magic_fd94ad9d {
    meta:
        description = "Decoded payload with magic bytes fd94ad9d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd94ad9d"
        confidence = "high"

    strings:
        $magic = { fd 94 ad 9d }

    condition:
        $magic
}

rule Payload_Magic_fd94addb {
    meta:
        description = "Decoded payload with magic bytes fd94addb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd94addb"
        confidence = "high"

    strings:
        $magic = { fd 94 ad db }

    condition:
        $magic
}

rule Payload_Magic_fd94adde {
    meta:
        description = "Decoded payload with magic bytes fd94adde"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd94adde"
        confidence = "high"

    strings:
        $magic = { fd 94 ad de }

    condition:
        $magic
}

rule Payload_Magic_fd94ade1 {
    meta:
        description = "Decoded payload with magic bytes fd94ade1"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        magic_bytes = "fd94ade1"
        confidence = "high"

    strings:
        $magic = { fd 94 ad e1 }

    condition:
        $magic
}

rule Payload_Magic_fd94aded {
    meta:
        description = "Decoded payload with magic bytes fd94aded"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        magic_bytes = "fd94aded"
        confidence = "high"

    strings:
        $magic = { fd 94 ad ed }

    condition:
        $magic
}

rule Payload_Magic_fd94c837 {
    meta:
        description = "Decoded payload with magic bytes fd94c837"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd94c837"
        confidence = "high"

    strings:
        $magic = { fd 94 c8 37 }

    condition:
        $magic
}

rule Payload_Magic_fd94c84a {
    meta:
        description = "Decoded payload with magic bytes fd94c84a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd94c84a"
        confidence = "high"

    strings:
        $magic = { fd 94 c8 4a }

    condition:
        $magic
}

rule Payload_Magic_fd94d237 {
    meta:
        description = "Decoded payload with magic bytes fd94d237"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd94d237"
        confidence = "high"

    strings:
        $magic = { fd 94 d2 37 }

    condition:
        $magic
}

rule Payload_Magic_fd94d24a {
    meta:
        description = "Decoded payload with magic bytes fd94d24a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd94d24a"
        confidence = "high"

    strings:
        $magic = { fd 94 d2 4a }

    condition:
        $magic
}

rule Payload_Magic_fd94d537 {
    meta:
        description = "Decoded payload with magic bytes fd94d537"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd94d537"
        confidence = "high"

    strings:
        $magic = { fd 94 d5 37 }

    condition:
        $magic
}

rule Payload_Magic_fd94d54a {
    meta:
        description = "Decoded payload with magic bytes fd94d54a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd94d54a"
        confidence = "high"

    strings:
        $magic = { fd 94 d5 4a }

    condition:
        $magic
}

rule Payload_Magic_fd94e19f {
    meta:
        description = "Decoded payload with magic bytes fd94e19f"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd94e19f"
        confidence = "high"

    strings:
        $magic = { fd 94 e1 9f }

    condition:
        $magic
}

rule Payload_Magic_fd964d2b {
    meta:
        description = "Decoded payload with magic bytes fd964d2b"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd964d2b"
        confidence = "high"

    strings:
        $magic = { fd 96 4d 2b }

    condition:
        $magic
}

rule Payload_Magic_fd964de0 {
    meta:
        description = "Decoded payload with magic bytes fd964de0"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd964de0"
        confidence = "high"

    strings:
        $magic = { fd 96 4d e0 }

    condition:
        $magic
}

rule Payload_Magic_fd964ded {
    meta:
        description = "Decoded payload with magic bytes fd964ded"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd964ded"
        confidence = "high"

    strings:
        $magic = { fd 96 4d ed }

    condition:
        $magic
}

rule Payload_Magic_fd9d7876 {
    meta:
        description = "Decoded payload with magic bytes fd9d7876"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd9d7876"
        confidence = "high"

    strings:
        $magic = { fd 9d 78 76 }

    condition:
        $magic
}

rule Payload_Magic_fd9d7a75 {
    meta:
        description = "Decoded payload with magic bytes fd9d7a75"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd9d7a75"
        confidence = "high"

    strings:
        $magic = { fd 9d 7a 75 }

    condition:
        $magic
}

rule Payload_Magic_fd9d7a76 {
    meta:
        description = "Decoded payload with magic bytes fd9d7a76"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd9d7a76"
        confidence = "high"

    strings:
        $magic = { fd 9d 7a 76 }

    condition:
        $magic
}

rule Payload_Magic_fd9d7a8d {
    meta:
        description = "Decoded payload with magic bytes fd9d7a8d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd9d7a8d"
        confidence = "high"

    strings:
        $magic = { fd 9d 7a 8d }

    condition:
        $magic
}

rule Payload_Magic_fd9d7b0d {
    meta:
        description = "Decoded payload with magic bytes fd9d7b0d"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9d7b0d"
        confidence = "high"

    strings:
        $magic = { fd 9d 7b 0d }

    condition:
        $magic
}

rule Payload_Magic_fd9d7b8e {
    meta:
        description = "Decoded payload with magic bytes fd9d7b8e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fd9d7b8e"
        confidence = "high"

    strings:
        $magic = { fd 9d 7b 8e }

    condition:
        $magic
}

rule Payload_Magic_fd9db43e {
    meta:
        description = "Decoded payload with magic bytes fd9db43e"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9db43e"
        confidence = "high"

    strings:
        $magic = { fd 9d b4 3e }

    condition:
        $magic
}

rule Payload_Magic_fd9db576 {
    meta:
        description = "Decoded payload with magic bytes fd9db576"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        magic_bytes = "fd9db576"
        confidence = "high"

    strings:
        $magic = { fd 9d b5 76 }

    condition:
        $magic
}

rule Payload_Magic_fd9db619 {
    meta:
        description = "Decoded payload with magic bytes fd9db619"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9db619"
        confidence = "high"

    strings:
        $magic = { fd 9d b6 19 }

    condition:
        $magic
}

rule Payload_Magic_fd9db622 {
    meta:
        description = "Decoded payload with magic bytes fd9db622"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9db622"
        confidence = "high"

    strings:
        $magic = { fd 9d b6 22 }

    condition:
        $magic
}

rule Payload_Magic_fd9db772 {
    meta:
        description = "Decoded payload with magic bytes fd9db772"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "fd9db772"
        confidence = "high"

    strings:
        $magic = { fd 9d b7 72 }

    condition:
        $magic
}

rule Payload_Magic_fd9dbc0a {
    meta:
        description = "Decoded payload with magic bytes fd9dbc0a"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9dbc0a"
        confidence = "high"

    strings:
        $magic = { fd 9d bc 0a }

    condition:
        $magic
}

rule Payload_Magic_fd9ec075 {
    meta:
        description = "Decoded payload with magic bytes fd9ec075"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "air.com.aaaedu.doubleenphonetic"
        magic_bytes = "fd9ec075"
        confidence = "high"

    strings:
        $magic = { fd 9e c0 75 }

    condition:
        $magic
}

rule Payload_Magic_feccacb5 {
    meta:
        description = "Decoded payload with magic bytes feccacb5"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        magic_bytes = "feccacb5"
        confidence = "high"

    strings:
        $magic = { fe cc ac b5 }

    condition:
        $magic
}

rule Payload_Magic_feccacfd {
    meta:
        description = "Decoded payload with magic bytes feccacfd"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        magic_bytes = "feccacfd"
        confidence = "high"

    strings:
        $magic = { fe cc ac fd }

    condition:
        $magic
}

rule Payload_Magic_feeb2bfe {
    meta:
        description = "Decoded payload with magic bytes feeb2bfe"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "feeb2bfe"
        confidence = "high"

    strings:
        $magic = { fe eb 2b fe }

    condition:
        $magic
}

rule Payload_Magic_fff827bb {
    meta:
        description = "Decoded payload with magic bytes fff827bb"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        magic_bytes = "fff827bb"
        confidence = "high"

    strings:
        $magic = { ff f8 27 bb }

    condition:
        $magic
}

rule C2_Domain_139199_com {
    meta:
        description = "C2 domain pattern for com.taolimogucun.dkdk"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.taolimogucun.dkdk"
        c2_domain = "139199.com"
        confidence = "medium"

    strings:
        $domain = "139199.com"

    condition:
        $domain
}

rule C2_Domain_189_cn {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "189.cn"
        confidence = "medium"

    strings:
        $domain = "189.cn"

    condition:
        $domain
}

rule C2_Domain_2cto_com {
    meta:
        description = "C2 domain pattern for com.ww.share"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.ww.share"
        c2_domain = "2cto.com"
        confidence = "medium"

    strings:
        $domain = "2cto.com"

    condition:
        $domain
}

rule C2_Domain_5j5l_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "5j5l.com"
        confidence = "medium"

    strings:
        $domain = "5j5l.com"

    condition:
        $domain
}

rule C2_Domain_5k3g_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "5k3g.com"
        confidence = "medium"

    strings:
        $domain = "5k3g.com"

    condition:
        $domain
}

rule C2_Domain_91_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "91.com"
        confidence = "medium"

    strings:
        $domain = "91.com"

    condition:
        $domain
}

rule C2_Domain_a_ {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "a."
        confidence = "medium"

    strings:
        $domain = "a."

    condition:
        $domain
}

rule C2_Domain_acs86_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "acs86.com"
        confidence = "medium"

    strings:
        $domain = "acs86.com"

    condition:
        $domain
}

rule C2_Domain_adcolony_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "adcolony.com"
        confidence = "medium"

    strings:
        $domain = "adcolony.com"

    condition:
        $domain
}

rule C2_Domain_adcome_cn {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "adcome.cn"
        confidence = "medium"

    strings:
        $domain = "adcome.cn"

    condition:
        $domain
}

rule C2_Domain_admarket_mobi {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "admarket.mobi"
        confidence = "medium"

    strings:
        $domain = "admarket.mobi"

    condition:
        $domain
}

rule C2_Domain_admob_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "13"
        family = "multi-family"
        c2_domain = "admob.com"
        confidence = "medium"

    strings:
        $domain = "admob.com"

    condition:
        $domain
}

rule C2_Domain_adobe_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "adobe.com"
        confidence = "medium"

    strings:
        $domain = "adobe.com"

    condition:
        $domain
}

rule C2_Domain_adsmogo_com {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "adsmogo.com"
        confidence = "medium"

    strings:
        $domain = "adsmogo.com"

    condition:
        $domain
}

rule C2_Domain_adview_cn {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "adview.cn"
        confidence = "medium"

    strings:
        $domain = "adview.cn"

    condition:
        $domain
}

rule C2_Domain_adwaken_cn {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "adwaken.cn"
        confidence = "medium"

    strings:
        $domain = "adwaken.cn"

    condition:
        $domain
}

rule C2_Domain_adwhirl_com {
    meta:
        description = "C2 domain pattern for com.acevireally.firsttvinnytheviking"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        c2_domain = "adwhirl.com"
        confidence = "medium"

    strings:
        $domain = "adwhirl.com"

    condition:
        $domain
}

rule C2_Domain_adwo_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "adwo.com"
        confidence = "medium"

    strings:
        $domain = "adwo.com"

    condition:
        $domain
}

rule C2_Domain_airpopt_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "airpopt.net"
        confidence = "medium"

    strings:
        $domain = "airpopt.net"

    condition:
        $domain
}

rule C2_Domain_airpush_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "9"
        family = "unknown"
        c2_domain = "airpush.com"
        confidence = "medium"

    strings:
        $domain = "airpush.com"

    condition:
        $domain
}

rule C2_Domain_alipay_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "alipay.com"
        confidence = "medium"

    strings:
        $domain = "alipay.com"

    condition:
        $domain
}

rule C2_Domain_amap_com {
    meta:
        description = "C2 domain pattern for cn.net.cnea.transportcapacitycooldemo"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        c2_domain = "amap.com"
        confidence = "medium"

    strings:
        $domain = "amap.com"

    condition:
        $domain
}

rule C2_Domain_amazon_adsystem_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "amazon-adsystem.com"
        confidence = "medium"

    strings:
        $domain = "amazon-adsystem.com"

    condition:
        $domain
}

rule C2_Domain_amazonaws_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "amazonaws.com"
        confidence = "medium"

    strings:
        $domain = "amazonaws.com"

    condition:
        $domain
}

rule C2_Domain_amoneron_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "amoneron.com"
        confidence = "medium"

    strings:
        $domain = "amoneron.com"

    condition:
        $domain
}

rule C2_Domain_android_antivir_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "android-antivir.com"
        confidence = "medium"

    strings:
        $domain = "android-antivir.com"

    condition:
        $domain
}

rule C2_Domain_android_app_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "android-app.ru"
        confidence = "medium"

    strings:
        $domain = "android-app.ru"

    condition:
        $domain
}

rule C2_Domain_android_supermarket_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "android-supermarket.com"
        confidence = "medium"

    strings:
        $domain = "android-supermarket.com"

    condition:
        $domain
}

rule C2_Domain_androiddoctor_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "androiddoctor.com"
        confidence = "medium"

    strings:
        $domain = "androiddoctor.com"

    condition:
        $domain
}

rule C2_Domain_androids_market_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "androids-market.ru"
        confidence = "medium"

    strings:
        $domain = "androids-market.ru"

    condition:
        $domain
}

rule C2_Domain_androidze_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "androidze.ru"
        confidence = "medium"

    strings:
        $domain = "androidze.ru"

    condition:
        $domain
}

rule C2_Domain_app2ad_com {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "app2ad.com"
        confidence = "medium"

    strings:
        $domain = "app2ad.com"

    condition:
        $domain
}

rule C2_Domain_appbrain_com {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "appbrain.com"
        confidence = "medium"

    strings:
        $domain = "appbrain.com"

    condition:
        $domain
}

rule C2_Domain_appbrain_com_http {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "appbrain.com,http"
        confidence = "medium"

    strings:
        $domain = "appbrain.com,http"

    condition:
        $domain
}

rule C2_Domain_appdriver_jp {
    meta:
        description = "C2 domain pattern for com.taolimogucun.dkdk"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.taolimogucun.dkdk"
        c2_domain = "appdriver.jp"
        confidence = "medium"

    strings:
        $domain = "appdriver.jp"

    condition:
        $domain
}

rule C2_Domain_apperhand_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "apperhand.com"
        confidence = "medium"

    strings:
        $domain = "apperhand.com"

    condition:
        $domain
}

rule C2_Domain_apple_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "apple.com"
        confidence = "medium"

    strings:
        $domain = "apple.com"

    condition:
        $domain
}

rule C2_Domain_applovin_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "applovin.com"
        confidence = "medium"

    strings:
        $domain = "applovin.com"

    condition:
        $domain
}

rule C2_Domain_appmob_cn {
    meta:
        description = "C2 domain pattern for com.taolimogucun.dkdk"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.taolimogucun.dkdk"
        c2_domain = "appmob.cn"
        confidence = "medium"

    strings:
        $domain = "appmob.cn"

    condition:
        $domain
}

rule C2_Domain_appodeal_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "appodeal.com"
        confidence = "medium"

    strings:
        $domain = "appodeal.com"

    condition:
        $domain
}

rule C2_Domain_appsgeyser_com {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "appsgeyser.com"
        confidence = "medium"

    strings:
        $domain = "appsgeyser.com"

    condition:
        $domain
}

rule C2_Domain_appspot_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "appspot.com"
        confidence = "medium"

    strings:
        $domain = "appspot.com"

    condition:
        $domain
}

rule C2_Domain_apptornado_com {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "apptornado.com"
        confidence = "medium"

    strings:
        $domain = "apptornado.com"

    condition:
        $domain
}

rule C2_Domain_apptornado_com_http {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "apptornado.com,http"
        confidence = "medium"

    strings:
        $domain = "apptornado.com,http"

    condition:
        $domain
}

rule C2_Domain_autonavi_com {
    meta:
        description = "C2 domain pattern for cn.net.cnea.transportcapacitycooldemo"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        c2_domain = "autonavi.com"
        confidence = "medium"

    strings:
        $domain = "autonavi.com"

    condition:
        $domain
}

rule C2_Domain_avocarrot_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "avocarrot.com"
        confidence = "medium"

    strings:
        $domain = "avocarrot.com"

    condition:
        $domain
}

rule C2_Domain_banota_info {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "banota.info"
        confidence = "medium"

    strings:
        $domain = "banota.info"

    condition:
        $domain
}

rule C2_Domain_battery_updates_android_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "battery-updates-android.net"
        confidence = "medium"

    strings:
        $domain = "battery-updates-android.net"

    condition:
        $domain
}

rule C2_Domain_besserwissen_biz {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "besserwissen.biz"
        confidence = "medium"

    strings:
        $domain = "besserwissen.biz"

    condition:
        $domain
}

rule C2_Domain_bihe0832_com {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "bihe0832.com"
        confidence = "medium"

    strings:
        $domain = "bihe0832.com"

    condition:
        $domain
}

rule C2_Domain_bit_ly {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "bit.ly"
        confidence = "medium"

    strings:
        $domain = "bit.ly"

    condition:
        $domain
}

rule C2_Domain_blackflyday_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "blackflyday.com"
        confidence = "medium"

    strings:
        $domain = "blackflyday.com"

    condition:
        $domain
}

rule C2_Domain_casee_cn {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "casee.cn"
        confidence = "medium"

    strings:
        $domain = "casee.cn"

    condition:
        $domain
}

rule C2_Domain_cfg_ {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "cfg."
        confidence = "medium"

    strings:
        $domain = "cfg."

    condition:
        $domain
}

rule C2_Domain_chartboost_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "chartboost.com"
        confidence = "medium"

    strings:
        $domain = "chartboost.com"

    condition:
        $domain
}

rule C2_Domain_clk_ {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "clk."
        confidence = "medium"

    strings:
        $domain = "clk."

    condition:
        $domain
}

rule C2_Domain_cloudfront_net {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "cloudfront.net"
        confidence = "medium"

    strings:
        $domain = "cloudfront.net"

    condition:
        $domain
}

rule C2_Domain_cmeuivl_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "cmeuivl.com"
        confidence = "medium"

    strings:
        $domain = "cmeuivl.com"

    condition:
        $domain
}

rule C2_Domain_cnzz_com {
    meta:
        description = "C2 domain pattern for com.dksmdz.model"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.dksmdz.model"
        c2_domain = "cnzz.com"
        confidence = "medium"

    strings:
        $domain = "cnzz.com"

    condition:
        $domain
}

rule C2_Domain_co_jp {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "co.jp"
        confidence = "medium"

    strings:
        $domain = "co.jp"

    condition:
        $domain
}

rule C2_Domain_com_ {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "com."
        confidence = "medium"

    strings:
        $domain = "com."

    condition:
        $domain
}

rule C2_Domain_com_cn {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "com.cn"
        confidence = "medium"

    strings:
        $domain = "com.cn"

    condition:
        $domain
}

rule C2_Domain_com_hk {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "com.hk"
        confidence = "medium"

    strings:
        $domain = "com.hk"

    condition:
        $domain
}

rule C2_Domain_cooguo_com {
    meta:
        description = "C2 domain pattern for com.acevireally.firsttvinnytheviking"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        c2_domain = "cooguo.com"
        confidence = "medium"

    strings:
        $domain = "cooguo.com"

    condition:
        $domain
}

rule C2_Domain_coolcode_org {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "coolcode.org"
        confidence = "medium"

    strings:
        $domain = "coolcode.org"

    condition:
        $domain
}

rule C2_Domain_cus_ {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "cus."
        confidence = "medium"

    strings:
        $domain = "cus."

    condition:
        $domain
}

rule C2_Domain_dalo3a_info {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "dalo3a.info"
        confidence = "medium"

    strings:
        $domain = "dalo3a.info"

    condition:
        $domain
}

rule C2_Domain_daneden_me {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "daneden.me"
        confidence = "medium"

    strings:
        $domain = "daneden.me"

    condition:
        $domain
}

rule C2_Domain_depositmobi_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "unknown"
        c2_domain = "depositmobi.com"
        confidence = "medium"

    strings:
        $domain = "depositmobi.com"

    condition:
        $domain
}

rule C2_Domain_domob_cn {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "domob.cn"
        confidence = "medium"

    strings:
        $domain = "domob.cn"

    condition:
        $domain
}

rule C2_Domain_doubleclick_net {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "doubleclick.net"
        confidence = "medium"

    strings:
        $domain = "doubleclick.net"

    condition:
        $domain
}

rule C2_Domain_droidsettings_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "droidsettings.com"
        confidence = "medium"

    strings:
        $domain = "droidsettings.com"

    condition:
        $domain
}

rule C2_Domain_dummy_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "dummy.com"
        confidence = "medium"

    strings:
        $domain = "dummy.com"

    condition:
        $domain
}

rule C2_Domain_emulab_it {
    meta:
        description = "C2 domain pattern for com.sdfasdwer.madgear"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        c2_domain = "emulab.it"
        confidence = "medium"

    strings:
        $domain = "emulab.it"

    condition:
        $domain
}

rule C2_Domain_erotte_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "erotte.com"
        confidence = "medium"

    strings:
        $domain = "erotte.com"

    condition:
        $domain
}

rule C2_Domain_evil_domain_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "evil-domain.com"
        confidence = "medium"

    strings:
        $domain = "evil-domain.com"

    condition:
        $domain
}

rule C2_Domain_example_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "example.com"
        confidence = "medium"

    strings:
        $domain = "example.com"

    condition:
        $domain
}

rule C2_Domain_facebook_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "facebook.com"
        confidence = "medium"

    strings:
        $domain = "facebook.com"

    condition:
        $domain
}

rule C2_Domain_firebaseio_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "firebaseio.com"
        confidence = "medium"

    strings:
        $domain = "firebaseio.com"

    condition:
        $domain
}

rule C2_Domain_flurry_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "flurry.com"
        confidence = "medium"

    strings:
        $domain = "flurry.com"

    condition:
        $domain
}

rule C2_Domain_free_bg {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "free.bg"
        confidence = "medium"

    strings:
        $domain = "free.bg"

    condition:
        $domain
}

rule C2_Domain_freeprivacypolicy_com {
    meta:
        description = "C2 domain pattern for com.hash.locationrecord"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        c2_domain = "freeprivacypolicy.com"
        confidence = "medium"

    strings:
        $domain = "freeprivacypolicy.com"

    condition:
        $domain
}

rule C2_Domain_ggpht_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "ggpht.com"
        confidence = "medium"

    strings:
        $domain = "ggpht.com"

    condition:
        $domain
}

rule C2_Domain_github_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "github.com"
        confidence = "medium"

    strings:
        $domain = "github.com"

    condition:
        $domain
}

rule C2_Domain_gnu_org {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "gnu.org"
        confidence = "medium"

    strings:
        $domain = "gnu.org"

    condition:
        $domain
}

rule C2_Domain_go360days_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "go360days.com"
        confidence = "medium"

    strings:
        $domain = "go360days.com"

    condition:
        $domain
}

rule C2_Domain_goo_gl {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "goo.gl"
        confidence = "medium"

    strings:
        $domain = "goo.gl"

    condition:
        $domain
}

rule C2_Domain_google_analytics_com {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "google-analytics.com"
        confidence = "medium"

    strings:
        $domain = "google-analytics.com"

    condition:
        $domain
}

rule C2_Domain_google_cn {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "google.cn"
        confidence = "medium"

    strings:
        $domain = "google.cn"

    condition:
        $domain
}

rule C2_Domain_google_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "google.com"
        confidence = "medium"

    strings:
        $domain = "google.com"

    condition:
        $domain
}

rule C2_Domain_googleadservices_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "googleadservices.com"
        confidence = "medium"

    strings:
        $domain = "googleadservices.com"

    condition:
        $domain
}

rule C2_Domain_googleplex_com {
    meta:
        description = "C2 domain pattern for com.andan.mgtxpmgtx"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        c2_domain = "googleplex.com"
        confidence = "medium"

    strings:
        $domain = "googleplex.com"

    condition:
        $domain
}

rule C2_Domain_googlesyndication_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "googlesyndication.com"
        confidence = "medium"

    strings:
        $domain = "googlesyndication.com"

    condition:
        $domain
}

rule C2_Domain_googletagmanager_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "googletagmanager.com"
        confidence = "medium"

    strings:
        $domain = "googletagmanager.com"

    condition:
        $domain
}

rule C2_Domain_gp_imports_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "gp-imports.com"
        confidence = "medium"

    strings:
        $domain = "gp-imports.com"

    condition:
        $domain
}

rule C2_Domain_greenrobotstudios_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "greenrobotstudios.com"
        confidence = "medium"

    strings:
        $domain = "greenrobotstudios.com"

    condition:
        $domain
}

rule C2_Domain_gtimg_cn {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "gtimg.cn"
        confidence = "medium"

    strings:
        $domain = "gtimg.cn"

    condition:
        $domain
}

rule C2_Domain_gtimg_com {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "gtimg.com"
        confidence = "medium"

    strings:
        $domain = "gtimg.com"

    condition:
        $domain
}

rule C2_Domain_guohead_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "guohead.com"
        confidence = "medium"

    strings:
        $domain = "guohead.com"

    condition:
        $domain
}

rule C2_Domain_haxx_se {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "haxx.se"
        confidence = "medium"

    strings:
        $domain = "haxx.se"

    condition:
        $domain
}

rule C2_Domain_huanhaola_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "huanhaola.com"
        confidence = "medium"

    strings:
        $domain = "huanhaola.com"

    condition:
        $domain
}

rule C2_Domain_iccto_com {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "iccto.com"
        confidence = "medium"

    strings:
        $domain = "iccto.com"

    condition:
        $domain
}

rule C2_Domain_iccto_net {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "iccto.net"
        confidence = "medium"

    strings:
        $domain = "iccto.net"

    condition:
        $domain
}

rule C2_Domain_icittys_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "icittys.com"
        confidence = "medium"

    strings:
        $domain = "icittys.com"

    condition:
        $domain
}

rule C2_Domain_iconosys_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "iconosys.com"
        confidence = "medium"

    strings:
        $domain = "iconosys.com"

    condition:
        $domain
}

rule C2_Domain_immob_cn {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "immob.cn"
        confidence = "medium"

    strings:
        $domain = "immob.cn"

    condition:
        $domain
}

rule C2_Domain_imp_ {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "imp."
        confidence = "medium"

    strings:
        $domain = "imp."

    condition:
        $domain
}

rule C2_Domain_inmobi_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "inmobi.com"
        confidence = "medium"

    strings:
        $domain = "inmobi.com"

    condition:
        $domain
}

rule C2_Domain_io_doucmentsource {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "io.doucmentsource"
        confidence = "medium"

    strings:
        $domain = "io.doucmentsource"

    condition:
        $domain
}

rule C2_Domain_jiguang_cn {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "jiguang.cn"
        confidence = "medium"

    strings:
        $domain = "jiguang.cn"

    condition:
        $domain
}

rule C2_Domain_jjdd_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "jjdd.com"
        confidence = "medium"

    strings:
        $domain = "jjdd.com"

    condition:
        $domain
}

rule C2_Domain_jpush_cn {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "jpush.cn"
        confidence = "medium"

    strings:
        $domain = "jpush.cn"

    condition:
        $domain
}

rule C2_Domain_ju6666_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "ju6666.com"
        confidence = "medium"

    strings:
        $domain = "ju6666.com"

    condition:
        $domain
}

rule C2_Domain_lanteanstudio_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "lanteanstudio.com"
        confidence = "medium"

    strings:
        $domain = "lanteanstudio.com"

    condition:
        $domain
}

rule C2_Domain_leadbolt_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "unknown"
        c2_domain = "leadbolt.net"
        confidence = "medium"

    strings:
        $domain = "leadbolt.net"

    condition:
        $domain
}

rule C2_Domain_leadboltapps_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "unknown"
        c2_domain = "leadboltapps.net"
        confidence = "medium"

    strings:
        $domain = "leadboltapps.net"

    condition:
        $domain
}

rule C2_Domain_lensfor_xyz {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "lensfor.xyz"
        confidence = "medium"

    strings:
        $domain = "lensfor.xyz"

    condition:
        $domain
}

rule C2_Domain_loadwtds_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "loadwtds.ru"
        confidence = "medium"

    strings:
        $domain = "loadwtds.ru"

    condition:
        $domain
}

rule C2_Domain_m_001_net {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "m-001.net"
        confidence = "medium"

    strings:
        $domain = "m-001.net"

    condition:
        $domain
}

rule C2_Domain_m_maps {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "m.maps"
        confidence = "medium"

    strings:
        $domain = "m.maps"

    condition:
        $domain
}

rule C2_Domain_macromedia_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "macromedia.com"
        confidence = "medium"

    strings:
        $domain = "macromedia.com"

    condition:
        $domain
}

rule C2_Domain_mail_ru {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "mail.ru"
        confidence = "medium"

    strings:
        $domain = "mail.ru"

    condition:
        $domain
}

rule C2_Domain_maps_google {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "maps.google"
        confidence = "medium"

    strings:
        $domain = "maps.google"

    condition:
        $domain
}

rule C2_Domain_market_android {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "market.android"
        confidence = "medium"

    strings:
        $domain = "market.android"

    condition:
        $domain
}

rule C2_Domain_memoapps_info {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "memoapps.info"
        confidence = "medium"

    strings:
        $domain = "memoapps.info"

    condition:
        $domain
}

rule C2_Domain_millennialmedia_com {
    meta:
        description = "C2 domain pattern for com.acevireally.firsttvinnytheviking"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        c2_domain = "millennialmedia.com"
        confidence = "medium"

    strings:
        $domain = "millennialmedia.com"

    condition:
        $domain
}

rule C2_Domain_mixpanel_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "mixpanel.com"
        confidence = "medium"

    strings:
        $domain = "mixpanel.com"

    condition:
        $domain
}

rule C2_Domain_mobfox_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "mobfox.com"
        confidence = "medium"

    strings:
        $domain = "mobfox.com"

    condition:
        $domain
}

rule C2_Domain_mobi911_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "5"
        family = "unknown"
        c2_domain = "mobi911.ru"
        confidence = "medium"

    strings:
        $domain = "mobi911.ru"

    condition:
        $domain
}

rule C2_Domain_mobile_maps {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "mobile.maps"
        confidence = "medium"

    strings:
        $domain = "mobile.maps"

    condition:
        $domain
}

rule C2_Domain_mobilehotdog_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "mobilehotdog.com"
        confidence = "medium"

    strings:
        $domain = "mobilehotdog.com"

    condition:
        $domain
}

rule C2_Domain_monternet_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "monternet.com"
        confidence = "medium"

    strings:
        $domain = "monternet.com"

    condition:
        $domain
}

rule C2_Domain_mopub_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "mopub.com"
        confidence = "medium"

    strings:
        $domain = "mopub.com"

    condition:
        $domain
}

rule C2_Domain_motorola_com {
    meta:
        description = "C2 domain pattern for com.acevireally.firsttvinnytheviking"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        c2_domain = "motorola.com"
        confidence = "medium"

    strings:
        $domain = "motorola.com"

    condition:
        $domain
}

rule C2_Domain_mts_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "mts.ru"
        confidence = "medium"

    strings:
        $domain = "mts.ru"

    condition:
        $domain
}

rule C2_Domain_my_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "my.com"
        confidence = "medium"

    strings:
        $domain = "my.com"

    condition:
        $domain
}

rule C2_Domain_myapp_com {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "myapp.com"
        confidence = "medium"

    strings:
        $domain = "myapp.com"

    condition:
        $domain
}

rule C2_Domain_mydas_mobi {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "mydas.mobi"
        confidence = "medium"

    strings:
        $domain = "mydas.mobi"

    condition:
        $domain
}

rule C2_Domain_myspace_com {
    meta:
        description = "C2 domain pattern for com.andan.mgtxpmgtx"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        c2_domain = "myspace.com"
        confidence = "medium"

    strings:
        $domain = "myspace.com"

    condition:
        $domain
}

rule C2_Domain_nashamarkets_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "nashamarkets.ru"
        confidence = "medium"

    strings:
        $domain = "nashamarkets.ru"

    condition:
        $domain
}

rule C2_Domain_openfeint_com {
    meta:
        description = "C2 domain pattern for com.acevireally.firsttvinnytheviking"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.acevireally.firsttvinnytheviking"
        c2_domain = "openfeint.com"
        confidence = "medium"

    strings:
        $domain = "openfeint.com"

    condition:
        $domain
}

rule C2_Domain_opensource_org {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "opensource.org"
        confidence = "medium"

    strings:
        $domain = "opensource.org"

    condition:
        $domain
}

rule C2_Domain_openssl_org {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "openssl.org"
        confidence = "medium"

    strings:
        $domain = "openssl.org"

    condition:
        $domain
}

rule C2_Domain_osaris_net {
    meta:
        description = "C2 domain pattern for com.taolimogucun.dkdk"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.taolimogucun.dkdk"
        c2_domain = "osaris.net"
        confidence = "medium"

    strings:
        $domain = "osaris.net"

    condition:
        $domain
}

rule C2_Domain_paypal_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "paypal.com"
        confidence = "medium"

    strings:
        $domain = "paypal.com"

    condition:
        $domain
}

rule C2_Domain_play_google {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "play.google"
        confidence = "medium"

    strings:
        $domain = "play.google"

    condition:
        $domain
}

rule C2_Domain_pubnative_net {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "pubnative.net"
        confidence = "medium"

    strings:
        $domain = "pubnative.net"

    condition:
        $domain
}

rule C2_Domain_qpic_cn {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "qpic.cn"
        confidence = "medium"

    strings:
        $domain = "qpic.cn"

    condition:
        $domain
}

rule C2_Domain_qq_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "qq.com"
        confidence = "medium"

    strings:
        $domain = "qq.com"

    condition:
        $domain
}

rule C2_Domain_quipper_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "quipper.com"
        confidence = "medium"

    strings:
        $domain = "quipper.com"

    condition:
        $domain
}

rule C2_Domain_readnovel_com {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "readnovel.com"
        confidence = "medium"

    strings:
        $domain = "readnovel.com"

    condition:
        $domain
}

rule C2_Domain_revmob_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "revmob.com"
        confidence = "medium"

    strings:
        $domain = "revmob.com"

    condition:
        $domain
}

rule C2_Domain_rsigma_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "rsigma.com"
        confidence = "medium"

    strings:
        $domain = "rsigma.com"

    condition:
        $domain
}

rule C2_Domain_rubiconproject_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "rubiconproject.com"
        confidence = "medium"

    strings:
        $domain = "rubiconproject.com"

    condition:
        $domain
}

rule C2_Domain_sandraapps_info {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "sandraapps.info"
        confidence = "medium"

    strings:
        $domain = "sandraapps.info"

    condition:
        $domain
}

rule C2_Domain_scoreloop_com {
    meta:
        description = "C2 domain pattern for com.andan.mgtxpmgtx"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.andan.mgtxpmgtx"
        c2_domain = "scoreloop.com"
        confidence = "medium"

    strings:
        $domain = "scoreloop.com"

    condition:
        $domain
}

rule C2_Domain_sdk_android {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "sdk.android"
        confidence = "medium"

    strings:
        $domain = "sdk.android"

    condition:
        $domain
}

rule C2_Domain_sdrv_ms {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "sdrv.ms"
        confidence = "medium"

    strings:
        $domain = "sdrv.ms"

    condition:
        $domain
}

rule C2_Domain_searchmobileonline_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "7"
        family = "multi-family"
        c2_domain = "searchmobileonline.com"
        confidence = "medium"

    strings:
        $domain = "searchmobileonline.com"

    condition:
        $domain
}

rule C2_Domain_sgadtracker_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "sgadtracker.com"
        confidence = "medium"

    strings:
        $domain = "sgadtracker.com"

    condition:
        $domain
}

rule C2_Domain_smaato_net {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "smaato.net"
        confidence = "medium"

    strings:
        $domain = "smaato.net"

    condition:
        $domain
}

rule C2_Domain_smsreplier_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "smsreplier.net"
        confidence = "medium"

    strings:
        $domain = "smsreplier.net"

    condition:
        $domain
}

rule C2_Domain_soso_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "soso.com"
        confidence = "medium"

    strings:
        $domain = "soso.com"

    condition:
        $domain
}

rule C2_Domain_startappexchange_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "startappexchange.com"
        confidence = "medium"

    strings:
        $domain = "startappexchange.com"

    condition:
        $domain
}

rule C2_Domain_store2apps_info {
    meta:
        description = "C2 domain pattern for mema.akngahh"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "mema.akngahh"
        c2_domain = "store2apps.info"
        confidence = "medium"

    strings:
        $domain = "store2apps.info"

    condition:
        $domain
}

rule C2_Domain_suizong_com {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "suizong.com"
        confidence = "medium"

    strings:
        $domain = "suizong.com"

    condition:
        $domain
}

rule C2_Domain_t_online_de {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "t-online.de"
        confidence = "medium"

    strings:
        $domain = "t-online.de"

    condition:
        $domain
}

rule C2_Domain_t_cn {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "t.cn"
        confidence = "medium"

    strings:
        $domain = "t.cn"

    condition:
        $domain
}

rule C2_Domain_taotobo_com {
    meta:
        description = "C2 domain pattern for com.sdfasdwer.madgear"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.sdfasdwer.madgear"
        c2_domain = "taotobo.com"
        confidence = "medium"

    strings:
        $domain = "taotobo.com"

    condition:
        $domain
}

rule C2_Domain_tapjoy_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "tapjoy.com"
        confidence = "medium"

    strings:
        $domain = "tapjoy.com"

    condition:
        $domain
}

rule C2_Domain_tapjoy_comfor {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "tapjoy.comfor"
        confidence = "medium"

    strings:
        $domain = "tapjoy.comfor"

    condition:
        $domain
}

rule C2_Domain_tapjoyads_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "multi-family"
        c2_domain = "tapjoyads.com"
        confidence = "medium"

    strings:
        $domain = "tapjoyads.com"

    condition:
        $domain
}

rule C2_Domain_temp_im {
    meta:
        description = "C2 domain pattern for com.tencent.android.qqdownloader"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.tencent.android.qqdownloader"
        c2_domain = "temp.im"
        confidence = "medium"

    strings:
        $domain = "temp.im"

    condition:
        $domain
}

rule C2_Domain_tinfochina_com {
    meta:
        description = "C2 domain pattern for cn.net.cnea.transportcapacitycooldemo"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "cn.net.cnea.transportcapacitycooldemo"
        c2_domain = "tinfochina.com"
        confidence = "medium"

    strings:
        $domain = "tinfochina.com"

    condition:
        $domain
}

rule C2_Domain_truste_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "truste.com"
        confidence = "medium"

    strings:
        $domain = "truste.com"

    condition:
        $domain
}

rule C2_Domain_tumblr_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "tumblr.com"
        confidence = "medium"

    strings:
        $domain = "tumblr.com"

    condition:
        $domain
}

rule C2_Domain_turbofly3d_com {
    meta:
        description = "C2 domain pattern for com.taolimogucun.dkdk"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.taolimogucun.dkdk"
        c2_domain = "turbofly3d.com"
        confidence = "medium"

    strings:
        $domain = "turbofly3d.com"

    condition:
        $domain
}

rule C2_Domain_tvchannelsfree_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "tvchannelsfree.com"
        confidence = "medium"

    strings:
        $domain = "tvchannelsfree.com"

    condition:
        $domain
}

rule C2_Domain_twitter_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "twitter.com"
        confidence = "medium"

    strings:
        $domain = "twitter.com"

    condition:
        $domain
}

rule C2_Domain_twitter4j_org {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "twitter4j.org"
        confidence = "medium"

    strings:
        $domain = "twitter4j.org"

    condition:
        $domain
}

rule C2_Domain_umeng_co {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "multi-family"
        c2_domain = "umeng.co"
        confidence = "medium"

    strings:
        $domain = "umeng.co"

    condition:
        $domain
}

rule C2_Domain_umeng_com {
    meta:
        description = "C2 domain pattern for multi-family"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "4"
        family = "multi-family"
        c2_domain = "umeng.com"
        confidence = "medium"

    strings:
        $domain = "umeng.com"

    condition:
        $domain
}

rule C2_Domain_umengcloud_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "umengcloud.com"
        confidence = "medium"

    strings:
        $domain = "umengcloud.com"

    condition:
        $domain
}

rule C2_Domain_unity3d_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "unity3d.com"
        confidence = "medium"

    strings:
        $domain = "unity3d.com"

    condition:
        $domain
}

rule C2_Domain_updapp_com {
    meta:
        description = "C2 domain pattern for com.wSpeedtest1A"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.wSpeedtest1A"
        c2_domain = "updapp.com"
        confidence = "medium"

    strings:
        $domain = "updapp.com"

    condition:
        $domain
}

rule C2_Domain_vnet_mobi {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "vnet.mobi"
        confidence = "medium"

    strings:
        $domain = "vnet.mobi"

    condition:
        $domain
}

rule C2_Domain_vpon_com {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "vpon.com"
        confidence = "medium"

    strings:
        $domain = "vpon.com"

    condition:
        $domain
}

rule C2_Domain_vungle_com {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "vungle.com"
        confidence = "medium"

    strings:
        $domain = "vungle.com"

    condition:
        $domain
}

rule C2_Domain_w3_org {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "w3.org"
        confidence = "medium"

    strings:
        $domain = "w3.org"

    condition:
        $domain
}

rule C2_Domain_wap4mobi_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "3"
        family = "unknown"
        c2_domain = "wap4mobi.ru"
        confidence = "medium"

    strings:
        $domain = "wap4mobi.ru"

    condition:
        $domain
}

rule C2_Domain_wb_help_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "wb-help.com"
        confidence = "medium"

    strings:
        $domain = "wb-help.com"

    condition:
        $domain
}

rule C2_Domain_weibo_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "weibo.com"
        confidence = "medium"

    strings:
        $domain = "weibo.com"

    condition:
        $domain
}

rule C2_Domain_whalecloud_com {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "whalecloud.com"
        confidence = "medium"

    strings:
        $domain = "whalecloud.com"

    condition:
        $domain
}

rule C2_Domain_winimage_com {
    meta:
        description = "C2 domain pattern for com.maatto.quack.ncr"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.maatto.quack.ncr"
        c2_domain = "winimage.com"
        confidence = "medium"

    strings:
        $domain = "winimage.com"

    condition:
        $domain
}

rule C2_Domain_winsmedia_net {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "winsmedia.net"
        confidence = "medium"

    strings:
        $domain = "winsmedia.net"

    condition:
        $domain
}

rule C2_Domain_winten_tech_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "winten-tech.com"
        confidence = "medium"

    strings:
        $domain = "winten-tech.com"

    condition:
        $domain
}

rule C2_Domain_wiyun_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "2"
        family = "unknown"
        c2_domain = "wiyun.com"
        confidence = "medium"

    strings:
        $domain = "wiyun.com"

    condition:
        $domain
}

rule C2_Domain_worldtimeapi_org {
    meta:
        description = "C2 domain pattern for com.hash.locationrecord"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.hash.locationrecord"
        c2_domain = "worldtimeapi.org"
        confidence = "medium"

    strings:
        $domain = "worldtimeapi.org"

    condition:
        $domain
}

rule C2_Domain_wwwapp_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "wwwapp.ru"
        confidence = "medium"

    strings:
        $domain = "wwwapp.ru"

    condition:
        $domain
}

rule C2_Domain_xs_cn {
    meta:
        description = "C2 domain pattern for com.readnovel.book_88488"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.readnovel.book_88488"
        c2_domain = "xs.cn"
        confidence = "medium"

    strings:
        $domain = "xs.cn"

    condition:
        $domain
}

rule C2_Domain_yandex_net {
    meta:
        description = "C2 domain pattern for com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "com.artwall.IntroductionToTheTempleOfTheBlessedVirginMaryWallpapers"
        c2_domain = "yandex.net"
        confidence = "medium"

    strings:
        $domain = "yandex.net"

    condition:
        $domain
}

rule C2_Domain_yandex_ru {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "yandex.ru"
        confidence = "medium"

    strings:
        $domain = "yandex.ru"

    condition:
        $domain
}

rule C2_Domain_youmi_net {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "youmi.net"
        confidence = "medium"

    strings:
        $domain = "youmi.net"

    condition:
        $domain
}

rule C2_Domain_ysler_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "ysler.com"
        confidence = "medium"

    strings:
        $domain = "ysler.com"

    condition:
        $domain
}

rule C2_Domain_yunos_com {
    meta:
        description = "C2 domain pattern for unknown"
        author = "DroidForensix Pipeline"
        date = "2026-06-16"
        sample_count = "1"
        family = "unknown"
        c2_domain = "yunos.com"
        confidence = "medium"

    strings:
        $domain = "yunos.com"

    condition:
        $domain
}
