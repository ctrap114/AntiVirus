// User-mode regression harness for the exact normalization/suffix matcher
// compiled into kernel_policy.cpp. It deliberately does not load a driver.
// The same source is compiled with the production policy table excluded so
// these cases can run on every developer machine and in CI.

#include <cassert>
#include <cstddef>
#include <cwchar>

#include <ntifs.h>

extern "C" SIZE_T EverbloomPathTestCompareMemory(
    const void* left,
    const void* right,
    SIZE_T length);

#define EVERBLOOM_KERNEL_POLICY_PATH_TEST 1
#define RtlCompareMemory EverbloomPathTestCompareMemory
#include "src/kernel_policy.cpp"
#undef RtlCompareMemory

extern "C" SIZE_T EverbloomPathTestCompareMemory(
    const void* left,
    const void* right,
    SIZE_T length) {
    const auto* a = static_cast<const unsigned char*>(left);
    const auto* b = static_cast<const unsigned char*>(right);
    SIZE_T equal = 0;
    while (equal < length && a[equal] == b[equal]) {
        ++equal;
    }
    return equal;
}

UNICODE_STRING unicode_literal(const wchar_t* value) {
    UNICODE_STRING result{};
    result.Buffer = const_cast<PWSTR>(value);
    result.Length = static_cast<USHORT>(wcslen(value) * sizeof(wchar_t));
    result.MaximumLength = result.Length;
    return result;
}

void assert_matches(const wchar_t* rule, const wchar_t* actual) {
    const auto expected = unicode_literal(rule);
    const auto candidate = unicode_literal(actual);
    assert(dos_path_suffix_matches(&expected, &candidate) == TRUE);
}

void assert_does_not_match(const wchar_t* rule, const wchar_t* actual) {
    const auto expected = unicode_literal(rule);
    const auto candidate = unicode_literal(actual);
    assert(dos_path_suffix_matches(&expected, &candidate) == FALSE);
}

int main() {
    // DOS drive and native device namespaces must resolve to the same suffix.
    assert_matches(
        L"C:\\Windows\\System32\\cmd.exe",
        L"\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe");
    assert_matches(
        L"C:\\Windows\\System32\\cmd.exe",
        L"\\DosDevices\\C:\\Windows\\System32\\cmd.exe");
    assert_matches(
        L"C:\\Windows\\System32\\cmd.exe",
        L"\\??\\C:\\Windows\\System32\\cmd.exe");
    assert_matches(
        L"C:\\Windows\\System32\\cmd.exe",
        L"\\\\?\\C:\\Windows\\System32\\cmd.exe");

    // 8.3 aliases, case differences, repeated separators and dot segments.
    assert_matches(
        L"C:\\Program Files\\EverbloomSecurity\\mal.exe",
        L"c:\\PROGRA~1\\EverbloomSecurity\\mal.exe");
    assert_matches(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\\\Windows\\System32\\tools\\..\\cmd.exe");

    // Filter Manager supplies a normalized name for reparse-point/junction
    // opens; this case verifies the suffix matcher does not reintroduce a
    // textual alias after that normalization.
    assert_matches(
        L"C:\\Windows\\System32\\drivers\\blocked.sys",
        L"\\Device\\HarddiskVolume2\\Windows\\System32\\drivers\\blocked.sys");
    assert_does_not_match(
        L"C:\\Windows\\System32\\cmd.exe",
        L"\\Device\\HarddiskVolume1\\Windows\\System32\\notepad.exe");
    return 0;
}
