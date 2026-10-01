#pragma once

/*
 * Kernel-side feature contract for the integer inference core.
 *
 * A process-creation callback cannot parse a PE image or run a transformer: the
 * callback is hot, has no file I/O budget, and must not allocate. The features
 * below are therefore derived only from what the callback already holds - the
 * image path, the command line and the parent process id - and each one is a
 * bounded computation over a bounded string.
 *
 * This vocabulary is deliberately NOT the engine's canonical twelve PE
 * features (coverage, section_entropy, ...). Those describe a file's bytes;
 * these describe how a process is being launched. The two are complementary,
 * and a model trained on one must never be evaluated against the other, which
 * is why the exporter under tools/ has to name this contract explicitly.
 *
 * Every feature is an int8 in [0, 127] carrying evidence strength: 0 when the
 * signal is absent, 127 when it is fully present. Only non-negative features
 * are used because the model encodes the direction of each signal in its own
 * weight. That keeps the extractor free of sign handling and makes "signal
 * absent" and "signal zero" the same value, which is what a linear model wants.
 *
 * The extractor is pure and header-only, and depends on nothing but <stdint.h>,
 * so the same code that runs in the callback is compiled into the user-mode
 * harness in tests_kernel_matrix.cpp and exercised there.
 */

#include <stdint.h>

#include "everbloom_kernel_matrix.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Feature vector width. The exporter must emit a model whose feature_count is
 * exactly this value, with inputs in the index order below.
 */
typedef enum EVERBLOOM_KERNEL_FEATURE {
    EverbloomFeaturePathLength = 0,
    EverbloomFeatureBasenameLength,
    EverbloomFeatureUserWritableDir,
    EverbloomFeatureSystemDir,
    EverbloomFeatureExecutableExtension,
    EverbloomFeatureScriptExtension,
    EverbloomFeatureDoubleExtension,
    EverbloomFeatureLolbinName,
    EverbloomFeatureDigitRatio,
    EverbloomFeatureDistinctCharacterRatio,
    EverbloomFeatureCommandLineLength,
    EverbloomFeatureObfuscatedCommand
} EVERBLOOM_KERNEL_FEATURE;

#define EVERBLOOM_KERNEL_FEATURE_COUNT 12u

/* Sentinel for "no such index" from the scanning helpers below. */
#define EVERBLOOM_KERNEL_MODEL_NO_INDEX 0xFFFFFFFFu

/* Highest evidence value a feature may carry. */
#define EVERBLOOM_KERNEL_FEATURE_MAX 127

/*
 * Directory markers for locations a standard user can write to. A directory
 * component is always followed by a separator, so an ordinary substring test is
 * exact here: it cannot match a file whose *name* merely contains "temp",
 * because that occurrence is not delimited by separators on both sides.
 */
static const char* const kEverbloomUserWritableMarkers[] = {
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\$recycle.bin\\",
    "\\programdata\\",
    "\\users\\public\\",
};

/* Install locations. Present here so the model can weigh them negatively. */
static const char* const kEverbloomSystemMarkers[] = {
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
};

static const char* const kEverbloomExecutableExtensions[] = {
    ".exe", ".com", ".scr", ".pif", ".cpl", ".msi",
};

/*
 * Extensions that are executed by an interpreter or the shell rather than
 * loaded by the image loader. Deliberately excludes .dll/.sys, which are not
 * process images.
 */
static const char* const kEverbloomScriptExtensions[] = {
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".ps1", ".psm1", ".lnk", ".reg", ".jar", ".chm",
};

/* Extensions used as the first half of a disguised double extension. */
static const char* const kEverbloomDocumentExtensions[] = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".rtf", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z",
};

/*
 * Signed Microsoft binaries that are routinely abused to proxy execution.
 * Matching is on the whole stem, not a substring, so "myrundll32helper.exe"
 * does not fire.
 */
static const char* const kEverbloomLolbinNames[] = {
    "rundll32", "regsvr32", "mshta", "wscript", "cscript", "certutil",
    "bitsadmin", "msiexec", "installutil", "msbuild", "cmstp", "forfiles",
    "pcalua", "odbcconf", "xwizard", "wmic",
};

/*
 * Command-line markers for encoding or hidden-window invocation. Only
 * multi-character markers are listed: a two- or three-character needle such as
 * "-enc" matches too much ordinary text to be evidence, which is the same
 * word-boundary problem the kernel emergency gate had with "rop".
 */
static const char* const kEverbloomObfuscationMarkers[] = {
    "-encodedcommand",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "windowstyle hidden",
    "executionpolicy bypass",
    "iex(",
};

static inline uint16_t everbloom_kernel_model_lower(uint16_t value) {
    return (value >= (uint16_t)'A' && value <= (uint16_t)'Z')
        ? (uint16_t)(value + 0x20u)
        : value;
}

/*
 * Case-insensitive substring search over UTF-16 with ASCII-only folding.
 *
 * `needle` is a NUL-terminated ASCII literal, which is all the tables above
 * contain. Anchoring on the first unit before running the full compare is the
 * same fix applied to the Rust static-sandbox matcher and to
 * contains_ascii_case_insensitive in sys_driver.cpp.
 */
static inline int everbloom_kernel_model_contains(
    const uint16_t* haystack,
    uint32_t haystack_length,
    const char* needle) {
    if (haystack == 0 || needle == 0) {
        return 0;
    }
    uint32_t needle_length = 0;
    while (needle[needle_length] != '\0') {
        ++needle_length;
    }
    if (needle_length == 0 || needle_length > haystack_length) {
        return 0;
    }
    const uint32_t last_offset = haystack_length - needle_length;
    for (uint32_t offset = 0; offset <= last_offset; ++offset) {
        if (everbloom_kernel_model_lower(haystack[offset])
            != (uint16_t)needle[0]) {
            continue;
        }
        uint32_t index = 1;
        for (; index < needle_length; ++index) {
            if (everbloom_kernel_model_lower(haystack[offset + index])
                != (uint16_t)needle[index]) {
                break;
            }
        }
        if (index == needle_length) {
            return 1;
        }
    }
    return 0;
}

static inline int everbloom_kernel_model_contains_any(
    const uint16_t* haystack,
    uint32_t haystack_length,
    const char* const* needles,
    uint32_t needle_count) {
    for (uint32_t index = 0; index < needle_count; ++index) {
        if (everbloom_kernel_model_contains(
                haystack, haystack_length, needles[index])) {
            return 1;
        }
    }
    return 0;
}

static inline int everbloom_kernel_model_ends_with(
    const uint16_t* value,
    uint32_t value_length,
    const char* suffix) {
    if (value == 0 || suffix == 0) {
        return 0;
    }
    uint32_t suffix_length = 0;
    while (suffix[suffix_length] != '\0') {
        ++suffix_length;
    }
    if (suffix_length == 0 || suffix_length > value_length) {
        return 0;
    }
    const uint32_t start = value_length - suffix_length;
    for (uint32_t index = 0; index < suffix_length; ++index) {
        if (everbloom_kernel_model_lower(value[start + index])
            != (uint16_t)suffix[index]) {
            return 0;
        }
    }
    return 1;
}

static inline int everbloom_kernel_model_ends_with_any(
    const uint16_t* value,
    uint32_t value_length,
    const char* const* suffixes,
    uint32_t suffix_count) {
    for (uint32_t index = 0; index < suffix_count; ++index) {
        if (everbloom_kernel_model_ends_with(value, value_length, suffixes[index])) {
            return 1;
        }
    }
    return 0;
}

/* Exact match of the whole value against a lowercase ASCII literal. */
static inline int everbloom_kernel_model_equals(
    const uint16_t* value,
    uint32_t value_length,
    const char* expected) {
    if (value == 0 || expected == 0) {
        return 0;
    }
    uint32_t index = 0;
    for (; index < value_length; ++index) {
        if (expected[index] == '\0'
            || everbloom_kernel_model_lower(value[index])
                != (uint16_t)expected[index]) {
            return 0;
        }
    }
    return expected[index] == '\0';
}

/* Offset of the final path separator, or 0 when the value is a bare name. */
static inline uint32_t everbloom_kernel_model_basename_offset(
    const uint16_t* path,
    uint32_t path_length) {
    for (uint32_t index = path_length; index > 0; --index) {
        const uint16_t value = path[index - 1];
        if (value == (uint16_t)'\\' || value == (uint16_t)'/') {
            return index;
        }
    }
    return 0;
}

/* Index of the last '.' within the first `length` units. */
static inline uint32_t everbloom_kernel_model_last_dot(
    const uint16_t* value,
    uint32_t length) {
    if (value == 0) {
        return EVERBLOOM_KERNEL_MODEL_NO_INDEX;
    }
    for (uint32_t index = length; index > 0; --index) {
        if (value[index - 1] == (uint16_t)'.') {
            return index - 1;
        }
    }
    return EVERBLOOM_KERNEL_MODEL_NO_INDEX;
}

static inline int8_t everbloom_kernel_model_saturate(uint32_t value) {
    return (int8_t)(value > (uint32_t)EVERBLOOM_KERNEL_FEATURE_MAX
            ? (uint32_t)EVERBLOOM_KERNEL_FEATURE_MAX
            : value);
}

/*
 * Builds the feature vector from callback context.
 *
 * All lengths are in UTF-16 units, excluding any terminator, and either string
 * may be absent. Nothing else from PS_CREATE_NOTIFY_INFO is consumed: the
 * parent image name is not available there, and resolving it would mean taking
 * a process reference inside the callback, which is not worth the risk for a
 * signal the user-mode engine already correlates.
 *
 * On return `features` always holds exactly EVERBLOOM_KERNEL_FEATURE_COUNT
 * values, so a caller may evaluate the model unconditionally.
 */
static inline void everbloom_kernel_model_build_features(
    const uint16_t* image_name,
    uint32_t image_name_length,
    const uint16_t* command_line,
    uint32_t command_line_length,
    int8_t* features) {
    if (features == 0) {
        return;
    }
    for (uint32_t index = 0; index < EVERBLOOM_KERNEL_FEATURE_COUNT; ++index) {
        features[index] = 0;
    }
    if (image_name == 0 || image_name_length == 0) {
        return;
    }

    /* A long path is weak evidence on its own; it usually just means a deep
     * user profile, so the model gives it a correspondingly small weight. */
    features[EverbloomFeaturePathLength] =
        everbloom_kernel_model_saturate(image_name_length);

    const uint32_t basename_offset =
        everbloom_kernel_model_basename_offset(image_name, image_name_length);
    const uint16_t* basename = image_name + basename_offset;
    const uint32_t basename_length = image_name_length - basename_offset;

    features[EverbloomFeatureBasenameLength] =
        everbloom_kernel_model_saturate(basename_length);

    if (everbloom_kernel_model_contains_any(
            image_name,
            image_name_length,
            kEverbloomUserWritableMarkers,
            (uint32_t)(sizeof(kEverbloomUserWritableMarkers)
                / sizeof(kEverbloomUserWritableMarkers[0])))) {
        features[EverbloomFeatureUserWritableDir] = EVERBLOOM_KERNEL_FEATURE_MAX;
    }
    if (everbloom_kernel_model_contains_any(
            image_name,
            image_name_length,
            kEverbloomSystemMarkers,
            (uint32_t)(sizeof(kEverbloomSystemMarkers)
                / sizeof(kEverbloomSystemMarkers[0])))) {
        features[EverbloomFeatureSystemDir] = EVERBLOOM_KERNEL_FEATURE_MAX;
    }

    const int executable = everbloom_kernel_model_ends_with_any(
        basename,
        basename_length,
        kEverbloomExecutableExtensions,
        (uint32_t)(sizeof(kEverbloomExecutableExtensions)
            / sizeof(kEverbloomExecutableExtensions[0])));
    const int script = everbloom_kernel_model_ends_with_any(
        basename,
        basename_length,
        kEverbloomScriptExtensions,
        (uint32_t)(sizeof(kEverbloomScriptExtensions)
            / sizeof(kEverbloomScriptExtensions[0])));
    if (executable) {
        features[EverbloomFeatureExecutableExtension] = EVERBLOOM_KERNEL_FEATURE_MAX;
    }
    if (script) {
        features[EverbloomFeatureScriptExtension] = EVERBLOOM_KERNEL_FEATURE_MAX;
    }

    /*
     * Double extension. This fires only when a *document* extension is
     * immediately followed by an executable or script extension, so
     * "report.final.docx" (document last) and "app.core.exe" (stem is not a
     * document type) both stay quiet while "invoice.pdf.exe" fires.
     */
    if (executable || script) {
        const uint32_t final_dot =
            everbloom_kernel_model_last_dot(basename, basename_length);
        if (final_dot != EVERBLOOM_KERNEL_MODEL_NO_INDEX && final_dot > 0) {
            const uint32_t earlier_dot =
                everbloom_kernel_model_last_dot(basename, final_dot);
            if (earlier_dot != EVERBLOOM_KERNEL_MODEL_NO_INDEX) {
                /* The stem includes its leading dot so it can be compared
                 * directly against the ".pdf"-style table. */
                const uint32_t stem_offset = earlier_dot;
                const uint32_t stem_length = final_dot - earlier_dot;
                if (stem_length > 0
                    && everbloom_kernel_model_ends_with_any(
                        basename + stem_offset,
                        stem_length,
                        kEverbloomDocumentExtensions,
                        (uint32_t)(sizeof(kEverbloomDocumentExtensions)
                            / sizeof(kEverbloomDocumentExtensions[0])))) {
                    features[EverbloomFeatureDoubleExtension] =
                        EVERBLOOM_KERNEL_FEATURE_MAX;
                }
            }
        }
    }

    const uint32_t name_dot =
        everbloom_kernel_model_last_dot(basename, basename_length);
    const uint32_t name_length =
        (name_dot == EVERBLOOM_KERNEL_MODEL_NO_INDEX) ? basename_length : name_dot;
    for (uint32_t index = 0;
         index < (uint32_t)(sizeof(kEverbloomLolbinNames)
             / sizeof(kEverbloomLolbinNames[0]));
         ++index) {
        if (everbloom_kernel_model_equals(
                basename, name_length, kEverbloomLolbinNames[index])) {
            features[EverbloomFeatureLolbinName] = EVERBLOOM_KERNEL_FEATURE_MAX;
            break;
        }
    }

    /*
     * Digit and distinct-character ratios are computed over the basename with
     * the extension excluded, because a generated name such as "a8f3k2qz.exe"
     * is what these signals are looking for and the ".exe" would otherwise
     * dominate the denominator.
     */
    uint32_t digits = 0;
    uint32_t alphanumeric = 0;
    uint64_t seen = 0;
    uint32_t distinct = 0;
    for (uint32_t index = 0; index < name_length; ++index) {
        const uint16_t value = everbloom_kernel_model_lower(basename[index]);
        uint32_t bucket = EVERBLOOM_KERNEL_MODEL_NO_INDEX;
        if (value >= (uint16_t)'0' && value <= (uint16_t)'9') {
            bucket = (uint32_t)(value - (uint16_t)'0');
            ++digits;
        } else if (value >= (uint16_t)'a' && value <= (uint16_t)'z') {
            bucket = 10u + (uint32_t)(value - (uint16_t)'a');
        } else {
            continue;
        }
        ++alphanumeric;
        const uint64_t bit = 1ull << bucket;
        if ((seen & bit) == 0) {
            seen |= bit;
            ++distinct;
        }
    }
    if (alphanumeric > 0) {
        features[EverbloomFeatureDigitRatio] = everbloom_kernel_model_saturate(
            (digits * (uint32_t)EVERBLOOM_KERNEL_FEATURE_MAX) / alphanumeric);
        features[EverbloomFeatureDistinctCharacterRatio] =
            everbloom_kernel_model_saturate(
                (distinct * (uint32_t)EVERBLOOM_KERNEL_FEATURE_MAX)
                / alphanumeric);
    }

    features[EverbloomFeatureCommandLineLength] =
        everbloom_kernel_model_saturate(command_line_length);

    if (command_line != 0 && command_line_length > 0
        && everbloom_kernel_model_contains_any(
            command_line,
            command_line_length,
            kEverbloomObfuscationMarkers,
            (uint32_t)(sizeof(kEverbloomObfuscationMarkers)
                / sizeof(kEverbloomObfuscationMarkers[0])))) {
        features[EverbloomFeatureObfuscatedCommand] = EVERBLOOM_KERNEL_FEATURE_MAX;
    }
}

/*
 * The embedded model, or 0 when none is linked in. Declared here rather than in
 * a kernel-only header so the user-mode harness can evaluate the very tables
 * the driver ships.
 */
const EVERBLOOM_MATRIX_MODEL* EverbloomKernelModelGet();

/*
 * Scores a vector built by everbloom_kernel_model_build_features.
 *
 * Returns 1 and writes the score in the model's output domain (per-mille of the
 * real score, so 1500 means 1.5) when a model is available, and 0 when no model
 * is embedded or the vector is rejected. A 0 return means "no kernel opinion",
 * which callers must treat as a reason to defer to the user-mode engine rather
 * than as a clean verdict.
 *
 * `int` rather than BOOLEAN so this translation unit stays free of kernel
 * headers and can therefore be compiled and tested in user mode.
 */
int EverbloomKernelModelScore(const int8_t* features, int32_t* score);

/*
 * Builds the features for one launch and scores them in a single call.
 *
 * Returns 1 and writes the score when a model is embedded, 0 otherwise. It
 * takes the two strings straight from PS_CREATE_NOTIFY_INFO, so a callback body
 * stays a comparison against the model's threshold rather than a sequence of
 * steps. Either string may be absent, in which case its features stay zero.
 *
 * A 0 return means "no kernel opinion", which a caller must treat as a reason
 * to defer to the user-mode engine, never as a clean verdict.
 */
static inline int everbloom_kernel_model_score_launch(
    const uint16_t* image_name,
    uint32_t image_name_length,
    const uint16_t* command_line,
    uint32_t command_line_length,
    int32_t* score) {
    if (score == 0) {
        return 0;
    }
    int8_t features[EVERBLOOM_KERNEL_FEATURE_COUNT];
    everbloom_kernel_model_build_features(
        image_name,
        image_name_length,
        command_line,
        command_line_length,
        features);
    return EverbloomKernelModelScore(features, score);
}

#ifdef __cplusplus
}
#endif
