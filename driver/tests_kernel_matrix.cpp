/*
 * User-mode verification harness for the integer inference core.
 *
 * The core is pure integer arithmetic with no kernel dependency, which is
 * precisely why it can be validated here: the same header that compiles into
 * everbloom_driver.sys is compiled into this executable. Only the section
 * placement of the weight tables is kernel-specific.
 *
 * Two independent checks are run, because they catch different failures:
 *
 *  1. Exact equality against a separately written integer reference. This
 *     validates the parts that are easy to get wrong: weight indexing, the
 *     ping-pong buffer walk, bias placement, and clamping order.
 *
 *  2. Tolerance agreement with a floating-point model built from the same
 *     weights. This validates the quantization scheme itself, in particular
 *     that the fixed-point multiplier encoding rescales by the intended ratio.
 *
 * Plus exact assertions for the properties that must be exact: saturation,
 * error codes, the identity rescale, and the shape guards.
 */

#include "everbloom_kernel_matrix.h"
#include "everbloom_kernel_model.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(condition, ...)                           \
    do {                                                \
        ++g_checks;                                     \
        if (!(condition)) {                             \
            ++g_failures;                               \
            printf("FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                        \
            printf("\n");                               \
        }                                               \
    } while (0)

/* --- reference implementations ------------------------------------------- */

/*
 * Independent integer reference. Written from the specification rather than by
 * reusing the core, so a bug in the core's indexing or walk does not reproduce
 * itself here. Uses long long throughout, which is a different code path from
 * the core's int32 accumulators plus int64 rescale.
 */
static int32_t reference_evaluate(
    const EVERBLOOM_MATRIX_MODEL* model,
    const int8_t* features) {
    int8_t current[EVERBLOOM_MATRIX_MAX_UNITS];
    memcpy(current, features, model->feature_count);
    uint32_t width = model->feature_count;

    for (uint32_t l = 0; l < model->layer_count; ++l) {
        const EVERBLOOM_MATRIX_LAYER* layer = &model->layers[l];
        int8_t next[EVERBLOOM_MATRIX_MAX_UNITS];

        for (uint32_t o = 0; o < layer->outputs; ++o) {
            long long acc = 0;
            for (uint32_t i = 0; i < width; ++i) {
                acc += (long long)layer->weights[(size_t)o * width + i] * (long long)current[i];
            }

            long long value;
            if (layer->requant_shift == 0) {
                value = acc;
            } else {
                /*
                 * Independent formulation of the same specification. Integer
                 * division truncates toward zero, so biasing the numerator by
                 * half the divisor with its own sign yields round-half-away-
                 * from-zero. The core reaches the same result through a shift
                 * plus a remainder/threshold comparison, which is a different
                 * code path, so agreement between the two is evidence and not
                 * a tautology.
                 */
                const long long numerator = acc * (long long)layer->requant_multiplier;
                const long long divisor = 1LL << layer->requant_shift;
                const long long half = divisor / 2;
                value = (numerator >= 0 ? numerator + half : numerator - half) / divisor;
            }
            if (layer->bias != 0) {
                value += layer->bias[o];
            }
            if (value < layer->activation_min) {
                value = layer->activation_min;
            }
            if (value > layer->activation_max) {
                value = layer->activation_max;
            }

            if (l + 1 == model->layer_count) {
                return (int32_t)value;
            }
            if (value > 127) {
                value = 127;
            }
            if (value < -128) {
                value = -128;
            }
            next[o] = (int8_t)value;
        }

        memcpy(current, next, layer->outputs);
        width = layer->outputs;
    }
    return 0;
}

/*
 * Encode m as multiplier * 2^-shift with multiplier in [2^30, 2^31), which is
 * the Q31 normalisation TFLite and gemmlowp use. Normalising keeps the full
 * 31-bit mantissa no matter how small m is. For a realistic per-tensor scale
 * near 1e-2 the resulting shift is about 37, which is exactly why the core's
 * shift bound is 62 and not 31: a bound of 31 would leave the multiplier with
 * only about 24 significant bits and silently coarsen every layer.
 */
static void encode_multiplier(double m, int32_t* multiplier, uint32_t* shift) {
    if (!(m > 0.0)) {
        *multiplier = 0;
        *shift = 1;
        return;
    }
    uint32_t s = 0;
    double scaled = m;
    while (scaled < 1073741824.0 && s < EVERBLOOM_MATRIX_MAX_SHIFT) {
        scaled *= 2.0;
        ++s;
    }
    *multiplier = (int32_t)llround(scaled);
    *shift = s;
}

static int8_t quantize_symmetric(double value, double scale) {
    long q = lround(value / scale);
    if (q > 127) {
        q = 127;
    }
    if (q < -128) {
        q = -128;
    }
    return (int8_t)q;
}

/* --- fixtures ------------------------------------------------------------ */

/* A 4 -> 3 (ReLU) -> 1 network with hand-chosen weights. */
static const double k_w0[3][4] = {
    { 0.9, -1.4, 0.3, 0.6 },
    { -0.5, 1.1, -0.8, 0.2 },
    { 0.4, 0.7, 1.3, -0.9 },
};
static const double k_b0[3] = { 0.1, -0.2, 0.05 };
static const double k_w1[1][3] = { { 1.2, -0.7, 0.5 } };
static const double k_b1[1] = { -0.15 };

static const double k_scale_in = 1.0 / 16.0;
static const double k_scale_hidden = 1.0 / 16.0;
static const double k_scale_out = 1.0 / 16.0;

static int8_t g_w0_q[3][4];
static int8_t g_w1_q[1][3];
static int32_t g_b0_q[3];
static int32_t g_b1_q[1];
static EVERBLOOM_MATRIX_LAYER g_layers[2];
static EVERBLOOM_MATRIX_MODEL g_model;

static void build_model() {
    double max_w0 = 0.0;
    for (int o = 0; o < 3; ++o) {
        for (int i = 0; i < 4; ++i) {
            max_w0 = fmax(max_w0, fabs(k_w0[o][i]));
        }
    }
    const double scale_w0 = max_w0 / 127.0;

    double max_w1 = 0.0;
    for (int i = 0; i < 3; ++i) {
        max_w1 = fmax(max_w1, fabs(k_w1[0][i]));
    }
    const double scale_w1 = max_w1 / 127.0;

    for (int o = 0; o < 3; ++o) {
        for (int i = 0; i < 4; ++i) {
            g_w0_q[o][i] = quantize_symmetric(k_w0[o][i], scale_w0);
        }
        g_b0_q[o] = (int32_t)lround(k_b0[o] / k_scale_hidden);
    }
    for (int i = 0; i < 3; ++i) {
        g_w1_q[0][i] = quantize_symmetric(k_w1[0][i], scale_w1);
    }
    g_b1_q[0] = (int32_t)lround(k_b1[0] / k_scale_out);

    int32_t m0 = 0;
    int32_t m1 = 0;
    uint32_t s0 = 0;
    uint32_t s1 = 0;
    encode_multiplier(scale_w0 * k_scale_in / k_scale_hidden, &m0, &s0);
    encode_multiplier(scale_w1 * k_scale_hidden / k_scale_out, &m1, &s1);

    memset(g_layers, 0, sizeof(g_layers));
    g_layers[0].weights = &g_w0_q[0][0];
    g_layers[0].bias = g_b0_q;
    g_layers[0].inputs = 4;
    g_layers[0].outputs = 3;
    g_layers[0].requant_multiplier = m0;
    g_layers[0].requant_shift = s0;
    g_layers[0].activation_min = 0;
    g_layers[0].activation_max = 127; /* ReLU */

    g_layers[1].weights = &g_w1_q[0][0];
    g_layers[1].bias = g_b1_q;
    g_layers[1].inputs = 3;
    g_layers[1].outputs = 1;
    g_layers[1].requant_multiplier = m1;
    g_layers[1].requant_shift = s1;
    g_layers[1].activation_min = -1000000;
    g_layers[1].activation_max = 1000000;

    memset(&g_model, 0, sizeof(g_model));
    g_model.layers = g_layers;
    g_model.layer_count = 2;
    g_model.feature_count = 4;
    g_model.output_threshold = 0;
}

static const int8_t k_samples[][4] = {
    { 16, -32, 48, 8 },
    { -64, 64, 0, -16 },
    { 0, 0, 0, 0 },
    { 127, -128, 127, -128 },
    { 4, 4, 4, 4 },
    { -1, 1, -1, 1 },
};

/* --- tests --------------------------------------------------------------- */

static void test_exact_agreement_with_integer_reference() {
    EVERBLOOM_MATRIX_SCRATCH scratch;
    for (size_t s = 0; s < sizeof(k_samples) / sizeof(k_samples[0]); ++s) {
        const int32_t actual = everbloom_matrix_evaluate(&g_model, k_samples[s], &scratch);
        const int32_t expected = reference_evaluate(&g_model, k_samples[s]);
        CHECK(actual == expected,
              "sample %zu: core=%d reference=%d",
              s,
              actual,
              expected);
    }
}

static void test_agreement_with_float_model() {
    EVERBLOOM_MATRIX_SCRATCH scratch;
    int compared = 0;
    for (size_t s = 0; s < sizeof(k_samples) / sizeof(k_samples[0]); ++s) {
        const int8_t* x = k_samples[s];

        double hidden[3];
        int saturates = 0;
        for (int o = 0; o < 3; ++o) {
            double acc = k_b0[o];
            for (int i = 0; i < 4; ++i) {
                acc += k_w0[o][i] * ((double)x[i] * k_scale_in);
            }
            hidden[o] = acc > 0.0 ? acc : 0.0;
            // The int8 representation of a hidden unit is hidden/scale_hidden,
            // so anything at or above 127 saturates on the way out of layer 0.
            if (hidden[o] >= 127.0 * k_scale_hidden) {
                saturates = 1;
            }
        }

        /*
         * A saturating sample is skipped rather than asserted. The quantized
         * model clamps the hidden unit where the float model keeps growing, so
         * the two are *expected* to disagree and the gap measures the clamp,
         * not the arithmetic. That divergence is still checked, exactly, by
         * test_exact_agreement_with_integer_reference and by
         * test_relu_saturates_without_wrapping.
         */
        if (saturates) {
            continue;
        }

        double y = k_b1[0];
        for (int i = 0; i < 3; ++i) {
            y += k_w1[0][i] * hidden[i];
        }
        const double expected = y / k_scale_out;
        const int32_t actual = everbloom_matrix_evaluate(&g_model, x, &scratch);
        ++compared;

        /*
         * Error budget. Each hidden unit carries up to half a step of its
         * output scale (1/32 real), and three of them pass through weights of
         * magnitude up to 1.4, so the output can move by roughly
         * 3 * 1.4 * (1/32) / k_scale_out ~= 17 integer steps. A 20% relative
         * tolerance with a floor of 20 steps covers that plus weight
         * quantization without being so loose that a wrong multiplier would
         * pass.
         */
        const double tolerance = fmax(20.0, 0.20 * fabs(expected));
        CHECK(fabs((double)actual - expected) <= tolerance,
              "sample %zu: core=%d float=%.2f delta=%.2f tol=%.2f",
              s,
              actual,
              expected,
              (double)actual - expected,
              tolerance);
    }

    // Without this the loop could silently stop testing anything if the sample
    // set were ever changed to one that saturates everywhere.
    CHECK(compared >= 4, "the float cross-check must compare samples, got %d", compared);
}

static void test_error_codes() {
    EVERBLOOM_MATRIX_SCRATCH scratch;
    const int8_t features[4] = { 1, 2, 3, 4 };

    CHECK(everbloom_matrix_evaluate(0, features, &scratch) == EVERBLOOM_MATRIX_ERR_NULL,
          "null model must be rejected");
    CHECK(everbloom_matrix_evaluate(&g_model, 0, &scratch) == EVERBLOOM_MATRIX_ERR_NULL,
          "null features must be rejected");
    CHECK(everbloom_matrix_evaluate(&g_model, features, 0) == EVERBLOOM_MATRIX_ERR_NULL,
          "null scratch must be rejected");

    EVERBLOOM_MATRIX_MODEL model = g_model;
    model.layers = 0;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_NULL,
          "null layer table must be rejected");

    model = g_model;
    model.layer_count = 0;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_LAYERS,
          "empty model must be rejected");

    model = g_model;
    model.layer_count = EVERBLOOM_MATRIX_MAX_LAYERS + 1;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_LAYERS,
          "too many layers must be rejected");

    model = g_model;
    model.feature_count = 0;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHAPE,
          "zero feature count must be rejected");

    model = g_model;
    model.feature_count = EVERBLOOM_MATRIX_MAX_UNITS + 1;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHAPE,
          "oversized feature count must be rejected");

    /* A layer whose declared width disagrees with its producer is the shape
     * error that would otherwise read past the weight table. */
    EVERBLOOM_MATRIX_LAYER layers[2];
    memcpy(layers, g_layers, sizeof(layers));
    layers[1].inputs = 4;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHAPE,
          "mismatched layer width must be rejected");

    memcpy(layers, g_layers, sizeof(layers));
    layers[0].weights = 0;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_NULL,
          "null weight table must be rejected");

    /*
     * The shift bound is 62, not 31: a Q31 multiplier for a realistic
     * per-tensor scale needs a shift in the high 30s. Both sides of the
     * boundary are checked so an off-by-one cannot hide.
     */
    memcpy(layers, g_layers, sizeof(layers));
    layers[0].requant_shift = EVERBLOOM_MATRIX_MAX_SHIFT + 1;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHIFT,
          "shift above EVERBLOOM_MATRIX_MAX_SHIFT must be rejected");

    memcpy(layers, g_layers, sizeof(layers));
    layers[0].requant_shift = EVERBLOOM_MATRIX_MAX_SHIFT;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) != EVERBLOOM_MATRIX_ERR_SHIFT,
          "the maximum shift must be accepted, not rejected");

    memcpy(layers, g_layers, sizeof(layers));
    layers[0].activation_min = 10;
    layers[0].activation_max = 5;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHAPE,
          "inverted clamp bounds must be rejected");

    /* The last layer must be a scalar: narrowing a multi-output final layer to
     * a single score would silently drop the other outputs. */
    memcpy(layers, g_layers, sizeof(layers));
    layers[1].outputs = 2;
    model = g_model;
    model.layers = layers;
    CHECK(everbloom_matrix_evaluate(&model, features, &scratch) == EVERBLOOM_MATRIX_ERR_SHAPE,
          "multi-output final layer must be rejected");
}

static void test_requantize_properties() {
    /* shift 0 is the documented identity. */
    CHECK(everbloom_matrix_requantize(12345, 999, 0) == 12345,
          "shift 0 must be the identity");
    CHECK(everbloom_matrix_requantize(-12345, 999, 0) == -12345,
          "shift 0 must be the identity for negatives");

    /* A multiplier of 2^30 with shift 30 is a scale of 1.0. */
    CHECK(everbloom_matrix_requantize(1000, 1073741824, 30) == 1000,
          "2^30 >> 30 must be unity");
    CHECK(everbloom_matrix_requantize(-1000, 1073741824, 30) == -1000,
          "2^30 >> 30 must be unity for negatives");

    /* Halving, with half-away-from-zero rounding. */
    CHECK(everbloom_matrix_requantize(5, 1073741824, 31) == 3, "5/2 rounds to 3");
    CHECK(everbloom_matrix_requantize(-5, 1073741824, 31) == -3, "-5/2 rounds to -3");
    CHECK(everbloom_matrix_requantize(4, 1073741824, 31) == 2, "4/2 is exact");
    CHECK(everbloom_matrix_requantize(0, 1073741824, 31) == 0, "0 stays 0");

    /* A zero multiplier collapses to zero. */
    CHECK(everbloom_matrix_requantize(999999, 0, 16) == 0, "zero multiplier yields zero");

    /*
     * The case that motivated widening the shift bound: a realistic per-tensor
     * scale near 1e-2. After Q31 normalisation it needs a shift well above 31,
     * which the original bound could not express without throwing away most of
     * the mantissa.
     */
    int32_t m = 0;
    uint32_t s = 0;
    encode_multiplier(0.01, &m, &s);
    CHECK(s > 31 && s <= EVERBLOOM_MATRIX_MAX_SHIFT,
          "a 1e-2 scale must normalise to a shift above 31, got %u",
          s);
    CHECK((long long)m >= 1073741824LL && (long long)m < 2147483648LL,
          "the multiplier must land in [2^30, 2^31), got %d",
          m);
    CHECK(everbloom_matrix_requantize(10000, m, s) == 100,
          "10000 * 1e-2 must rescale to 100, got %d",
          everbloom_matrix_requantize(10000, m, s));
    CHECK(everbloom_matrix_requantize(-10000, m, s) == -100,
          "-10000 * 1e-2 must rescale to -100, got %d",
          everbloom_matrix_requantize(-10000, m, s));

    /*
     * The maximum shift must be usable and must not overflow the int64
     * intermediate, including the half-step rounding offset.
     */
    CHECK(everbloom_matrix_requantize(1, 1073741824, EVERBLOOM_MATRIX_MAX_SHIFT) == 0,
          "the maximum shift must be representable");
    CHECK(everbloom_matrix_requantize(2000000, 1073741824, EVERBLOOM_MATRIX_MAX_SHIFT) == 0,
          "a large accumulator at the maximum shift must not overflow");
}

static void test_narrow_and_clamp() {
    CHECK(everbloom_matrix_narrow_int8(200) == 127, "positive saturation");
    CHECK(everbloom_matrix_narrow_int8(-200) == -128, "negative saturation");
    CHECK(everbloom_matrix_narrow_int8(127) == 127, "127 is representable");
    CHECK(everbloom_matrix_narrow_int8(-128) == -128, "-128 is representable");
    CHECK(everbloom_matrix_narrow_int8(0) == 0, "zero");

    CHECK(everbloom_matrix_clamp(5, 0, 3) == 3, "clamp high");
    CHECK(everbloom_matrix_clamp(-5, 0, 3) == 0, "clamp low");
    CHECK(everbloom_matrix_clamp(2, 0, 3) == 2, "clamp pass-through");
}

/* The ReLU hidden layer must saturate at the int8 output bound, not wrap. */
static void test_relu_saturates_without_wrapping() {
    /* Large positive features drive the hidden accumulators far above 127. */
    const int8_t features[4] = { 127, 127, 127, 127 };
    EVERBLOOM_MATRIX_SCRATCH scratch;
    const int32_t result = everbloom_matrix_evaluate(&g_model, features, &scratch);
    CHECK(result != EVERBLOOM_MATRIX_ERR_SHAPE && result != EVERBLOOM_MATRIX_ERR_NULL,
          "saturating input must still evaluate, got %d",
          result);
    CHECK(result == reference_evaluate(&g_model, features),
          "saturating input must agree with the reference, got %d",
          result);
}

/*
 * Regression guard for the shift bound. The fixture's per-tensor scales are
 * representative of a real model, and a Q31 multiplier for them needs a shift
 * above 31. If that ever stops holding, the end-to-end tests above have quietly
 * stopped covering the case the widened bound exists for.
 */
static void test_fixture_uses_a_shift_above_31() {
    for (uint32_t l = 0; l < sizeof(g_layers) / sizeof(g_layers[0]); ++l) {
        CHECK(g_layers[l].requant_shift > 31
                  && g_layers[l].requant_shift <= EVERBLOOM_MATRIX_MAX_SHIFT,
              "layer %u shift must exceed 31 and stay in range, got %u",
              l,
              g_layers[l].requant_shift);
    }
}

/* --- kernel model -------------------------------------------------------- */

/* Capacity of the UTF-16 test strings, including the terminator. */
constexpr uint32_t kMaxWideTestChars = 512;

/*
 * The extractor takes UTF-16 because that is what the callback holds. These
 * helpers widen ASCII literals so the tests read as the paths they describe.
 */
static void widen_ascii(const char* ascii, uint16_t* out, uint32_t* length) {
    uint32_t index = 0;
    while (index + 1 < kMaxWideTestChars && ascii[index] != '\0') {
        out[index] = (uint16_t)(unsigned char)ascii[index];
        ++index;
    }
    out[index] = 0;
    *length = index;
}

static void features_for(const char* image_name, const char* command_line, int8_t* features) {
    uint16_t wide_image[kMaxWideTestChars];
    uint16_t wide_command[kMaxWideTestChars];
    uint32_t image_length = 0;
    uint32_t command_length = 0;
    widen_ascii(image_name, wide_image, &image_length);
    if (command_line != 0) {
        widen_ascii(command_line, wide_command, &command_length);
    }
    everbloom_kernel_model_build_features(
        wide_image,
        image_length,
        command_line != 0 ? wide_command : 0,
        command_length,
        features);
}

static void test_kernel_features_flag_launch_risk() {
    int8_t features[EVERBLOOM_KERNEL_FEATURE_COUNT];

    /* An installed binary: system directory, ordinary .exe, no command line. */
    features_for("C:\\Windows\\System32\\svchost.exe", 0, features);
    CHECK(features[EverbloomFeatureSystemDir] == 127, "System32 must set the system-dir feature");
    CHECK(features[EverbloomFeatureUserWritableDir] == 0, "System32 must not look user-writable");
    CHECK(features[EverbloomFeatureExecutableExtension] == 127, ".exe must set the executable feature");
    CHECK(features[EverbloomFeatureScriptExtension] == 0, ".exe must not set the script feature");
    CHECK(features[EverbloomFeatureDoubleExtension] == 0, "svchost.exe must not look double-extended");
    CHECK(features[EverbloomFeatureLolbinName] == 0, "svchost must not match a LOLBin stem");
    CHECK(features[EverbloomFeatureObfuscatedCommand] == 0, "an absent command line must not look obfuscated");

    /* A disguised payload in a user-writable directory. */
    features_for("C:\\Users\\a\\AppData\\Local\\Temp\\invoice.pdf.exe", 0, features);
    CHECK(features[EverbloomFeatureUserWritableDir] == 127, "AppData\\Local\\Temp must look user-writable");
    CHECK(features[EverbloomFeatureDoubleExtension] == 127, "invoice.pdf.exe must look double-extended");
    CHECK(features[EverbloomFeatureSystemDir] == 0, "a Temp path must not look like a system directory");

    /* A LOLBin launched with an encoded command line. */
    features_for(
        "C:\\Windows\\System32\\rundll32.exe",
        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";-EncodedCommand",
        features);
    CHECK(features[EverbloomFeatureLolbinName] == 127, "rundll32 must match a LOLBin stem");
    CHECK(features[EverbloomFeatureObfuscatedCommand] == 127, "-EncodedCommand must set the obfuscation feature");
    CHECK(features[EverbloomFeatureSystemDir] == 127, "System32 must still set the system-dir feature");

    /*
     * The LOLBin test is a whole-stem comparison, not a substring one, so a
     * name that merely contains a LOLBin name must not match. This is the same
     * class of false positive as "rop" matching "Europe" in the emergency gate.
     */
    features_for("C:\\Windows\\System32\\myrundll32helper.exe", 0, features);
    CHECK(features[EverbloomFeatureLolbinName] == 0, "a name containing a LOLBin stem must not match");

    /* "temp" inside a file or directory name is not a writable directory. */
    features_for("C:\\Program Files\\contemporary\\app.exe", 0, features);
    CHECK(features[EverbloomFeatureUserWritableDir] == 0, "an undelimited 'temp' substring must not match");

    /* A document extension in the final position is not a disguise. */
    features_for("C:\\Users\\a\\Documents\\report.final.docx", 0, features);
    CHECK(features[EverbloomFeatureDoubleExtension] == 0, "a trailing document extension is not a disguise");

    /* A script extension is not an executable one, and vice versa. */
    features_for("C:\\Users\\a\\Downloads\\run.vbs", 0, features);
    CHECK(features[EverbloomFeatureScriptExtension] == 127, ".vbs must set the script feature");
    CHECK(features[EverbloomFeatureExecutableExtension] == 0, ".vbs must not set the executable feature");

    /*
     * Generated-looking names: digits and distinct characters are measured over
     * the stem only, because ".exe" would otherwise dominate the denominator
     * and flatten every name to the same ratio.
     */
    features_for("C:\\Windows\\Temp\\a8f3k2qz.exe", 0, features);
    CHECK(features[EverbloomFeatureDigitRatio] > 0, "a digit-bearing stem must raise the digit ratio");
    features_for("C:\\Windows\\Temp\\svchost.exe", 0, features);
    CHECK(features[EverbloomFeatureDigitRatio] == 0, "a digit-free stem must have a zero digit ratio");

    /* Every feature must stay inside the declared evidence range. */
    features_for("C:\\Users\\a\\AppData\\Local\\Temp\\invoice.pdf.exe", "x", features);
    for (uint32_t index = 0; index < EVERBLOOM_KERNEL_FEATURE_COUNT; ++index) {
        CHECK(features[index] >= 0 && features[index] <= EVERBLOOM_KERNEL_FEATURE_MAX,
              "feature %u out of range: %d",
              index,
              features[index]);
    }
}

static void test_kernel_model_scores_launch_risk() {
    const EVERBLOOM_MATRIX_MODEL* model = EverbloomKernelModelGet();
    CHECK(model != 0, "the driver must embed a model");
    if (model == 0) {
        return;
    }
    CHECK(model->feature_count == EVERBLOOM_KERNEL_FEATURE_COUNT,
          "the embedded model must take the feature contract width, got %u",
          model->feature_count);
    CHECK(model->layer_count >= 1, "the embedded model must have at least one layer");
    if (model->layer_count == 0) {
        return;
    }

    /*
     * The rescale shift must stay above 31. This is the property the embedded
     * model keeps honest end to end: a Q31 multiplier for a per-mille output
     * domain needs a shift in the mid thirties, so if it ever drops to 31 or
     * below, the core's widened bound has lost its coverage in the real driver
     * and not just in the synthetic fixture.
     */
    for (uint32_t index = 0; index < model->layer_count; ++index) {
        CHECK(model->layers[index].requant_shift > 31,
              "layer %u shift must exceed 31, got %u",
              index,
              model->layers[index].requant_shift);
    }

    /*
     * The output domain must exclude negatives.
     *
     * The core reports failures as negative EVERBLOOM_MATRIX_ERR_* codes, so the
     * only way a caller can tell a failure from a score is for the score domain
     * to exclude negatives. A risk score is non-negative by definition, and this
     * assertion is what keeps the two contracts from drifting apart: with a
     * negative lower clamp an ordinary installed binary scores below zero and
     * EverbloomKernelModelScore would report it as a failure instead of a score.
     */
    const int32_t output_min = model->layers[model->layer_count - 1].activation_min;
    CHECK(output_min >= 0,
          "the output domain must be non-negative, got %d",
          output_min);

    int8_t benign[EVERBLOOM_KERNEL_FEATURE_COUNT];
    int8_t suspicious[EVERBLOOM_KERNEL_FEATURE_COUNT];
    features_for("C:\\Windows\\System32\\svchost.exe", 0, benign);
    features_for(
        "C:\\Users\\a\\AppData\\Local\\Temp\\invoice.pdf.exe",
        "powershell -windowstyle hidden -encodedcommand AAAA",
        suspicious);

    int32_t benign_score = 0;
    int32_t suspicious_score = 0;
    CHECK(EverbloomKernelModelScore(benign, &benign_score) == 1, "the benign vector must score");
    CHECK(EverbloomKernelModelScore(suspicious, &suspicious_score) == 1, "the suspicious vector must score");

    /*
     * The installed binary scores negative before the clamp, because the
     * system-directory weight outweighs everything its name contributes. The
     * clamp is what turns that into a zero rather than a value the wrapper would
     * have to guess about.
     */
    CHECK(benign_score == output_min,
          "an installed binary must clamp to the output floor, got %d vs %d",
          benign_score,
          output_min);
    CHECK(suspicious_score > benign_score,
          "a disguised Temp payload must outscore an installed binary, got %d vs %d",
          suspicious_score,
          benign_score);
    CHECK(suspicious_score >= model->output_threshold,
          "a disguised Temp payload must cross the threshold, got %d vs %d",
          suspicious_score,
          model->output_threshold);

    /* Argument validation must fail closed rather than score garbage. */
    CHECK(EverbloomKernelModelScore(0, &benign_score) == 0, "a null vector must be rejected");
    CHECK(EverbloomKernelModelScore(benign, 0) == 0, "a null output must be rejected");

    /* A zero vector must return the bias rather than an uninitialized read.
     * The embedded bias is zero, so the score must be exactly zero. */
    int8_t zeros[EVERBLOOM_KERNEL_FEATURE_COUNT] = { 0 };
    int32_t zero_score = -1;
    CHECK(EverbloomKernelModelScore(zeros, &zero_score) == 1, "the zero vector must score");
    CHECK(zero_score == 0, "a zero vector must score zero, got %d", zero_score);
}

/*
 * The callback calls one helper that builds the features and scores them, so
 * its body stays a threshold comparison. This covers that entry point,
 * including the absent-input case a callback can really hit: a process created
 * without a command line.
 */
static int32_t score_launch_for(const char* image_name, const char* command_line) {
    uint16_t wide_image[kMaxWideTestChars];
    uint16_t wide_command[kMaxWideTestChars];
    uint32_t image_length = 0;
    uint32_t command_length = 0;
    widen_ascii(image_name, wide_image, &image_length);
    if (command_line != 0) {
        widen_ascii(command_line, wide_command, &command_length);
    }
    int32_t score = 0;
    const int scored = everbloom_kernel_model_score_launch(
        wide_image,
        image_length,
        command_line != 0 ? wide_command : 0,
        command_length,
        &score);
    // Scores are non-negative, so -1 is unambiguous as "no score produced".
    return scored ? score : -1;
}

static void test_kernel_model_score_launch_helper() {
    const EVERBLOOM_MATRIX_MODEL* model = EverbloomKernelModelGet();
    CHECK(model != 0, "the model must be embedded for this test");
    if (model == 0) {
        return;
    }

    const int32_t benign = score_launch_for("C:\\Windows\\System32\\svchost.exe", 0);
    const int32_t suspicious = score_launch_for(
        "C:\\Users\\a\\AppData\\Local\\Temp\\invoice.pdf.exe",
        "powershell -windowstyle hidden -encodedcommand AAAA");
    CHECK(benign >= 0, "a benign launch must still produce a score, got %d", benign);
    CHECK(benign < model->output_threshold,
          "a benign launch must not cross the advisory threshold, got %d",
          benign);
    CHECK(suspicious >= model->output_threshold,
          "a suspicious launch must cross the advisory threshold, got %d",
          suspicious);

    /*
     * Absent inputs must still produce a score rather than a failure, and that
     * score must be the output floor. The callback has to be able to say
     * "nothing suspicious here" without the helper reporting an error.
     */
    int32_t score = 0;
    CHECK(everbloom_kernel_model_score_launch(0, 0, 0, 0, &score) == 1,
          "absent inputs must still produce a score");
    CHECK(score == model->layers[model->layer_count - 1].activation_min,
          "absent inputs must score the output floor, got %d",
          score);
    CHECK(everbloom_kernel_model_score_launch(0, 0, 0, 0, 0) == 0,
          "a null score output must be rejected");
}

int main() {
    build_model();

    test_exact_agreement_with_integer_reference();
    test_agreement_with_float_model();
    test_error_codes();
    test_requantize_properties();
    test_narrow_and_clamp();
    test_relu_saturates_without_wrapping();
    test_fixture_uses_a_shift_above_31();
    test_kernel_features_flag_launch_risk();
    test_kernel_model_scores_launch_risk();
    test_kernel_model_score_launch_helper();

    printf("kernel matrix: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
