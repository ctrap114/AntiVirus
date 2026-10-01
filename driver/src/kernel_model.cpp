/*
 * Kernel model tables and the scoring entry point.
 *
 * This translation unit is deliberately free of kernel headers. The model is
 * plain const data and the scoring call is a thin wrapper over the integer
 * core, so nothing here needs ntifs.h, and keeping it portable means the exact
 * tables the driver ships are the ones the user-mode harness evaluates. Only
 * the *placement* of this data is kernel-specific: plain const data lands in a
 * non-paged section by default, because the PAGE section is opt-in. Do not move
 * these tables into #pragma data_seg("PAGE") and do not mark the scoring call
 * #pragma alloc_text(PAGE, ...): both would make the weights pageable while a
 * callback may be reading them at DISPATCH_LEVEL.
 */

#include "everbloom_kernel_model.h"

namespace {

/*
 * Bootstrap weights, one per EVERBLOOM_KERNEL_FEATURE, as Q7 in [-127, 127].
 *
 * These are NOT trained. They are the launch heuristics this driver already
 * applies elsewhere, written down once in model form so the whole pipeline -
 * feature extraction, int8 quantization, fixed-point rescale, thresholding - is
 * live and exercised end to end instead of existing as untested scaffolding. A
 * trained model exported by tools/ replaces this table without any code change;
 * only the numbers below and the multiplier/shift pair move.
 *
 * The values encode direction and relative confidence:
 *
 *   +127  obfuscated command line      strongest single launch signal
 *   +114  user-writable directory      the payload is not installed
 *   +102  script extension             interpreted, not image-loaded
 *    +89  double extension             deliberately disguised type
 *    +51  LOLBin stem                  proxy execution
 *    +44  digit ratio                  generated-looking name
 *    +32  distinct-character ratio     generated-looking name
 *    +19  command-line length          wrapped or templated invocation
 *    +13  executable extension         ordinary, barely informative
 *     +6  path length                  weak; deep profiles are normal
 *     +6  basename length              weak for the same reason
 *    -64  system directory             strongly negative: installed location
 *
 * A negative weight is what makes the model able to clear an ordinary
 * System32 launch rather than only ever adding suspicion.
 */
const int8_t kModelWeights[EVERBLOOM_KERNEL_FEATURE_COUNT] = {
    6, 6, 114, -64, 13, 102, 89, 51, 44, 32, 19, 127
};

/*
 * Zero bias, in the output domain. It is kept as a real table rather than a
 * null pointer so the exported model can introduce a bias without changing the
 * shape of this file.
 */
const int32_t kModelBias[1] = { 0 };

/*
 * Fixed-point rescale for the output domain.
 *
 * features are int8 in [0, 127] representing evidence in [0, 1], so
 * scale_feature = 1/127. Weights are Q7, so scale_weight = 1/127. The output is
 * per-mille of the real score, so scale_output = 1/1000. The rescale ratio is
 * therefore
 *
 *     scale_weight * scale_feature / scale_output
 *         = (1/127) * (1/127) * 1000
 *         = 0.062000124
 *
 * normalised to Q31. The resulting shift is 35, not 30: this is exactly the
 * case that motivated widening the core's shift bound past 31, and the harness
 * asserts it stays above 31 so the coverage cannot silently regress.
 *
 * activation_min is 0, not a large negative bound, and that is load bearing
 * rather than cosmetic. This model produces a risk score, so a negative value
 * is meaningless, and clamping at zero keeps the output domain non-negative.
 * That is what makes the core's convention sound at this call site: the core
 * reports failures as negative EVERBLOOM_MATRIX_ERR_* codes, so a caller can
 * only tell a failure from a score if the score domain excludes negatives.
 * With a negative activation_min an ordinary installed binary would score
 * below zero and EverbloomKernelModelScore would misread it as a failure. The
 * harness asserts this bound stays non-negative.
 */
const EVERBLOOM_MATRIX_LAYER kModelLayers[1] = {
    {
        kModelWeights,
        kModelBias,
        EVERBLOOM_KERNEL_FEATURE_COUNT,
        1u,
        2130308039,
        35u,
        0,
        1000000
    }
};

/*
 * output_threshold is advisory. At these weights the score saturates near 4244
 * per-mille when every feature is fully present, and a fully suspicious launch
 * (user-writable directory plus a script or disguised extension, or an
 * obfuscated command line) lands well above 1500 while an ordinary installed
 * binary clamps to zero. The driver treats crossing it as telemetry, never as a
 * veto.
 */
const EVERBLOOM_MATRIX_MODEL kModel = {
    kModelLayers,
    1u,
    EVERBLOOM_KERNEL_FEATURE_COUNT,
    1500
};

} // namespace

const EVERBLOOM_MATRIX_MODEL* EverbloomKernelModelGet() {
    return &kModel;
}

int EverbloomKernelModelScore(const int8_t* features, int32_t* score) {
    if (features == 0 || score == 0) {
        return 0;
    }
    const EVERBLOOM_MATRIX_MODEL* model = EverbloomKernelModelGet();
    if (model == 0) {
        return 0;
    }

    /*
     * Stack scratch, and the reason is worth stating because it looks like a
     * violation of the core's caller-owned-scratch contract.
     *
     * A process-creation callback can run concurrently on several CPUs, so a
     * single shared scratch would need either per-CPU storage or a lock. A lock
     * is not available here: this path must not block, and it can be reached
     * while a spin lock is already held elsewhere in the callback chain. A
     * per-call frame is race-free by construction and EVERBLOOM_MATRIX_SCRATCH is
     * 384 bytes, a small fraction of the roughly 12 KB kernel stack. The
     * contract exists to keep large buffers off the stack; 384 bytes is not one.
     */
    EVERBLOOM_MATRIX_SCRATCH scratch;
    const int32_t result = everbloom_matrix_evaluate(model, features, &scratch);
    if (result < 0) {
        return 0;
    }
    *score = result;
    return 1;
}
