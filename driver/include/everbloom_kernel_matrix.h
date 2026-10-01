#pragma once

/*
 * Integer-only matrix inference core for kernel mode.
 *
 * Why it is shaped this way:
 *
 *  - The WFP classify callback runs at DISPATCH_LEVEL, where floating point is
 *    not permitted (and would need KeSaveExtendedProcessorState even at
 *    PASSIVE_LEVEL). Every operation here is therefore integer.
 *  - The x64 kernel stack is roughly 12 KB, so no working buffer lives on the
 *    stack. All mutable state is passed in through EVERBLOOM_MATRIX_SCRATCH,
 *    which the caller allocates once at PASSIVE_LEVEL and reuses.
 *  - The core never allocates, never blocks and takes no locks, so it is safe
 *    to call from any callback that already owns its state.
 *  - `tract`/ONNX cannot be linked into a kernel image (rayon thread pools,
 *    dynamic dispatch, heap allocation), so the model is exported offline as
 *    quantized int8 weights. See the export step under tools/.
 *
 * Quantization is the standard symmetric per-tensor scheme used by TFLite and
 * gemmlowp: weights and activations are int8, accumulators are int32, and the
 * rescale back to the output domain is a fixed-point multiply followed by a
 * right shift.
 *
 * One layer computes:
 *
 *     acc[o] = sum_i weights[o][i] * input[i]
 *     y[o]   = clamp(requantize(acc[o]) + bias[o], activation_min, activation_max)
 *
 * `bias` is expressed in the *output* domain (already requantized), so the
 * exporter does not have to pre-scale it into the accumulator domain.
 *
 * Every layer except the last narrows its result to int8 and writes it into
 * the caller's ping-pong buffer. The last layer must have exactly one output
 * and is returned as int32, so the final score is never narrowed to int8.
 *
 * Accumulator headroom: a product of two int8 values is at most 16129, and a
 * layer takes at most EVERBLOOM_MATRIX_MAX_UNITS of them, so an accumulator
 * stays under 2^21. The fixed-point product is computed in int64, and with the
 * multiplier below 2^31 and the shift at most EVERBLOOM_MATRIX_MAX_SHIFT the
 * intermediate, including the half-step rounding offset, stays below 2^62 and
 * therefore cannot overflow.
 *
 * Non-paged placement: plain `const` data in a driver lands in a non-paged
 * section by default, because the `PAGE` section is opt-in. Model tables must
 * therefore NOT be moved into `#pragma data_seg("PAGE")`, and code that reads
 * them at DISPATCH_LEVEL must not be marked `#pragma alloc_text(PAGE, ...)`.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Widest layer accepted. Bounds the scratch struct and the accumulator range. */
#define EVERBLOOM_MATRIX_MAX_UNITS 64u
#define EVERBLOOM_MATRIX_MAX_LAYERS 4u

/*
 * Largest right shift accepted by the fixed-point rescale.
 *
 * The rescale forms an int64 product, so a shift up to 62 is representable:
 * the half-step rounding offset is 1 << 61 and the product stays below 2^52,
 * leaving the intermediate below 2^62. This bound matters in practice because
 * real per-tensor scales are small. A typical
 * scale_weight * scale_input / scale_output lands near 1e-2, which needs a
 * shift near 37 once the multiplier is normalised into [2^30, 2^31). Capping
 * the shift at 31 would silently discard most of the multiplier's mantissa.
 */
#define EVERBLOOM_MATRIX_MAX_SHIFT 62u

/* Result codes. Negative values are failures. */
#define EVERBLOOM_MATRIX_OK 0
#define EVERBLOOM_MATRIX_ERR_NULL (-1)
#define EVERBLOOM_MATRIX_ERR_SHAPE (-2)
#define EVERBLOOM_MATRIX_ERR_LAYERS (-3)
#define EVERBLOOM_MATRIX_ERR_SHIFT (-4)

typedef struct EVERBLOOM_MATRIX_LAYER {
    /* [outputs][inputs], row-major. */
    const int8_t* weights;
    /* [outputs], in the output domain. May be null for a zero bias. */
    const int32_t* bias;
    uint32_t inputs;
    uint32_t outputs;
    /*
     * Fixed-point rescale: the real ratio is multiplier * 2^-shift.
     *
     * The exporter normalises the multiplier into [2^30, 2^31) so the full
     * 31-bit mantissa is used, which places the shift in [1, 62] for any
     * realistic per-tensor scale. The core does not enforce that range, it
     * only requires the shift to stay within EVERBLOOM_MATRIX_MAX_SHIFT.
     */
    int32_t requant_multiplier;
    uint32_t requant_shift;
    /* Clamp bounds applied after bias, in the output domain. */
    int32_t activation_min;
    int32_t activation_max;
} EVERBLOOM_MATRIX_LAYER;

typedef struct EVERBLOOM_MATRIX_MODEL {
    const EVERBLOOM_MATRIX_LAYER* layers;
    uint32_t layer_count;
    /* Width of the feature vector handed to layer 0. */
    uint32_t feature_count;
    /*
     * Advisory decision boundary in the output domain. Callers may ignore it;
     * it exists so the same exported model can be used for triage and for a
     * hard gate without re-deriving the threshold on each side.
     */
    int32_t output_threshold;
} EVERBLOOM_MATRIX_MODEL;

/*
 * All mutable inference state. The caller owns this so the core stays
 * allocation-free and the kernel stack frame stays small.
 */
typedef struct EVERBLOOM_MATRIX_SCRATCH {
    int8_t ping[EVERBLOOM_MATRIX_MAX_UNITS];
    int8_t pong[EVERBLOOM_MATRIX_MAX_UNITS];
    int32_t accumulators[EVERBLOOM_MATRIX_MAX_UNITS];
} EVERBLOOM_MATRIX_SCRATCH;

static inline int32_t everbloom_matrix_clamp(int32_t value, int32_t low, int32_t high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

static inline int8_t everbloom_matrix_narrow_int8(int32_t value) {
    if (value > 127) {
        return 127;
    }
    if (value < -128) {
        return -128;
    }
    return (int8_t)value;
}

/*
 * Fixed-point rescale: round(accumulator * multiplier / 2^shift), rounding half
 * away from zero so that a symmetric model stays symmetric.
 *
 * The product is formed in int64.
 *
 * The rounding compares the truncated remainder against the halfway threshold
 * instead of using the more obvious "add half, then arithmetic-shift" shortcut.
 * That shortcut is wrong on the negative side, because an arithmetic right
 * shift floors: an exactly representable value gets pushed one step further
 * away, so it would map -1000.0 to -1001. An exactly representable value has to
 * stay exact, otherwise a multi-layer model drifts by a step per layer.
 *
 * `mask` is positive, so `scaled & mask` is the non-negative residue of
 * `scaled` modulo 2^shift even when `scaled` is negative, which is precisely
 * the truncated fraction to compare against the halfway point.
 *
 * shift == 0 is the identity case (no rescale); a shift above
 * EVERBLOOM_MATRIX_MAX_SHIFT is rejected by the evaluator before this is
 * reached.
 */
static inline int32_t everbloom_matrix_requantize(
    int32_t accumulator,
    int32_t multiplier,
    uint32_t shift) {
    if (shift == 0) {
        return accumulator;
    }
    const int64_t scaled = (int64_t)accumulator * (int64_t)multiplier;
    const int64_t mask = ((int64_t)1 << shift) - 1;
    const int64_t remainder = scaled & mask;
    // For a negative value, an exact half rounds away from zero, which is the
    // direction the floor of `scaled >> shift` already points, so the tie has
    // to be broken toward the floor rather than away from it.
    const int64_t threshold = (mask >> 1) + (scaled < 0 ? 1 : 0);
    return (int32_t)((scaled >> shift) + (remainder > threshold ? 1 : 0));
}

/*
 * acc[o] = sum_i weights[o][i] * input[i]
 *
 * Kept separate from the activation step so the accumulator domain stays
 * inspectable and so a future layer type (for example a residual add) can
 * reuse it.
 */
static inline void everbloom_matrix_gemv(
    const EVERBLOOM_MATRIX_LAYER* layer,
    const int8_t* input,
    int32_t* accumulators) {
    for (uint32_t o = 0; o < layer->outputs; ++o) {
        const int8_t* row = layer->weights + (size_t)o * (size_t)layer->inputs;
        int32_t accumulator = 0;
        for (uint32_t i = 0; i < layer->inputs; ++i) {
            accumulator += (int32_t)row[i] * (int32_t)input[i];
        }
        accumulators[o] = accumulator;
    }
}

/*
 * requantize, add bias, clamp, and narrow to int8.
 *
 * The clamp is what implements the activation: a ReLU hidden layer sets
 * activation_min to 0 and activation_max to 127, so the narrowing below is a
 * no-op and the activation is exact.
 */
static inline void everbloom_matrix_activate_int8(
    const EVERBLOOM_MATRIX_LAYER* layer,
    const int32_t* accumulators,
    int8_t* output) {
    for (uint32_t o = 0; o < layer->outputs; ++o) {
        int32_t value = everbloom_matrix_requantize(
            accumulators[o],
            layer->requant_multiplier,
            layer->requant_shift);
        if (layer->bias != 0) {
            value += layer->bias[o];
        }
        output[o] = everbloom_matrix_narrow_int8(
            everbloom_matrix_clamp(value, layer->activation_min, layer->activation_max));
    }
}

/*
 * Runs the model over `features` and returns the single output value in the
 * model's output domain, or a negative EVERBLOOM_MATRIX_ERR_* code.
 *
 * Shape is validated on every call rather than trusted, because a model table
 * is a build-time artifact and a malformed one must fail closed instead of
 * reading past its weights.
 */
static inline int32_t everbloom_matrix_evaluate(
    const EVERBLOOM_MATRIX_MODEL* model,
    const int8_t* features,
    EVERBLOOM_MATRIX_SCRATCH* scratch) {
    if (model == 0 || features == 0 || scratch == 0 || model->layers == 0) {
        return EVERBLOOM_MATRIX_ERR_NULL;
    }
    if (model->layer_count == 0 || model->layer_count > EVERBLOOM_MATRIX_MAX_LAYERS) {
        return EVERBLOOM_MATRIX_ERR_LAYERS;
    }
    if (model->feature_count == 0 || model->feature_count > EVERBLOOM_MATRIX_MAX_UNITS) {
        return EVERBLOOM_MATRIX_ERR_SHAPE;
    }

    const int8_t* input = features;
    int8_t* output = scratch->ping;

    for (uint32_t index = 0; index < model->layer_count; ++index) {
        const EVERBLOOM_MATRIX_LAYER* layer = &model->layers[index];
        const uint32_t expected_inputs =
            (index == 0) ? model->feature_count : model->layers[index - 1].outputs;

        // A null weight table is a null-pointer fault rather than a shape
        // mismatch, and the two need different fixes, so they are reported
        // separately.
        if (layer->weights == 0) {
            return EVERBLOOM_MATRIX_ERR_NULL;
        }
        if (layer->inputs != expected_inputs
            || layer->inputs > EVERBLOOM_MATRIX_MAX_UNITS
            || layer->outputs == 0
            || layer->outputs > EVERBLOOM_MATRIX_MAX_UNITS) {
            return EVERBLOOM_MATRIX_ERR_SHAPE;
        }
        if (layer->requant_shift > EVERBLOOM_MATRIX_MAX_SHIFT) {
            return EVERBLOOM_MATRIX_ERR_SHIFT;
        }
        if (layer->activation_min > layer->activation_max) {
            return EVERBLOOM_MATRIX_ERR_SHAPE;
        }

        everbloom_matrix_gemv(layer, input, scratch->accumulators);

        const int last = (index + 1 == model->layer_count);
        if (last) {
            // The final layer is returned at full accumulator precision. If it
            // were narrowed to int8 the score would quantize to 256 levels,
            // which is too coarse for a triage threshold.
            if (layer->outputs != 1) {
                return EVERBLOOM_MATRIX_ERR_SHAPE;
            }
            int32_t value = everbloom_matrix_requantize(
                scratch->accumulators[0],
                layer->requant_multiplier,
                layer->requant_shift);
            if (layer->bias != 0) {
                value += layer->bias[0];
            }
            return everbloom_matrix_clamp(value, layer->activation_min, layer->activation_max);
        }

        everbloom_matrix_activate_int8(layer, scratch->accumulators, output);

        // Ping-pong so the input of the next layer is never overwritten while
        // it is still being read.
        input = output;
        output = (output == scratch->ping) ? scratch->pong : scratch->ping;
    }

    // Unreachable: the loop returns on the last layer.
    return EVERBLOOM_MATRIX_ERR_LAYERS;
}

#ifdef __cplusplus
}
#endif
