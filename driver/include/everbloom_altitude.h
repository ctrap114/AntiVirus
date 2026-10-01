/*
 * Altitude-string arithmetic for collision recovery.
 *
 * Why this exists
 * ---------------
 * A minifilter altitude lives in a global namespace: only one instance may sit
 * at a given altitude on a given volume. The object-callback registration
 * shares that namespace, so both of these report the same failure when another
 * driver already holds the value:
 *
 *   FltAttachVolumeAtAltitude  -> STATUS_FLT_INSTANCE_ALTITUDE_COLLISION
 *   ObRegisterCallbacks        -> STATUS_FLT_INSTANCE_ALTITUDE_COLLISION
 *
 * Recovering from a collision means stepping the altitude and retrying, which
 * needs the arithmetic below. Keeping it here rather than inline in the driver
 * is deliberate: this header has no kernel dependency, so the same code that
 * compiles into everbloom_driver.sys is verified by a user-mode test target.
 *
 * Scope
 * -----
 * Plain integer altitudes only - the form this driver ships. A fractional part
 * is rejected rather than truncated: silently turning "325000.7" into
 * "325000" could land directly on another vendor's filter, which is the very
 * collision this code exists to avoid.
 *
 * Note that altitude strings are compared as numbers with leading zeros
 * ignored ("03333" outranks "100.123456"), so parsing to an integer is the
 * correct comparison and rendering back from an integer is lossless for the
 * integer-only form.
 */

#ifndef EVERBLOOM_ALTITUDE_H
#define EVERBLOOM_ALTITUDE_H

#include <stdint.h>

/* FSFilter Anti-Virus, the load order group this filter belongs to. Stepping
 * down must never leave it: an altitude outside the group would place the
 * filter in a group it was not designed for. */
#define EVERBLOOM_ALTITUDE_GROUP_MIN 320000u
#define EVERBLOOM_ALTITUDE_GROUP_MAX 329999u

/* Widest integer altitude in the group range. */
#define EVERBLOOM_ALTITUDE_MAX_DIGITS 6u

/*
 * The altitude this driver package ships with.
 *
 * The same value appears as the Altitude string in
 * driver/package/everbloom_driver.inf. The two cannot be derived from one
 * another - the INF is plain text and cannot include a C header - so
 * tools/dev_driver.ps1 parses both and refuses to start the service when they
 * disagree. That check is the only thing keeping them in step; without it a
 * change to one silently leaves the other behind.
 */
#define EVERBLOOM_ALTITUDE_SHIPPED 329671u

/* Bounded so a pathological collision storm cannot spin forever during load. */
#define EVERBLOOM_ALTITUDE_RETRY_LIMIT 8u

static inline int everbloom_altitude_is_digit(uint16_t character) {
    return character >= (uint16_t)'0' && character <= (uint16_t)'9';
}

/*
 * Parse a plain integer altitude string.
 * Returns 0 on success and stores the value, -1 if the text is empty, too
 * long, or contains anything other than decimal digits.
 */
static inline int everbloom_altitude_parse(
    const uint16_t* text,
    uint32_t length,
    uint32_t* out_value) {
    if (text == 0 || out_value == 0) {
        return -1;
    }
    if (length == 0 || length > EVERBLOOM_ALTITUDE_MAX_DIGITS) {
        return -1;
    }
    uint32_t value = 0;
    for (uint32_t index = 0; index < length; ++index) {
        if (!everbloom_altitude_is_digit(text[index])) {
            return -1;
        }
        value = value * 10u + (uint32_t)(text[index] - (uint16_t)'0');
    }
    *out_value = value;
    return 0;
}

/*
 * Render an integer altitude as digits.
 * Returns the number of characters written, or 0 if the buffer is too small.
 * Writes nothing when it fails, so the caller never sees a partial string.
 */
static inline uint32_t everbloom_altitude_format(
    uint32_t value,
    uint16_t* out_text,
    uint32_t capacity) {
    if (out_text == 0 || capacity < EVERBLOOM_ALTITUDE_MAX_DIGITS) {
        return 0;
    }
    uint16_t reversed[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    uint32_t count = 0;
    if (value == 0) {
        reversed[count++] = (uint16_t)'0';
    }
    while (value > 0) {
        reversed[count++] = (uint16_t)('0' + (value % 10u));
        value /= 10u;
    }
    for (uint32_t index = 0; index < count; ++index) {
        out_text[index] = reversed[count - 1u - index];
    }
    return count;
}

/* True when the value sits inside the FSFilter Anti-Virus band. */
static inline int everbloom_altitude_in_group(uint32_t value) {
    return value >= EVERBLOOM_ALTITUDE_GROUP_MIN && value <= EVERBLOOM_ALTITUDE_GROUP_MAX;
}

/*
 * Next candidate after a collision.
 * Returns 0 and stores the candidate, or -1 when stepping down would cross the
 * group floor. A -1 means "stop retrying and fail the surface" rather than
 * "keep going", so the caller cannot drift into another group by accident.
 */
static inline int everbloom_altitude_step_down(uint32_t current, uint32_t* out_next) {
    if (out_next == 0) {
        return -1;
    }
    if (!everbloom_altitude_in_group(current)) {
        return -1;
    }
    if (current <= EVERBLOOM_ALTITUDE_GROUP_MIN) {
        return -1;
    }
    *out_next = current - 1u;
    return 0;
}

#endif /* EVERBLOOM_ALTITUDE_H */
