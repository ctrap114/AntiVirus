/*
 * User-mode verification harness for the altitude collision arithmetic.
 *
 * The header under test has no kernel dependency, so the exact code that
 * compiles into everbloom_driver.sys is compiled here. This matters because
 * the retry loop runs during driver load: a bug that walks the altitude out
 * of the FSFilter Anti-Virus band, or that wraps at zero, would not surface
 * as a crash but as the filter silently attaching in the wrong group.
 *
 * The tests are grouped by the property they protect:
 *
 *  - parse rejects everything that is not a plain integer, in particular the
 *    fractional form, because truncating "325000.7" to "325000" could land on
 *    another vendor's filter - the collision this code exists to avoid.
 *  - format round-trips and never writes a partial string.
 *  - in_group matches the documented FSFilter Anti-Virus band exactly.
 *  - step_down is monotone, bounded, and fails closed at the group floor.
 */

#include "everbloom_altitude.h"

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

/* --- helpers ------------------------------------------------------------- */

/* Widen an ASCII literal into the UTF-16 form the header consumes. */
static uint32_t widen(const char* ascii, uint16_t* out, uint32_t capacity) {
    uint32_t length = (uint32_t)strlen(ascii);
    if (length >= capacity) {
        length = capacity - 1u;
    }
    for (uint32_t index = 0; index < length; ++index) {
        out[index] = (uint16_t)(unsigned char)ascii[index];
    }
    out[length] = 0;
    return length;
}

static int expect_parse_ok(const char* ascii, uint32_t expected) {
    uint16_t buffer[32];
    uint32_t length = widen(ascii, buffer, 32);
    uint32_t value = 0xFFFFFFFFu;
    int result = everbloom_altitude_parse(buffer, length, &value);
    if (result != 0 || value != expected) {
        printf("FAIL %s:%d: parse(\"%s\") -> rc=%d value=%u, expected %u\n",
               __FILE__, __LINE__, ascii, result, value, expected);
        return 0;
    }
    return 1;
}

static int expect_parse_rejected(const char* ascii) {
    uint16_t buffer[32];
    uint32_t length = widen(ascii, buffer, 32);
    uint32_t value = 0x12345678u;
    int result = everbloom_altitude_parse(buffer, length, &value);
    if (result == 0) {
        printf("FAIL %s:%d: parse(\"%s\") was accepted as %u\n",
               __FILE__, __LINE__, ascii, value);
        return 0;
    }
    /* A rejected parse must not have written to the output. */
    if (value != 0x12345678u) {
        printf("FAIL %s:%d: parse(\"%s\") wrote %u on failure\n",
               __FILE__, __LINE__, ascii, value);
        return 0;
    }
    return 1;
}

/* --- parse --------------------------------------------------------------- */

static void test_parse_accepts_plain_integers() {
    CHECK(expect_parse_ok("0", 0u), "single zero digit");
    CHECK(expect_parse_ok("329671", 329671u), "the shipped altitude");
    CHECK(expect_parse_ok("320000", 320000u), "the group floor");
    CHECK(expect_parse_ok("329999", 329999u), "the group ceiling");
    CHECK(expect_parse_ok("999999", 999999u), "widest representable");
    /*
     * Altitudes compare numerically with leading zeros ignored, so "03333"
     * is the value 3333 and not a six-digit string. Parsing to an integer is
     * therefore the correct comparison, and this pins that down.
     */
    CHECK(expect_parse_ok("03333", 3333u), "leading zeros are not significant");
    CHECK(expect_parse_ok("000001", 1u), "leading zeros in a full-width string");
}

static void test_parse_rejects_non_integers() {
    uint16_t buffer[32];
    uint32_t length = widen("329671", buffer, 32);
    uint32_t value = 0;

    CHECK(expect_parse_rejected(""), "empty string");
    /*
     * The fractional form is the important rejection. Altitude strings do
     * allow a fraction, but this driver does not ship one, and truncating it
     * would silently change which filter we collide with.
     */
    CHECK(expect_parse_rejected("325000.7"), "fractional altitude is rejected, not truncated");
    CHECK(expect_parse_rejected("100.123456"), "long fractional altitude");
    CHECK(expect_parse_rejected("-1"), "negative altitude");
    CHECK(expect_parse_rejected("+325000"), "explicit sign");
    CHECK(expect_parse_rejected("32 671"), "embedded space");
    CHECK(expect_parse_rejected("32967a"), "trailing letter");
    CHECK(expect_parse_rejected("0x51A87"), "hexadecimal form");
    CHECK(expect_parse_rejected("1234567"), "seven digits exceeds the buffer width");
    CHECK(expect_parse_rejected(" "), "single space");

    CHECK(everbloom_altitude_parse(0, 6u, &value) == -1, "null text is rejected");
    CHECK(everbloom_altitude_parse(buffer, length, 0) == -1, "null output is rejected");
    CHECK(everbloom_altitude_parse(buffer, 0u, &value) == -1, "zero length is rejected");
}

/* --- format -------------------------------------------------------------- */

static void test_format_round_trips() {
    uint16_t buffer[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    memset(buffer, 0, sizeof(buffer));

    CHECK(everbloom_altitude_format(329671u, buffer, EVERBLOOM_ALTITUDE_MAX_DIGITS) == 6u,
          "329671 renders as six characters");
    CHECK(buffer[0] == (uint16_t)'3' && buffer[5] == (uint16_t)'1',
          "329671 renders most significant digit first");
    CHECK(buffer[0] == (uint16_t)'3' && buffer[1] == (uint16_t)'2'
              && buffer[2] == (uint16_t)'9' && buffer[3] == (uint16_t)'6'
              && buffer[4] == (uint16_t)'7' && buffer[5] == (uint16_t)'1',
          "329671 renders exactly");

    CHECK(everbloom_altitude_format(0u, buffer, EVERBLOOM_ALTITUDE_MAX_DIGITS) == 1u,
          "zero renders as one character");
    CHECK(buffer[0] == (uint16_t)'0', "zero renders as the digit zero");

    CHECK(everbloom_altitude_format(320000u, buffer, EVERBLOOM_ALTITUDE_MAX_DIGITS) == 6u,
          "320000 renders as six characters");
    CHECK(buffer[5] == (uint16_t)'0', "320000 ends in zero");

    /*
     * Round-trip through parse for every value the retry loop can produce
     * between the shipped altitude and the group floor. Rendering back from
     * an integer must be lossless for the integer-only form.
     */
    int round_trip_failures = 0;
    for (uint32_t candidate = 329671u; candidate >= EVERBLOOM_ALTITUDE_GROUP_MIN; --candidate) {
        uint16_t rendered[EVERBLOOM_ALTITUDE_MAX_DIGITS];
        uint32_t count = everbloom_altitude_format(
            candidate, rendered, EVERBLOOM_ALTITUDE_MAX_DIGITS);
        if (count == 0u) {
            ++round_trip_failures;
            break;
        }
        uint32_t parsed = 0;
        if (everbloom_altitude_parse(rendered, count, &parsed) != 0 || parsed != candidate) {
            ++round_trip_failures;
            break;
        }
        if (candidate == EVERBLOOM_ALTITUDE_GROUP_MIN) {
            break;
        }
    }
    CHECK(round_trip_failures == 0, "every reachable altitude round-trips through format/parse");
}

static void test_format_rejects_small_buffers() {
    uint16_t buffer[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    memset(buffer, 0xAB, sizeof(buffer));

    CHECK(everbloom_altitude_format(329671u, buffer, 0u) == 0u, "zero capacity is rejected");
    CHECK(everbloom_altitude_format(329671u, buffer, 3u) == 0u, "short capacity is rejected");
    CHECK(everbloom_altitude_format(329671u, 0, EVERBLOOM_ALTITUDE_MAX_DIGITS) == 0u,
          "null buffer is rejected");
    /* A failed format must not have touched the buffer. */
    int untouched = 1;
    for (uint32_t index = 0; index < EVERBLOOM_ALTITUDE_MAX_DIGITS; ++index) {
        if (buffer[index] != (uint16_t)0xABAB) {
            untouched = 0;
        }
    }
    CHECK(untouched, "a rejected format writes nothing");
}

/* --- group bounds -------------------------------------------------------- */

static void test_in_group_matches_the_documented_band() {
    CHECK(!everbloom_altitude_in_group(0u), "zero is outside the band");
    CHECK(!everbloom_altitude_in_group(319999u), "one below the floor");
    CHECK(everbloom_altitude_in_group(320000u), "the floor is inside");
    CHECK(everbloom_altitude_in_group(325000u), "a mid-band value is inside");
    CHECK(everbloom_altitude_in_group(329671u), "the shipped altitude is inside");
    CHECK(everbloom_altitude_in_group(329999u), "the ceiling is inside");
    CHECK(!everbloom_altitude_in_group(330000u), "one above the ceiling");
    CHECK(!everbloom_altitude_in_group(370102u), "the old object-callback value is outside");
}

/* --- step down ----------------------------------------------------------- */

static void test_step_down_is_monotone_and_bounded() {
    uint32_t next = 0xFFFFFFFFu;
    CHECK(everbloom_altitude_step_down(329671u, &next) == 0 && next == 329670u,
          "one step below the shipped altitude");
    CHECK(everbloom_altitude_step_down(329999u, &next) == 0 && next == 329998u,
          "stepping from the ceiling stays in the band");
    CHECK(everbloom_altitude_step_down(320001u, &next) == 0 && next == 320000u,
          "the last step lands exactly on the floor");

    /* At the floor there is no legal next value: the caller must stop. */
    CHECK(everbloom_altitude_step_down(320000u, &next) == -1,
          "the floor refuses to step, so the caller fails closed");
    CHECK(everbloom_altitude_step_down(319999u, &next) == -1, "below the floor refuses to step");
    CHECK(everbloom_altitude_step_down(370102u, &next) == -1,
          "a value outside the band refuses to step");
    CHECK(everbloom_altitude_step_down(0u, &next) == -1, "zero refuses to step");

    /* Never wrap: the floor is the hard stop. */
    next = 0xFFFFFFFFu;
    CHECK(everbloom_altitude_step_down(320000u, &next) == -1 && next == 0xFFFFFFFFu,
          "a refused step leaves the output untouched");
    CHECK(everbloom_altitude_step_down(329671u, 0) == -1, "null output is rejected");
}

static void test_retry_loop_stays_in_band() {
    /*
     * Simulate the collision retry loop the driver runs at load time. Starting
     * from the shipped altitude, walk down at most the retry limit and assert
     * that every candidate remains in the FSFilter Anti-Virus band.
     */
    uint32_t current = 329671u;
    uint32_t attempts = 0;
    int out_of_band = 0;
    while (attempts < EVERBLOOM_ALTITUDE_RETRY_LIMIT) {
        uint32_t candidate = 0;
        if (everbloom_altitude_step_down(current, &candidate) != 0) {
            break;
        }
        if (!everbloom_altitude_in_group(candidate)) {
            out_of_band = 1;
            break;
        }
        current = candidate;
        ++attempts;
    }
    CHECK(!out_of_band, "every retry candidate stays inside the band");
    CHECK(attempts == EVERBLOOM_ALTITUDE_RETRY_LIMIT,
          "the shipped altitude affords the full retry budget, got %u", attempts);
    CHECK(current == 329671u - EVERBLOOM_ALTITUDE_RETRY_LIMIT,
          "the retry loop steps down exactly one per collision, ended at %u", current);

    /*
     * Exhausting the budget must not escape the band. Walk all the way to the
     * floor and confirm the loop stops there rather than wrapping.
     */
    current = EVERBLOOM_ALTITUDE_GROUP_MIN + 2u;
    uint32_t steps = 0;
    while (everbloom_altitude_step_down(current, &current) == 0) {
        ++steps;
        if (steps > EVERBLOOM_ALTITUDE_GROUP_MAX) {
            break;
        }
    }
    CHECK(current == EVERBLOOM_ALTITUDE_GROUP_MIN,
          "a full descent stops on the floor, ended at %u", current);
    CHECK(steps == 2u, "a full descent takes exactly the remaining steps, took %u", steps);
}

static void test_shipped_altitude_is_usable() {
    /*
     * The value the package ships with has to be inside the band, or the
     * filter would attach in a load order group it was not designed for.
     */
    CHECK(everbloom_altitude_in_group(EVERBLOOM_ALTITUDE_SHIPPED),
          "the shipped altitude is inside the FSFilter Anti-Virus band");

    /*
     * The object-callback registration sits one below the minifilter so the
     * two never collide with each other. Both must still be in band, and they
     * must be distinct - an off-by-one that made them equal would cost the
     * handle-protection surface on every machine.
     */
    const uint32_t object_callback = EVERBLOOM_ALTITUDE_SHIPPED - 1u;
    CHECK(object_callback != EVERBLOOM_ALTITUDE_SHIPPED,
          "the two registrations must not share an altitude");
    CHECK(everbloom_altitude_in_group(object_callback),
          "the object-callback altitude is inside the band");

    /*
     * The shipped altitude must afford the full retry budget without leaving
     * the band, otherwise the collision loop would give up early on a busy
     * machine.
     */
    uint32_t current = EVERBLOOM_ALTITUDE_SHIPPED;
    uint32_t stepped = 0;
    while (stepped < EVERBLOOM_ALTITUDE_RETRY_LIMIT
           && everbloom_altitude_step_down(current, &current) == 0) {
        ++stepped;
    }
    CHECK(stepped == EVERBLOOM_ALTITUDE_RETRY_LIMIT,
          "the shipped altitude affords the full retry budget, got %u", stepped);
    CHECK(everbloom_altitude_in_group(current),
          "the retry budget never leaves the band, ended at %u", current);

    /* The shipped value must be renderable into the fixed-width buffer. */
    uint16_t text[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    CHECK(everbloom_altitude_format(
              EVERBLOOM_ALTITUDE_SHIPPED, text, EVERBLOOM_ALTITUDE_MAX_DIGITS) == 6u,
          "the shipped altitude fits the six-digit buffer");
    uint32_t reparsed = 0;
    CHECK(everbloom_altitude_parse(text, 6u, &reparsed) == 0
              && reparsed == EVERBLOOM_ALTITUDE_SHIPPED,
          "the shipped altitude survives a render/parse round trip");
}

int main() {
    test_parse_accepts_plain_integers();
    test_parse_rejects_non_integers();
    test_format_round_trips();
    test_format_rejects_small_buffers();
    test_in_group_matches_the_documented_band();
    test_step_down_is_monotone_and_bounded();
    test_retry_loop_stays_in_band();
    test_shipped_altitude_is_usable();

    printf("kernel altitude: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
