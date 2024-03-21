/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
null_empty(void **state)
{
    assert_false(pcmk__xml_needs_escape(NULL, false));
    assert_false(pcmk__xml_needs_escape(NULL, true));

    assert_false(pcmk__xml_needs_escape("", false));
    assert_false(pcmk__xml_needs_escape("", true));
}

static void
escape_unchanged(void **state)
{
    // No escaped characters (note: this string includes single quote at end)
    const char *unchanged = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789"
                            "`~!@#$%^*()-_=+/|\\[]{}?.,'";

    assert_false(pcmk__xml_needs_escape(unchanged, false));
    assert_false(pcmk__xml_needs_escape(unchanged, true));
}

// Ensure special characters get escaped at start, middle, and end

static void
escape_left_angle(void **state)
{
    const char *l_angle_left = "<abcdef";
    const char *l_angle_mid = "abc<def";
    const char *l_angle_right = "abcdef<";

    assert_true(pcmk__xml_needs_escape(l_angle_left, false));
    assert_true(pcmk__xml_needs_escape(l_angle_mid, false));
    assert_true(pcmk__xml_needs_escape(l_angle_right, false));

    assert_true(pcmk__xml_needs_escape(l_angle_left, true));
    assert_true(pcmk__xml_needs_escape(l_angle_mid, true));
    assert_true(pcmk__xml_needs_escape(l_angle_right, true));
}

static void
escape_right_angle(void **state)
{
    const char *r_angle_left = ">abcdef";
    const char *r_angle_mid = "abc>def";
    const char *r_angle_right = "abcdef>";

    assert_true(pcmk__xml_needs_escape(r_angle_left, false));
    assert_true(pcmk__xml_needs_escape(r_angle_mid, false));
    assert_true(pcmk__xml_needs_escape(r_angle_right, false));

    assert_true(pcmk__xml_needs_escape(r_angle_left, true));
    assert_true(pcmk__xml_needs_escape(r_angle_mid, true));
    assert_true(pcmk__xml_needs_escape(r_angle_right, true));
}

static void
escape_ampersand(void **state)
{
    const char *ampersand_left = "&abcdef";
    const char *ampersand_mid = "abc&def";
    const char *ampersand_right = "abcdef&";

    assert_true(pcmk__xml_needs_escape(ampersand_left, false));
    assert_true(pcmk__xml_needs_escape(ampersand_mid, false));
    assert_true(pcmk__xml_needs_escape(ampersand_right, false));

    assert_true(pcmk__xml_needs_escape(ampersand_left, true));
    assert_true(pcmk__xml_needs_escape(ampersand_mid, true));
    assert_true(pcmk__xml_needs_escape(ampersand_right, true));
}

static void
escape_double_quote(void **state)
{
    const char *double_quote_left = "\"abcdef";
    const char *double_quote_mid = "abc\"def";
    const char *double_quote_right = "abcdef\"";

    assert_false(pcmk__xml_needs_escape(double_quote_left, false));
    assert_false(pcmk__xml_needs_escape(double_quote_mid, false));
    assert_false(pcmk__xml_needs_escape(double_quote_right, false));

    assert_true(pcmk__xml_needs_escape(double_quote_left, true));
    assert_true(pcmk__xml_needs_escape(double_quote_mid, true));
    assert_true(pcmk__xml_needs_escape(double_quote_right, true));
}

static void
escape_newline(void **state)
{
    const char *newline_left = "\nabcdef";
    const char *newline_mid = "abc\ndef";
    const char *newline_right = "abcdef\n";

    assert_false(pcmk__xml_needs_escape(newline_left, false));
    assert_false(pcmk__xml_needs_escape(newline_mid, false));
    assert_false(pcmk__xml_needs_escape(newline_right, false));

    assert_true(pcmk__xml_needs_escape(newline_left, true));
    assert_true(pcmk__xml_needs_escape(newline_mid, true));
    assert_true(pcmk__xml_needs_escape(newline_right, true));
}

static void
escape_tab(void **state)
{
    const char *tab_left = "\tabcdef";
    const char *tab_mid = "abc\tdef";
    const char *tab_right = "abcdef\t";

    assert_false(pcmk__xml_needs_escape(tab_left, false));
    assert_false(pcmk__xml_needs_escape(tab_mid, false));
    assert_false(pcmk__xml_needs_escape(tab_right, false));

    assert_true(pcmk__xml_needs_escape(tab_left, true));
    assert_true(pcmk__xml_needs_escape(tab_mid, true));
    assert_true(pcmk__xml_needs_escape(tab_right, true));
}

static void
escape_carriage_return(void **state)
{
    const char *cr_left = "\rabcdef";
    const char *cr_mid = "abc\rdef";
    const char *cr_right = "abcdef\r";

    assert_true(pcmk__xml_needs_escape(cr_left, false));
    assert_true(pcmk__xml_needs_escape(cr_mid, false));
    assert_true(pcmk__xml_needs_escape(cr_right, false));

    assert_true(pcmk__xml_needs_escape(cr_left, true));
    assert_true(pcmk__xml_needs_escape(cr_mid, true));
    assert_true(pcmk__xml_needs_escape(cr_right, true));
}

static void
escape_nonprinting(void **state)
{
    const char *alert_left = "\aabcdef";
    const char *alert_mid = "abc\adef";
    const char *alert_right = "abcdef\a";

    const char *delete_left = "\x7F""abcdef";
    const char *delete_mid = "abc\x7F""def";
    const char *delete_right = "abcdef\x7F";

    const char *nonprinting_all = "\a\x7F\x1B";

    assert_true(pcmk__xml_needs_escape(alert_left, false));
    assert_true(pcmk__xml_needs_escape(alert_mid, false));
    assert_true(pcmk__xml_needs_escape(alert_right, false));

    assert_true(pcmk__xml_needs_escape(alert_left, true));
    assert_true(pcmk__xml_needs_escape(alert_mid, true));
    assert_true(pcmk__xml_needs_escape(alert_right, true));

    assert_true(pcmk__xml_needs_escape(delete_left, false));
    assert_true(pcmk__xml_needs_escape(delete_mid, false));
    assert_true(pcmk__xml_needs_escape(delete_right, false));

    assert_true(pcmk__xml_needs_escape(delete_left, true));
    assert_true(pcmk__xml_needs_escape(delete_mid, true));
    assert_true(pcmk__xml_needs_escape(delete_right, true));

    assert_true(pcmk__xml_needs_escape(nonprinting_all, false));
    assert_true(pcmk__xml_needs_escape(nonprinting_all, true));
}

static void
escape_utf8(void **state)
{
    /* Non-ASCII UTF-8 characters may be two, three, or four 8-bit bytes wide
     * and should not be escaped.
     */
    const char *chinese = "仅高级使用";
    const char *two_byte = "abc""\xCF\xA6""def";
    const char *two_byte_special = "abc""\xCF\xA6""d<ef";
    const char *three_byte = "abc""\xEF\x98\x98""def";
    const char *three_byte_special = "abc""\xEF\x98\x98""d<ef";
    const char *four_byte = "abc""\xF0\x94\x81\x90""def";
    const char *four_byte_special = "abc""\xF0\x94\x81\x90""d<ef";

    assert_false(pcmk__xml_needs_escape(chinese, false));
    assert_false(pcmk__xml_needs_escape(chinese, true));

    assert_false(pcmk__xml_needs_escape(two_byte, false));
    assert_false(pcmk__xml_needs_escape(two_byte, true));
    assert_true(pcmk__xml_needs_escape(two_byte_special, false));
    assert_true(pcmk__xml_needs_escape(two_byte_special, true));

    assert_false(pcmk__xml_needs_escape(three_byte, false));
    assert_false(pcmk__xml_needs_escape(three_byte, true));
    assert_true(pcmk__xml_needs_escape(three_byte_special, false));
    assert_true(pcmk__xml_needs_escape(three_byte_special, true));

    assert_false(pcmk__xml_needs_escape(four_byte, false));
    assert_false(pcmk__xml_needs_escape(four_byte, true));
    assert_true(pcmk__xml_needs_escape(four_byte_special, false));
    assert_true(pcmk__xml_needs_escape(four_byte_special, true));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_empty),
                cmocka_unit_test(escape_unchanged),
                cmocka_unit_test(escape_left_angle),
                cmocka_unit_test(escape_right_angle),
                cmocka_unit_test(escape_ampersand),
                cmocka_unit_test(escape_double_quote),
                cmocka_unit_test(escape_newline),
                cmocka_unit_test(escape_tab),
                cmocka_unit_test(escape_carriage_return),
                cmocka_unit_test(escape_nonprinting),
                cmocka_unit_test(escape_utf8));
