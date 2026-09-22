"""Tests for the pure alignment helpers in reportal.diffing."""

from __future__ import annotations

from reportal import diffing


class TestAlign:
    def test_identical_text_is_all_equal(self) -> None:
        entries = diffing.align("a\nb", "a\nb")
        assert [entry["op"] for entry in entries] == ["equal", "equal"]
        assert entries[0] == {
            "op": "equal",
            "left_line": 1,
            "right_line": 1,
            "left": "a",
            "right": "a",
        }
        assert entries[1]["left_line"] == 2
        assert entries[1]["right_line"] == 2

    def test_inserted_line_has_no_left_side(self) -> None:
        entries = diffing.align("a\nc", "a\nb\nc")
        assert [entry["op"] for entry in entries] == ["equal", "insert", "equal"]
        inserted = entries[1]
        assert inserted["left_line"] is None
        assert inserted["left"] is None
        assert inserted["right_line"] == 2
        assert inserted["right"] == "b"
        assert entries[2]["left_line"] == 2
        assert entries[2]["right_line"] == 3

    def test_deleted_line_has_no_right_side(self) -> None:
        entries = diffing.align("a\nb\nc", "a\nc")
        assert [entry["op"] for entry in entries] == ["equal", "delete", "equal"]
        deleted = entries[1]
        assert deleted["right_line"] is None
        assert deleted["right"] is None
        assert deleted["left_line"] == 2
        assert deleted["left"] == "b"
        assert entries[2]["left_line"] == 3
        assert entries[2]["right_line"] == 2

    def test_replaced_line_is_delete_then_insert(self) -> None:
        entries = diffing.align("a\nb\nc", "a\nx\nc")
        assert [entry["op"] for entry in entries] == ["equal", "delete", "insert", "equal"]
        assert entries[1]["left_line"] == 2
        assert entries[1]["right_line"] is None
        assert entries[2]["left_line"] is None
        assert entries[2]["right_line"] == 2

    def test_replacement_run_numbers_each_side_separately(self) -> None:
        entries = diffing.align("a\nb\nc\nd", "a\nx\ny\nz\nd")
        assert [entry["op"] for entry in entries] == [
            "equal",
            "delete",
            "delete",
            "insert",
            "insert",
            "insert",
            "equal",
        ]
        deletes = [entry for entry in entries if entry["op"] == "delete"]
        inserts = [entry for entry in entries if entry["op"] == "insert"]
        assert [entry["left_line"] for entry in deletes] == [2, 3]
        assert [entry["right_line"] for entry in inserts] == [2, 3, 4]

    def test_empty_left_is_every_line_inserted(self) -> None:
        entries = diffing.align("", "a\nb")
        assert [entry["op"] for entry in entries] == ["insert", "insert"]
        assert all(entry["left_line"] is None for entry in entries)
        assert [entry["right_line"] for entry in entries] == [1, 2]

    def test_empty_right_is_every_line_deleted(self) -> None:
        entries = diffing.align("a\nb", "")
        assert [entry["op"] for entry in entries] == ["delete", "delete"]
        assert all(entry["right_line"] is None for entry in entries)
        assert [entry["left_line"] for entry in entries] == [1, 2]

    def test_both_empty_has_no_entries(self) -> None:
        assert diffing.align("", "") == []


class TestSummary:
    def test_replacement_counts_as_one_changed_group(self) -> None:
        entries = diffing.align("a\nb\nc", "a\nx\nc")
        assert diffing.summary(entries) == {
            "equal": 2,
            "insert": 1,
            "delete": 1,
            "changed": 1,
        }

    def test_identical_text_has_no_changes(self) -> None:
        summary = diffing.summary(diffing.align("a\nb", "a\nb"))
        assert summary == {"equal": 2, "insert": 0, "delete": 0, "changed": 0}

    def test_pure_insert_has_no_changed_group(self) -> None:
        summary = diffing.summary(diffing.align("a", "a\nb\nc"))
        assert summary["insert"] == 2
        assert summary["changed"] == 0

    def test_pure_delete_has_no_changed_group(self) -> None:
        summary = diffing.summary(diffing.align("a\nb\nc", "a"))
        assert summary["delete"] == 2
        assert summary["changed"] == 0

    def test_two_replacement_groups_count_two(self) -> None:
        summary = diffing.summary(diffing.align("a\nb\nc\nd", "a\nx\nc\ny"))
        assert summary == {"equal": 2, "insert": 2, "delete": 2, "changed": 2}


class TestStripAddresses:
    def test_hex_listing_drops_address_and_bytes(self) -> None:
        listing = "  0x00401000:  55 8b ec             push ebp"
        assert diffing.strip_addresses(listing) == "push ebp"

    def test_nasm_listing_drops_the_address_and_byte_comment(self) -> None:
        listing = "    push ebp                                 ; 00100000  55"
        assert diffing.strip_addresses(listing) == "push ebp"

    def test_operands_are_kept(self) -> None:
        listing = "    mov eax, dword ptr [ebp-4]               ; 00100003  8b45fc"
        assert diffing.strip_addresses(listing) == "mov eax, dword ptr [ebp-4]"

    def test_c_comment_is_dropped(self) -> None:
        assert diffing.strip_addresses("  x = 1; // set x") == "x = 1;"

    def test_bare_eight_digit_address_column(self) -> None:
        assert diffing.strip_addresses("00401000  55 8b ec  push ebp") == "push ebp"

    def test_plain_lines_are_untouched(self) -> None:
        listing = "bits 32\norg 0x00100000\n\nfunc_1000:"
        assert diffing.strip_addresses(listing) == listing

    def test_mnemonic_of_hex_digits_is_not_an_address(self) -> None:
        assert diffing.strip_addresses("    fadd st0, st1") == "fadd st0, st1"

    def test_whitespace_is_collapsed(self) -> None:
        assert diffing.strip_addresses("    push      ebp") == "push ebp"

    def test_blank_lines_survive(self) -> None:
        assert diffing.strip_addresses("bits 32\n\nret") == "bits 32\n\nret"


class TestSummaryReplace:
    def test_replace_op_counts_one_changed(self) -> None:
        entries = [
            {"op": diffing.OP_EQUAL, "left_no": 1, "right_no": 1, "left": "a", "right": "a"},
            {"op": diffing.OP_REPLACE, "left_no": 2, "right_no": 2, "left": "b", "right": "x"},
        ]
        assert diffing.summary(entries) == {
            "equal": 1,
            "insert": 0,
            "delete": 0,
            "changed": 1,
        }
