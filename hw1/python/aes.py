from __future__ import annotations
from typing import List

# A "State" is a list of 4 rows, each a list of 4 ints (0-255):
# state[r][c] = s_{r,c}  (see FIPS-197 Sec. 3.4).
State = List[List[int]]

# ---------------------------------------------------------------------------
# Given data (from the assignment PDF - do not need to compute these)
# ---------------------------------------------------------------------------

PLAINTEXT_HEX = "00112233445566778899aabbccddeeff"
MASTER_KEY_HEX = "000102030405060708090a0b0c0d0e0f"

# round_keys_hex[0] is the master key (used for the initial AddRoundKey in
# Q1); round_keys_hex[1..10] are the pre-derived round keys given in the
# assignment (no key expansion needed).
round_keys_hex = [
    "000102030405060708090a0b0c0d0e0f",  # round[ 0]
    "d6aa74fdd2af72fadaa678f1d6ab76fe",  # round[ 1]
    "b692cf0b643dbdf1be9bc5006830b3fe",  # round[ 2]
    "b6ff744ed2c2c9bf6c590cbf0469bf41",  # round[ 3]
    "47f7f7bc95353e03f96c32bcfd058dfd",  # round[ 4]
    "3caaa3e8a99f9deb50f3af57adf622aa",  # round[ 5]
    "5e390f7df7a69296a7553dc10aa31f6b",  # round[ 6]
    "14f9701ae35fe28c440adf4d4ea9c026",  # round[ 7]
    "47438735a41c65b9e016baf4aebf7ad2",  # round[ 8]
    "549932d1f08557681093ed9cbe2c974e",  # round[ 9]
    "13111d7fe3944a17f307a78b4d2b30c5",  # round[10]
]

# S-box (FIPS-197 Fig. 7), row = high nibble, col = low nibble.
# Provided as given constant data, same as the round keys - it is not
# something you derive, just something sub_bytes() looks values up in.
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse S-box (FIPS-197 Fig. 14) - only needed for the bonus decryption.
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

def hex_to_bytes(hex_str: str) -> List[int]:
    """Parse a 32-character hex string into a list of 16 ints (0-255)."""
    return list(bytes.fromhex(hex_str))


def bytes_to_hex(data: List[int]) -> str:
    """Format a list of 16 ints (0-255) as a 32-character lowercase hex string."""
    return bytes(data).hex()


def print_bytes(label: str, data: List[int]) -> None:
    """Pretty-print a 16-byte list labeled like the assignment, e.g.
    round[ 1].start = 00102030405060708090a0b0c0d0e0f0
    """
    print(f"{label:<18} {bytes_to_hex(data)}")


def print_state(label: str, state: State) -> None:
    """Pretty-print the 4x4 state matrix (for Q3)."""
    print(label)
    for row in state:
        print("  " + " ".join(f"{b:02x}" for b in row))

def bytes_to_state(data: List[int]) -> State:
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = data[r + 4 *c]
    return state


def state_to_bytes(state: State) -> List[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r][c]
    return out

def sub_bytes(data: List[int]) -> List[int]:
    return [SBOX[b] for b in data]

def shift_rows(state: State) -> State:
    out = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            out[r][c] = state[r][(c + r) % 4]
    return out


def xtime(a: int) -> int:
    high_bit_set = a & 0x80  
    shifted = (a << 1) & 0xFF
    if high_bit_set:
        shifted = shifted ^ 0x1B
    return shifted

def gmul(a: int, b: int) -> int:
    result = 0
    current = a
    if (b & 1):
        result ^= current
    else:
        result ^= 0
    for x in range(8):
        b >>= 1
        current = xtime(current)
        if(b & 1):
            result ^= current
        else: result ^= 0
    return result

def mix_columns(state: State) -> State:
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        out[0][c] = gmul(state[0][c], 2) ^ gmul(state[1][c], 3) ^ state[2][c] ^ state[3][c]
        out[1][c] = state[0][c] ^ gmul(state[1][c], 2) ^ gmul(state[2][c], 3) ^ state[3][c]
        out[2][c] = state[0][c] ^ state[1][c] ^ gmul(state[2][c], 2) ^ gmul(state[3][c], 3)
        out[3][c] = gmul(state[0][c], 3) ^ state[1][c] ^ state[2][c] ^ gmul(state[3][c], 2)
    return out


def add_round_key(data: List[int], round_key: List[int]) -> List[int]:
    return [data[i] ^ round_key[i] for i in range(16)]

def inv_sub_bytes(data: List[int]) -> List[int]:
    return [INV_SBOX[b] for b in data]

def inv_shift_rows(state: State) -> State:
    out = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            out[r][c] = state[r][(c - r) % 4]
    return out


def inv_mix_columns(state: State) -> State:
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        out[0][c] = gmul(state[0][c], 0x0e) ^ gmul(state[1][c], 0x0b) ^ gmul(state[2][c], 0x0d) ^ gmul(state[3][c], 0x09)
        out[1][c] = gmul(state[0][c], 0x09) ^ gmul(state[1][c], 0x0e) ^ gmul(state[2][c], 0x0b) ^ gmul(state[3][c], 0x0d)
        out[2][c] = gmul(state[0][c], 0x0d) ^ gmul(state[1][c], 0x09) ^ gmul(state[2][c], 0x0e) ^ gmul(state[3][c], 0x0b)
        out[3][c] = gmul(state[0][c], 0x0b) ^ gmul(state[1][c], 0x0d) ^ gmul(state[2][c], 0x09) ^ gmul(state[3][c], 0x0e)
    return out

def question1() -> List[int]:
    plaintext = hex_to_bytes(PLAINTEXT_HEX)
    master_key = hex_to_bytes(MASTER_KEY_HEX)

    round1_start = add_round_key(plaintext, master_key)
    print_bytes("round[ 1].start", round1_start)
    return round1_start


def question2(round1_start: List[int]) -> List[int]:
    sbox_bytes = sub_bytes(round1_start)
    print_bytes("round[ 1].s_box", sbox_bytes)
    return sbox_bytes


def question3(sbox_bytes: List[int]) -> State:
    state = bytes_to_state(sbox_bytes)
    print_state("round[ 1] state matrix (Q3):", state)
    return state


def question4(state: State) -> List[int]:
    shifted = shift_rows(state)
    srow_bytes = state_to_bytes(shifted)
    print_bytes("round[ 1].s_row", srow_bytes)
    return srow_bytes


def question5(srow_bytes: List[int]) -> List[int]:
    state = bytes_to_state(srow_bytes)
    mixed = mix_columns(state)
    mcol_bytes = state_to_bytes(mixed)
    print_bytes("round[ 1].m_col", mcol_bytes)
    return mcol_bytes


def question6(mcol_bytes: List[int]) -> List[int]:
    round_key1 = hex_to_bytes(round_keys_hex[1])
    round2_start = add_round_key(mcol_bytes, round_key1)
    print_bytes("round[ 2].start", round2_start)
    return round2_start


def aes_round(data: List[int], round_index: int) -> List[int]:
    data = sub_bytes(data)

    state = bytes_to_state(data)
    state = shift_rows(state)
    state = mix_columns(state)
    data = state_to_bytes(state)

    round_key = hex_to_bytes(round_keys_hex[round_index])
    data = add_round_key(data, round_key)
    return data


def question7(round2_start: List[int]) -> List[int]:
    data = round2_start
    for round_index in range(2, 10):
        data = aes_round(data, round_index)

    print_bytes("round[10].start", data)
    return data


def question8(round10_start: List[int]) -> List[int]:
    data = sub_bytes(round10_start)

    state = bytes_to_state(data)
    state = shift_rows(state)
    data = state_to_bytes(state)

    round_key10 = hex_to_bytes(round_keys_hex[10])
    ciphertext = add_round_key(data, round_key10)

    print_bytes("output (ciphertext)", ciphertext)
    return ciphertext


def bonus_decrypt(ciphertext: List[int]) -> List[int]:
    data = add_round_key(ciphertext, hex_to_bytes(round_keys_hex[10]))

    for round_index in range(9, 0, -1):
        state = bytes_to_state(data)
        state = inv_shift_rows(state)
        data = state_to_bytes(state)

        data = inv_sub_bytes(data)
        data = add_round_key(data, hex_to_bytes(round_keys_hex[round_index]))

        state = bytes_to_state(data)
        state = inv_mix_columns(state)
        data = state_to_bytes(state)

    state = bytes_to_state(data)
    state = inv_shift_rows(state)
    data = state_to_bytes(state)

    data = inv_sub_bytes(data)
    plaintext = add_round_key(data, hex_to_bytes(round_keys_hex[0]))

    print_bytes("bonus ioutput (plaintext)", plaintext)
    return plaintext

def main() -> None:
    print("== Question 1: initial AddRoundKey ==")
    round1_start = question1()

    print("\n== Question 2: SubBytes ==")
    sbox_bytes = question2(round1_start)

    print("\n== Question 3: state matrix ==")
    state_q3 = question3(sbox_bytes)

    print("\n== Question 4: ShiftRows ==")
    srow_bytes = question4(state_q3)

    print("\n== Question 5: MixColumns ==")
    mcol_bytes = question5(srow_bytes)

    print("\n== Question 6: AddRoundKey (round 1) ==")
    round2_start = question6(mcol_bytes)

    print("\n== Question 7: rounds 2-9 ==")
    round10_start = question7(round2_start)

    print("\n== Question 8: final round ==")
    ciphertext = question8(round10_start)

    print("\n== Bonus: decrypt back to plaintext ==")
    bonus_decrypt(ciphertext)


if __name__ == "__main__":
    main()
