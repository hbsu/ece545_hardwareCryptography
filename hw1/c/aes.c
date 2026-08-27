/* ============================================================================
 * ECE 592/CSC 591 - Assignment 1: Implementing AES-128
 *
 * SCAFFOLD ONLY. Given data (plaintext, master key, round keys, S-boxes) and
 * plumbing (hex<->bytes, printing, the main() driver that calls things in
 * the order the assignment asks) are filled in. Everywhere you see
 * "TODO(Qn)" is where you write the actual algorithm for question n.
 *
 * Mapping of questions -> functions:
 *   Q1  add_round_key()                    -> round[1].start
 *   Q2  sub_bytes()                        -> round[1].s_box
 *   Q3  bytes_to_state()                   -> the 4x4 matrix
 *   Q4  shift_rows() + state_to_bytes()    -> round[1].s_row
 *   Q5  gmul() + mix_columns()             -> round[1].m_col
 *   Q6  add_round_key() (reused)           -> round[2].start
 *   Q7  loop calling Q2-Q6 eight more times -> round[10].start
 *   Q8  final round (no MixColumns)        -> ciphertext
 *   Q9  not code - report hours in your writeup
 *   BONUS decryption: inv_sub_bytes(), inv_shift_rows(), inv_mix_columns()
 *
 * Build:  gcc -std=c11 -Wall -o aes aes.c
 * Run:    ./aes
 * ==========================================================================*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Types
 * ---------------------------------------------------------------------- */

/* The AES "State": 4 rows x 4 columns of bytes, state[r][c] = s_{r,c}
 * (see FIPS-197 Sec. 3.4). Row 0 is untouched by ShiftRows; columns are
 * what MixColumns operates on. */
typedef uint8_t State[4][4];

/* -------------------------------------------------------------------------
 * Given data (from the assignment PDF - do not need to compute these)
 * ---------------------------------------------------------------------- */

static const char *PLAINTEXT_HEX  = "00112233445566778899aabbccddeeff";
static const char *MASTER_KEY_HEX = "000102030405060708090a0b0c0d0e0f";

/* round_keys_hex[0] is the master key (used for the initial AddRoundKey in
 * Q1); round_keys_hex[1..10] are the pre-derived round keys given in the
 * assignment (no key expansion needed). */
static const char *round_keys_hex[11] = {
    "000102030405060708090a0b0c0d0e0f", /* round[ 0] */
    "d6aa74fdd2af72fadaa678f1d6ab76fe", /* round[ 1] */
    "b692cf0b643dbdf1be9bc5006830b3fe", /* round[ 2] */
    "b6ff744ed2c2c9bf6c590cbf0469bf41", /* round[ 3] */
    "47f7f7bc95353e03f96c32bcfd058dfd", /* round[ 4] */
    "3caaa3e8a99f9deb50f3af57adf622aa", /* round[ 5] */
    "5e390f7df7a69296a7553dc10aa31f6b", /* round[ 6] */
    "14f9701ae35fe28c440adf4d4ea9c026", /* round[ 7] */
    "47438735a41c65b9e016baf4aebf7ad2", /* round[ 8] */
    "549932d1f08557681093ed9cbe2c974e", /* round[ 9] */
    "13111d7fe3944a17f307a78b4d2b30c5", /* round[10] */
};

/* S-box (FIPS-197 Fig. 7), row = high nibble, col = low nibble.
 * Provided as given constant data, same as the round keys - it is not
 * something you derive, just something SubBytes() looks values up in. */
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Inverse S-box (FIPS-197 Fig. 14) - only needed for the bonus decryption. */
static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

/* -------------------------------------------------------------------------
 * Utilities (implemented for you - not the point of the assignment)
 * ---------------------------------------------------------------------- */

/* Parse a 32-character hex string into 16 raw bytes. */
static void hex_to_bytes(const char *hex, uint8_t out[16]) {
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (uint8_t)byte;
    }
}

/* Format 16 raw bytes as a 32-character lowercase hex string (33 with NUL). */
static void bytes_to_hex(const uint8_t in[16], char out[33]) {
    for (int i = 0; i < 16; i++) {
        sprintf(out + 2 * i, "%02x", in[i]);
    }
}

/* Pretty-print a 16-byte array labeled like the assignment, e.g.
 *   round[ 1].start = 00102030405060708090a0b0c0d0e0f0
 */
static void print_bytes(const char *label, const uint8_t in[16]) {
    char hex[33];
    bytes_to_hex(in, hex);
    printf("%-18s %s\n", label, hex);
}

/* Pretty-print the 4x4 state matrix (for Q3). */
static void print_state(const char *label, const State state) {
    printf("%s\n", label);
    for (int r = 0; r < 4; r++) {
        printf("  ");
        for (int c = 0; c < 4; c++) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
}

/* -------------------------------------------------------------------------
 * TODO(Q3): state <-> byte array conversion
 *
 * FIPS-197 Sec. 3.4, Eq. (3.3)/(3.4):
 *   state[r][c] = in[r + 4*c]      for 0 <= r < 4, 0 <= c < 4
 *   out[r + 4*c] = state[r][c]
 * ---------------------------------------------------------------------- */

static void bytes_to_state(const uint8_t in[16], State state) {
    /* TODO(Q3): fill in `state` from the flat 16-byte array `in`. */
    (void)in; (void)state;
}

static void state_to_bytes(const State state, uint8_t out[16]) {
    /* TODO(Q4): flatten `state` back into the 16-byte array `out`. */
    (void)state; (void)out;
}

/* -------------------------------------------------------------------------
 * TODO: the four AES round transformations (FIPS-197 Sec. 5.1)
 * Each is written ONCE here and reused across every round.
 * ---------------------------------------------------------------------- */

/* Q2: SubBytes - replace every byte with SBOX[byte], independent of
 * position, so this can operate directly on the flat 16-byte array. */
static void sub_bytes(uint8_t state[16]) {
    /* TODO(Q2): state[i] = SBOX[state[i]] for i in 0..15 */
    (void)state;
}

/* Q4: ShiftRows - row r is cyclically left-shifted by r positions.
 * (Sec. 5.1.2, Eq. 5.3/5.4.) Operates on the 4x4 State. */
static void shift_rows(State state) {
    /* TODO(Q4): shift row 1 by 1, row 2 by 2, row 3 by 3; row 0 unchanged. */
    (void)state;
}

/* Helper for MixColumns: multiplication by 'x' (i.e. {02}) in GF(2^8),
 * reduced modulo m(x) = x^8+x^4+x^3+x+1 (Sec. 4.2.1). */
static uint8_t xtime(uint8_t a) {
    /* TODO(Q5): implement xtime as described in Sec. 4.2.1.
     * Hint: (a << 1) ^ (0x1b if the high bit of a was set else 0) */
    (void)a;
    return 0;
}

/* Helper for MixColumns: general GF(2^8) multiplication a*b, built from
 * repeated xtime() and XOR of intermediate results (Sec. 4.2). */
static uint8_t gmul(uint8_t a, uint8_t b) {
    /* TODO(Q5): implement finite-field multiply using xtime(). */
    (void)a; (void)b;
    return 0;
}

/* Q5: MixColumns - each column is left-multiplied by the fixed matrix in
 * Sec. 5.1.3, Eq. (5.6). Operates on the 4x4 State, column by column. */
static void mix_columns(State state) {
    /* TODO(Q5): for each column c, compute the new s'_{0..3,c} using gmul()
     * per Eq. (5.6):
     *   s'0 = (02*s0) ^ (03*s1) ^ s2 ^ s3
     *   s'1 = s0 ^ (02*s1) ^ (03*s2) ^ s3
     *   s'2 = s0 ^ s1 ^ (02*s2) ^ (03*s3)
     *   s'3 = (03*s0) ^ s1 ^ s2 ^ (02*s3)
     */
    (void)state;
}

/* Q1 / Q6: AddRoundKey - XOR the state with the round key, byte for byte.
 * Position-independent, so it operates on the flat 16-byte arrays. */
static void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    /* TODO(Q1): state[i] ^= round_key[i] for i in 0..15 */
    (void)state; (void)round_key;
}

/* -------------------------------------------------------------------------
 * BONUS: inverse transformations for decryption (FIPS-197 Sec. 5.3).
 * AddRoundKey is its own inverse - reuse add_round_key() above.
 * ---------------------------------------------------------------------- */

static void inv_sub_bytes(uint8_t state[16]) {
    /* TODO(bonus): state[i] = INV_SBOX[state[i]] for i in 0..15 */
    (void)state;
}

static void inv_shift_rows(State state) {
    /* TODO(bonus): cyclic RIGHT shift of rows 1..3 by 1..3 (Sec. 5.3.1). */
    (void)state;
}

static void inv_mix_columns(State state) {
    /* TODO(bonus): apply a^-1(x) = {0b}x^3+{0d}x^2+{09}x+{0e} (Sec. 5.3.3,
     * Eq. 5.10), using the same gmul() helper. */
    (void)state;
}

/* -------------------------------------------------------------------------
 * Question-by-question drivers. These just call the primitives above in
 * the sequence the assignment asks for and print the labeled results -
 * no crypto logic lives down here.
 * ---------------------------------------------------------------------- */

/* Q1: initial AddRoundKey. Returns round[1].start. */
static void question1(uint8_t out_round1_start[16]) {
    uint8_t plaintext[16], master_key[16];
    hex_to_bytes(PLAINTEXT_HEX, plaintext);
    hex_to_bytes(MASTER_KEY_HEX, master_key);

    memcpy(out_round1_start, plaintext, 16);
    add_round_key(out_round1_start, master_key);
    print_bytes("round[ 1].start", out_round1_start);
}

/* Q2: SubBytes on round[1].start. Returns round[1].s_box. */
static void question2(const uint8_t round1_start[16], uint8_t out_sbox[16]) {
    memcpy(out_sbox, round1_start, 16);
    sub_bytes(out_sbox);
    print_bytes("round[ 1].s_box", out_sbox);
}

/* Q3: arrange round[1].s_box as the 4x4 state matrix and print it. */
static void question3(const uint8_t sbox_bytes[16], State out_state) {
    bytes_to_state(sbox_bytes, out_state);
    print_state("round[ 1] state matrix (Q3):", out_state);
}

/* Q4: ShiftRows on the state from Q3. Returns round[1].s_row. */
static void question4(const State state_in, uint8_t out_srow[16]) {
    State state;
    memcpy(state, state_in, sizeof(State));
    shift_rows(state);
    state_to_bytes(state, out_srow);
    print_bytes("round[ 1].s_row", out_srow);
}

/* Q5: MixColumns on round[1].s_row. Returns round[1].m_col. */
static void question5(const uint8_t srow_bytes[16], uint8_t out_mcol[16]) {
    State state;
    bytes_to_state(srow_bytes, state);
    mix_columns(state);
    state_to_bytes(state, out_mcol);
    print_bytes("round[ 1].m_col", out_mcol);
}

/* Q6: AddRoundKey with round key 1 on round[1].m_col. Returns round[2].start. */
static void question6(const uint8_t mcol_bytes[16], uint8_t out_round2_start[16]) {
    uint8_t round_key1[16];
    hex_to_bytes(round_keys_hex[1], round_key1);

    memcpy(out_round2_start, mcol_bytes, 16);
    add_round_key(out_round2_start, round_key1);
    print_bytes("round[ 2].start", out_round2_start);
}

/* One full "normal" round (SubBytes -> ShiftRows -> MixColumns ->
 * AddRoundKey) using round_keys_hex[round_index]. Used by Q7 to repeat the
 * Q2-Q6 sequence for rounds 2..9. */
static void aes_round(uint8_t state[16], int round_index) {
    State s;
    uint8_t round_key[16];

    sub_bytes(state);

    bytes_to_state(state, s);
    shift_rows(s);
    mix_columns(s);
    state_to_bytes(s, state);

    hex_to_bytes(round_keys_hex[round_index], round_key);
    add_round_key(state, round_key);
}

/* Q7: rounds 2..9 (8 rounds), starting from round[2].start. Returns
 * round[10].start. */
static void question7(const uint8_t round2_start[16], uint8_t out_round10_start[16]) {
    uint8_t state[16];
    memcpy(state, round2_start, 16);

    /* round[2].start -> apply round key 2 gets you round[3].start, etc.
     * We already have round[2].start; running rounds with keys 2..9
     * produces round[3].start .. round[10].start. */
    for (int round_index = 2; round_index <= 9; round_index++) {
        aes_round(state, round_index);
    }

    memcpy(out_round10_start, state, 16);
    print_bytes("round[10].start", out_round10_start);
}

/* Q8: final round - SubBytes, ShiftRows, AddRoundKey(round key 10).
 * NOTE: no MixColumns in the final round. Returns the ciphertext. */
static void question8(const uint8_t round10_start[16], uint8_t out_ciphertext[16]) {
    State s;
    uint8_t round_key10[16];
    uint8_t state[16];

    memcpy(state, round10_start, 16);

    sub_bytes(state);

    bytes_to_state(state, s);
    shift_rows(s);
    state_to_bytes(s, state);

    hex_to_bytes(round_keys_hex[10], round_key10);
    add_round_key(state, round_key10);

    memcpy(out_ciphertext, state, 16);
    print_bytes("output (ciphertext)", out_ciphertext);
}

/* BONUS: full inverse cipher (straightforward Inverse Cipher, FIPS-197
 * Fig. 12), reusing add_round_key() (self-inverse) plus the inv_* TODOs
 * above. Should reproduce the original plaintext when fed the ciphertext
 * from Q8. */
static void bonus_decrypt(const uint8_t ciphertext[16], uint8_t out_plaintext[16]) {
    uint8_t state[16];
    uint8_t round_key[16];
    State s;

    memcpy(state, ciphertext, 16);

    hex_to_bytes(round_keys_hex[10], round_key);
    add_round_key(state, round_key);

    for (int round_index = 9; round_index >= 1; round_index--) {
        bytes_to_state(state, s);
        inv_shift_rows(s);
        state_to_bytes(s, state);

        inv_sub_bytes(state);

        hex_to_bytes(round_keys_hex[round_index], round_key);
        add_round_key(state, round_key);

        bytes_to_state(state, s);
        inv_mix_columns(s);
        state_to_bytes(s, state);
    }

    bytes_to_state(state, s);
    inv_shift_rows(s);
    state_to_bytes(s, state);

    inv_sub_bytes(state);

    hex_to_bytes(round_keys_hex[0], round_key);
    add_round_key(state, round_key);

    memcpy(out_plaintext, state, 16);
    print_bytes("bonus ioutput (plaintext)", out_plaintext);
}

/* -------------------------------------------------------------------------
 * main: runs Q1 through Q8 in order, then the bonus decryption.
 * ---------------------------------------------------------------------- */

int main(void) {
    uint8_t round1_start[16], sbox_bytes[16], srow_bytes[16], mcol_bytes[16];
    uint8_t round2_start[16], round10_start[16], ciphertext[16], plaintext_back[16];
    State state_q3;

    printf("== Question 1: initial AddRoundKey ==\n");
    question1(round1_start);

    printf("\n== Question 2: SubBytes ==\n");
    question2(round1_start, sbox_bytes);

    printf("\n== Question 3: state matrix ==\n");
    question3(sbox_bytes, state_q3);

    printf("\n== Question 4: ShiftRows ==\n");
    question4(state_q3, srow_bytes);

    printf("\n== Question 5: MixColumns ==\n");
    question5(srow_bytes, mcol_bytes);

    printf("\n== Question 6: AddRoundKey (round 1) ==\n");
    question6(mcol_bytes, round2_start);

    printf("\n== Question 7: rounds 2-9 ==\n");
    question7(round2_start, round10_start);

    printf("\n== Question 8: final round ==\n");
    question8(round10_start, ciphertext);

    printf("\n== Bonus: decrypt back to plaintext ==\n");
    bonus_decrypt(ciphertext, plaintext_back);

    return 0;
}
