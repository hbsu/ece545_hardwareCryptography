# HW1 - AES-128 (ECE 592/CSC 591)

Implements one round-trip of AES-128 encryption (and a bonus decryption)
on a fixed plaintext/key, printing the intermediate state after each
step (AddRoundKey, SubBytes, ShiftRows, MixColumns) through 10 rounds.

Two equivalent implementations, same algorithm:

- `python/aes.py` - run with `python3 aes.py`
- `c/aes.c` - build with `gcc -std=c11 -Wall -o aes aes.c`, run with `./aes`

`report.tex`/`report.pdf` contain the write-up with the output for each
question.
