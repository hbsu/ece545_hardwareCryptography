# HW2 - Breaking AES through Differential Power Analysis (DPA)

ECE 545 Assignment 2: run an iVerilog simulation of an AES-128-ECB core,
extract a Hamming-distance power trace from the VCD dump, and recover the
128-bit secret key with a DPA attack (Pearson correlation on Sbox output).

The assignment is designed around Google Colab (see
`ECE_545_Assignment_02 (1).pdf`), but this directory is set up to run
**entirely locally** instead, since there's no need for a cloud runtime -
everything Colab does (iverilog install, simulation, VCD parsing, DPA) runs
fine as plain Python.

## One-time setup

```bash
./setup_env.sh
```

This:
- installs the Python packages the notebook needs (`scipy`, `pandas`,
  `gdown`, `vcdvcd`, `ipykernel`) via `pip --user`
- builds Icarus Verilog (`iverilog`/`vvp`) from source into `tools/iverilog/`
  (no sudo/apt required - useful since this machine has neither)
- downloads the course-provided RTL/testbench/plaintext files from Google
  Drive into `DPA_AES/`
- registers a Jupyter kernel called **ECE545 HW2 (DPA)** so
  `DPA_Assignment_local.ipynb` can be run from VS Code or `jupyter lab`

`numpy` and `matplotlib` are assumed already present system-wide/user-wide;
`setup_env.sh` doesn't touch them.

## Provenance: what's instructor-provided vs. edited

`DPA_AES/` is downloaded from the instructor's Google Drive folder (the same
one `DPA_Assignment (1).ipynb` cell 5 pulls from) - not something you
uploaded yourself. Two files in it were edited (see below):
`DPA_AES/sim/tb_aes128_table_ecb_5k.sv` and `_10k.sv`. The exact
as-downloaded originals are kept alongside as
`tb_aes128_table_ecb_5k_original.sv` and `_10k_original.sv` for reference/
diffing - `diff tb_aes128_table_ecb_5k_original.sv tb_aes128_table_ecb_5k.sv`
shows the only change is the one-line path fix described below. Nothing
else in `DPA_AES/` (the RTL, `extract_regs.sh`, the plaintext/ciphertext
files) was touched. `ECE_545_Assignment_02 (1).pdf` and
`DPA_Assignment (1).ipynb` - the two files you provided directly - were
never modified either; `DPA_Assignment_local.ipynb` is a separate copy.

## Important bug fix already applied

Both `DPA_AES/sim/tb_aes128_table_ecb_5k.sv` and `_10k.sv` hardcode the
plaintext/ciphertext file path as `/content/DPA_AES/sim/...` (a Colab-only
path). Outside Colab this makes `$readmemh` silently fail to find the file,
so every plaintext/ciphertext/register in the simulation becomes `x`
(unknown) and the resulting VCD/power-trace is garbage - the simulation
still runs and prints "Test Fail" for all 5000/10000 tests without erroring.

**This has been patched already** in the copies of the testbench under
`DPA_AES/` (the path is now `DPA_AES/sim/plaintext_ciphertext_orig_*.txt`,
relative to whatever directory you run `vvp` from). This matches how the
unmodified notebook already references `DPA_AES/rtl/...` and
`DPA_AES/sim/...` - i.e. it assumes you run with your working directory set
to `hw2/` itself (where the real `DPA_AES/` lives). `run5k/DPA_AES` and
`run10k/DPA_AES` are symlinks back to `../DPA_AES` so the *same* relative
path also resolves correctly if you run iverilog/vvp from inside those
subdirectories instead (see below). If `setup_env.sh` re-downloads a fresh
`DPA_AES/` folder, re-apply the fix with:

```bash
sed -i 's#/content/DPA_AES/sim/plaintext_ciphertext_orig_5000.txt#DPA_AES/sim/plaintext_ciphertext_orig_5000.txt#' DPA_AES/sim/tb_aes128_table_ecb_5k.sv DPA_AES/sim/tb_aes128_table_ecb_10k.sv
sed -i 's#/content/DPA_AES/sim/plaintext_ciphertext_orig_10000.txt#DPA_AES/sim/plaintext_ciphertext_orig_10000.txt#' DPA_AES/sim/tb_aes128_table_ecb_10k.sv
ln -sfn ../DPA_AES run5k/DPA_AES
ln -sfn ../DPA_AES run10k/DPA_AES
```

Before trusting any run, always check `output.txt` for `Test Pass` (not
`Test Fail`) on a sample of tests - that confirms plaintext/ciphertext data
actually loaded. Verified: the corrected 5k run in `run5k/` shows
`5000 Test Pass / 0 Test Fail`.

## Other issues fixed for this local setup

- **`compute()`'s Python version** (notebook section 3.3.1) calls
  `diff.bit_count()`, which needs Python >= 3.10. This machine has Python
  3.9, where `int` has no `.bit_count()`. `DPA_Assignment_local.ipynb` uses
  `bin(diff).count('1')` instead (identical result, works on 3.9+). If you
  add your own bit-counting code elsewhere in the notebook, use the same
  pattern rather than `.bit_count()`.
- `DPA_AES/scripts/extract_regs.sh` references an undefined
  `$output_vcd_file` on line 11 (`> $output_vcd_file`), printing
  `ambiguous redirect` to stderr every time it runs. This is a harmless bug
  in the provided script (leftover from a version with a 3rd argument) -
  the register extraction on the following lines still works correctly and
  register_file.txt is produced as expected. Safe to ignore.

## Running the simulation from the command line

The notebook does this too, but it's often more convenient to run the
(several-minute) simulation directly in a terminal rather than tying up a
notebook kernel:

```bash
cd run5k   # or run10k; DPA_AES here is a symlink to ../DPA_AES
export PATH="$PWD/../tools/iverilog/bin:$PATH"
iverilog -g2012 -o aes.out DPA_AES/rtl/aes128_table_ecb.sv DPA_AES/sim/tb_aes128_table_ecb_5k.sv
vvp aes.out > output.txt   # ~6 minutes for 5k traces, ~12 minutes for 10k
```

(Running flat in `hw2/` itself, exactly like the notebook does, also works
the same way since the real `DPA_AES/` is right there too - just drop the
`cd run5k` step and the paths resolve identically.)

Use `run10k/` and `tb_aes128_table_ecb_10k.sv` for the 10000-trace version.
`waveform.vcd` lands in the run directory (~190 MB for 5k, expect roughly
double for 10k) - that's the file the notebook's VCD-parsing section reads.

**Disk space:** this NFS home directory has a small quota. Check
`df -h ~` before running the 10k simulation if you've already generated the
5k trace and haven't cleaned it up - `run5k/` and `run10k/` are each on the
order of 150-400 MB (`waveform.vcd` + `output.txt`).

## Running the notebook

Open `DPA_Assignment_local.ipynb` (VS Code Jupyter extension or
`jupyter lab`), select the **ECE545 HW2 (DPA)** kernel, and run top to
bottom. It's identical to the original `DPA_Assignment (1).ipynb` except the
`!apt install iverilog` cell is replaced with one that just adds
`tools/iverilog/bin` to `PATH` for the kernel.

If you already ran the simulation from the command line as above, you can
skip the notebook's simulation cells (section 3.1) and just point
`VCD_File` (section 3.2) at `run5k/waveform.vcd` or `run10k/waveform.vcd`.

## Your work

The notebook's Task 1-3 subtasks (section 4.4) are intentionally left
blank/unimplemented - that's the assignment. This setup only gets you to the
point of having a working power trace CSV and plaintext/ciphertext pairs to
attack; the DPA attack itself (Pearson correlation across key hypotheses,
the four required figures, and the nine questions) is yours to write up in
the report per `ECE_545_Assignment_02 (1).pdf`.

## Directory layout

```
hw2/
  ECE_545_Assignment_02 (1).pdf   assignment instructions
  DPA_Assignment (1).ipynb        original notebook (as given, unmodified)
  DPA_Assignment_local.ipynb      local-run copy (only the iverilog-install cell differs)
  setup_env.sh                    one-shot environment setup (see above)
  README.md                       this file
  tools/iverilog/                 iverilog built from source (gitignored)
  DPA_AES/                        downloaded RTL/testbench/plaintext files (gitignored)
    sim/tb_*_5k.sv, tb_*_10k.sv      patched (path fix) - actually simulated
    sim/tb_*_5k_original.sv, etc.    as-downloaded originals, unmodified
  run5k/, run10k/                 simulation working directories (gitignored)
```
