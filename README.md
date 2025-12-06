# ECE 418 Course Project
**Network Security & Cryptography, UW Fall 2025**

**Collaborators:** Oorjit Chowdhary, Aakash Namboodiri

## Project Overview

Implementation and cryptographic analysis of two RFID mutual authentication protocols: MMAP (M²AP) and EMAP. This project demonstrates passive eavesdropping attacks that recover secret tag identifiers by observing protocol message exchanges.

## Files

- `mmap.py` - MMAP protocol oracle and attack implementation
- `emap.py` - EMAP protocol oracle and attack implementation  
- `main.py` - Experimental framework and empirical scaling analysis

## Usage

```bash
python3 main.py
```

Runs both attacks and generates comparative scaling plots showing protocol runs required vs key length.

## Goal

Analyze vulnerability to passive attacks where adversaries recover the secret ID by observing authenticated sessions between RFID tags and readers. Demonstrates that both protocols are cryptographically broken despite their algebraic complexity.
