# Malware Sample Downloader

This script downloads malware samples from MalwareBazaar and Hybrid Analysis, and can generate synthetic samples if needed. It's designed to download approximately 200 samples for each of these malware family/extension combinations:

- ELF: Miner (CoinMiner/BitCoin)
- ELF: Berbew
- EXE: Loader
- EXE: Dacic (Darkcloud)

## Features

- Downloads samples from MalwareBazaar
- Downloads samples from Hybrid Analysis (requires API key)
- Avoids downloading duplicates of files that already exist in eng_final_data directory
- Generates synthetic samples when not enough real samples are available
- Tracks progress to allow resuming interrupted downloads
- Organizes samples into appropriate directories
- Handles ZIP extraction for MalwareBazaar samples
- Implements error handling with 60-second retries for API errors

## Requirements

The script requires the following Python packages:
- requests
- zipfile
- hashlib
- argparse
- json
- random

These are already included in the requirements.txt file.

## Usage

### Basic Usage

To download approximately 200 samples for each malware family:

```bash
python download_malware_samples.py
```

### Command-line Options

- `--samples N`: Download N samples per family (default: 200)
- `--resume`: Resume download from previous progress
- `--mb-api-key KEY`: Use a custom MalwareBazaar API key
- `--ha-api-key KEY`: Use a custom Hybrid Analysis API key
- `--family NAME`: Download samples for a specific family only
- `--no-hybrid`: Disable Hybrid Analysis API
- `--no-synthetic`: Disable synthetic sample generation

### Examples

Download 100 samples per family:
```bash
python download_malware_samples.py --samples 100
```

Download only ELF Miner samples:
```bash
python download_malware_samples.py --family elf_miner
```

Resume a previously interrupted download:
```bash
python download_malware_samples.py --resume
```

Use a custom Hybrid Analysis API key:
```bash
python download_malware_samples.py --ha-api-key YOUR_API_KEY
```

Download without generating synthetic samples:
```bash
python download_malware_samples.py --no-synthetic
```

## API Keys

- The script includes a default MalwareBazaar API key
- For Hybrid Analysis, the script includes both an API key and secret
- You can provide your own Hybrid Analysis API key using the `--ha-api-key` option or by editing the script

## Output Structure

The script creates the following directory structure:

```
finalengagement/
└── training_data/
    └── malicious/
        ├── elf_miner/
        │   ├── [hash1].elf
        │   ├── [hash2].elf
        │   └── synthetic/
        │       ├── [synth_hash1].elf
        │       └── [synth_hash2].elf
        ├── elf_berbew/
        ├── exe_loader/
        └── exe_dacic/
```

## Progress Tracking

The script creates JSON files to track progress:
- `elf_miner_progress.json`
- `elf_berbew_progress.json`
- `exe_loader_progress.json`
- `exe_dacic_progress.json`

These files allow resuming downloads if the script is interrupted.
