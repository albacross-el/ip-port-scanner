# TCP Connect IP Port Scanner

Small interactive TCP connect port scanner written in Python. Attempts to connect to target ports, optionally grabs simple banners, and prints a console table of open ports. Includes an option to save results to a text report.

## Files
- `IP Port Scanner.py` — main interactive scanner script.

## Requirements
- Python 3.10+ (script uses modern type annotations / union operator)
- No external packages required (uses standard library: socket, concurrent.futures, etc.)

## Usage
1. From a terminal:
   - python "IP Port Scanner.py"
2. Follow the interactive menus:
   - Enter a hostname or IP address.
   - Choose port range (common ports / 1-1024 / custom range / specific ports).
   - Optionally set max threads (default 50).
   - View open ports and banners; optionally export the last scan to a text file.

## Important legal & safety note
Port scanning systems you do not own or have explicit permission to test can be considered intrusive or illegal in many jurisdictions. Only scan targets you own or where you have explicit authorization to test. Use this tool responsibly.

## Improvements you might want
- Add CLI flags (argparse) for non-interactive usage.
- Add concurrency tuning and rate-limiting to avoid flooding networks.
- Add optional UDP scanning (requires different approach).
- Add more robust banner parsing and fingerprinting.

## License
Add your preferred license (e.g., MIT). This repository currently contains no license by default — include one if you intend to publish.
