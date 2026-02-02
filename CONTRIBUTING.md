# Contributing to Phonchain Node

Thank you for your interest in contributing to Phonchain.

## Scope
This repository contains a **reference implementation** of a Phonchain node.
Consensus rules are defined in the canonical repository and MUST NOT be changed here.

## What you can contribute
- Code improvements
- Bug fixes
- Performance optimizations
- Documentation
- Tests

## What you must NOT do
- Change consensus rules
- Change genesis parameters
- Add backdoors or privileged logic
- Add telemetry or tracking

## Development setup
```bash
git clone https://github.com/Phoncoin/phonchain-node.git
cd phonchain-node
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
