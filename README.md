# BLV CLI

CLI copilot pour pentest BLV.

## Quick Start

```powershell
# Setup
copy .env.example .env
# Edit .env avec keys

# Install
uv pip install typer rich prompt-toolkit litellm

# Run
uv run python cli.py chat
```

## Commands

```bash
python cli.py chat           # Stream chat
python cli.py mindsets       # List/toggle
python cli.py add-mindset "Security Expert" "You are..."
python cli.py stats          # Display stats
python cli.py help           # Commands list
```

## Features

- Streaming LLM responses
- SQLite storage (requests + mindsets + history)
- Syntax highlighting (rich)
- Input history (prompt_toolkit)
- UTF-8 Windows compatible

Total: <150 lignes Python.
