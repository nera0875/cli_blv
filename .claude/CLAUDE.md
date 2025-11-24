# BLV CLI - Claude Instructions

## PRE-COMMIT VALIDATION (MANDATORY)

Before ANY code change, ALWAYS run with `uv`:

```bash
# 1. Syntax check ALL modified files
uv run python -m py_compile cli.py db.py llm.py

# 2. Test imports
uv run python -c "import db; db.init(); print('DB OK')"
uv run python -c "import cli; print('CLI OK')"

# 3. If DB changes: test init
uv run python -c "import db; db.init(); print('Init OK')"

# 4. Run CLI
uv run python cli.py
```

**NEVER skip validation.** If tests fail, fix before commit.
**ALWAYS use `uv run python` - NEVER plain `python` or `python3`.**

## Project Context

**Stack:**
- Python 3.12+ (WSL Ubuntu)
- UV package manager (MANDATORY)
- LiteLLM proxy (VPS: http://89.116.27.88:5000)
- SQLite (blv.db)
- Rich + prompt_toolkit (CLI)

**Architecture:**
- `cli.py` - REPL interface, commands
- `db.py` - SQLite ops (prompts, rules, requests, findings, conversations, chat)
- `llm.py` - LiteLLM streaming with prompt caching

**Key features:**
- System prompts in SQLite (no more MD files)
- Multi-conversations with /clear, /resume
- Burp XML import
- Prompt caching (90% cost reduction)
- Model switching (/model)

## Code Rules

1. **DB Operations:**
   - Use `cursor.lastrowid` (NOT `connection.lastrowid`)
   - Always commit after INSERT/UPDATE
   - Use context manager `with conn()`

2. **Global State:**
   - `CURRENT_CONVERSATION_ID` in db.py
   - Update via `set_current_conversation()`

3. **Error Handling:**
   - Try/except on user input
   - Clear error messages (Rich formatting)
   - Never crash on bad input

4. **Testing:**
   - Syntax: `uv run python -m py_compile file.py`
   - Import: `uv run python -c "import module"`
   - DB: Test init before validation
   - Run: `uv run python cli.py`

## Commands Reference

```
/chat   or /c  - Stream chat (reload hist each msg)
/prompt or /p  - Manage system prompts (add/edit/del/toggle)
/import or /i  - Import Burp XML (drag/drop)
/model         - Switch LLM model
/clear         - New conversation
/resume        - Switch conversation + preview
/stats  or /s  - Usage stats
/cost          - LiteLLM cost analytics
/help   or /h  - Show help
/back          - Exit chat to main
```

## Common Fixes

**AttributeError lastrowid:**
```python
# WRONG
c.execute("INSERT...")
return c.lastrowid

# RIGHT
cursor = c.execute("INSERT...")
return cursor.lastrowid
```

**History not updating after /resume:**
```python
# Reload hist inside loop
hist = [{"role": h["role"], "content": h["content"]} for h in db.get_history()]
```

**New convo each startup:**
```python
# db.py init()
CURRENT_CONVERSATION_ID = create_conversation()  # NOT get_or_create
```

## File Locations

```
/home/gesti/projects/cli_blv/  (WSL)
├── .env              # LiteLLM config
├── blv.db            # SQLite database (prompts, rules, findings, requests, chat)
├── cli.py            # Main CLI
├── db.py             # Database ops
├── llm.py            # LLM streaming
├── tools.py          # Tools definitions (not used yet)
└── pyproject.toml    # UV dependencies
```

## Validation Checklist

Before saying "done":
- [ ] `uv run python -m py_compile` all modified files
- [ ] Test imports with `uv run python -c "import module"`
- [ ] If DB changes: test `uv run python -c "import db; db.init()"`
- [ ] Explain changes < 100 words

## Database Schema

**Tables:**
- `prompts` - System prompts (name, content, active, priority)
- `rules` - Conditional rules (trigger, action, priority, active)
- `requests` - HTTP requests from Burp XML (url, method, headers, body, response)
- `findings` - BLV patterns tested (pattern, worked, target, context)
- `conversations` - Chat sessions (name, created_at)
- `chat` - Messages (conversation_id, role, content, tokens)
