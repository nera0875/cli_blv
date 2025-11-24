"""SQLite ops for BLV CLI."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime

DB = "blv.db"
CURRENT_CONVERSATION_ID = None

@contextmanager
def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()

def init():
    with conn() as c:
        # Drop old tables
        c.execute("DROP TABLE IF EXISTS mindsets")

        c.execute("""CREATE TABLE IF NOT EXISTS prompts (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            content TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL,
            priority INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS triggers (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            pattern TEXT NOT NULL,
            response TEXT NOT NULL,
            category TEXT,
            priority INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS hooks (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            event TEXT NOT NULL,
            matcher TEXT NOT NULL,
            check_type TEXT NOT NULL,
            check_value TEXT,
            action TEXT NOT NULL,
            message TEXT,
            priority INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY, url TEXT, method TEXT,
            headers TEXT, body TEXT, response TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY, name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS chat (
            id INTEGER PRIMARY KEY, conversation_id INTEGER,
            role TEXT, content TEXT, tokens INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id))""")
        c.commit()

        # Migrate existing data if needed
        cursor = c.execute("PRAGMA table_info(chat)")
        cols = [col[1] for col in cursor.fetchall()]
        if "conversation_id" not in cols:
            c.execute("DROP TABLE chat")
            c.execute("""CREATE TABLE chat (
                id INTEGER PRIMARY KEY, conversation_id INTEGER,
                role TEXT, content TEXT, tokens INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id))""")
            c.commit()

    # Create new conversation at each startup
    global CURRENT_CONVERSATION_ID
    CURRENT_CONVERSATION_ID = create_conversation()

def clean_request(headers_str, body_str, response_str):
    """Nettoie une requête avant stockage."""

    # Headers : filtrer
    KEEP = ['host', 'x-xsrf-token', 'authorization', 'content-type', 'x-csrf', 'x-token']
    REMOVE = ['user-agent', 'accept', 'sec-fetch', 'priority', 'te:', 'referer']

    clean_headers = []
    for line in headers_str.split('\n'):
        lower = line.lower()
        if any(k in lower for k in REMOVE):
            continue
        if lower.startswith('cookie:'):
            clean_headers.append('Cookie: [session]')
        else:
            clean_headers.append(line)

    # Response : status + body seulement
    lines = response_str.split('\n')
    status = lines[0] if lines else ''
    body_start = response_str.find('\n\n')
    resp_body = response_str[body_start+2:] if body_start > 0 else ''
    clean_response = status + '\n' + resp_body

    return '\n'.join(clean_headers), body_str, clean_response

def add_request(url, method, headers, body, response):
    import hashlib

    headers, body, response = clean_request(headers, body, response)

    # Generate hash for deduplication (url + method + body)
    hash_input = f"{url}|{method}|{body}".encode('utf-8')
    request_hash = hashlib.sha256(hash_input).hexdigest()[:16]

    with conn() as c:
        # Check if hash exists (duplicate)
        existing = c.execute("SELECT id FROM requests WHERE hash=?", (request_hash,)).fetchone()
        if existing:
            return False  # Duplicate skipped

        c.execute("INSERT INTO requests (url, method, headers, body, response, hash) VALUES (?,?,?,?,?,?)",
                  (url, method, headers, body, response, request_hash))
        c.commit()
        return True  # Successfully added

def get_requests():
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM requests").fetchall()]

def clean_existing_requests():
    """Nettoie toutes les requêtes existantes en base."""
    with conn() as c:
        rows = c.execute("SELECT id, headers, body, response FROM requests").fetchall()
        for row in rows:
            clean_h, clean_b, clean_r = clean_request(row['headers'], row['body'], row['response'])
            c.execute("UPDATE requests SET headers=?, body=?, response=? WHERE id=?",
                     (clean_h, clean_b, clean_r, row['id']))
        c.commit()
        return len(rows)

def get_or_create_conversation(name):
    """Get or create conversation by name."""
    with conn() as c:
        existing = c.execute("SELECT id FROM conversations WHERE name=?", (name,)).fetchone()
        if existing:
            return existing["id"]
        cursor = c.execute("INSERT INTO conversations (name) VALUES (?)", (name,))
        c.commit()
        return cursor.lastrowid

def create_conversation(name=None):
    """Create new conversation with auto-generated name if not provided."""
    if not name:
        from datetime import datetime
        name = f"Chat {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return get_or_create_conversation(name)

def get_conversations():
    """List all conversations."""
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, name, created_at FROM conversations ORDER BY id DESC").fetchall()]

def delete_conversation(conv_id):
    """Delete conversation and its messages."""
    with conn() as c:
        c.execute("DELETE FROM chat WHERE conversation_id=?", (conv_id,))
        c.execute("DELETE FROM conversations WHERE id=?", (conv_id,))
        c.commit()

def set_current_conversation(conv_id):
    """Switch to different conversation."""
    global CURRENT_CONVERSATION_ID
    CURRENT_CONVERSATION_ID = conv_id

def get_current_conversation():
    """Get current conversation ID."""
    return CURRENT_CONVERSATION_ID

def add_msg(role, content, tokens=0):
    global CURRENT_CONVERSATION_ID
    with conn() as c:
        c.execute("INSERT INTO chat (conversation_id, role, content, tokens) VALUES (?,?,?,?)",
                  (CURRENT_CONVERSATION_ID, role, content, tokens))
        c.commit()

def get_history(limit=20):
    global CURRENT_CONVERSATION_ID
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM chat WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
            (CURRENT_CONVERSATION_ID, limit)).fetchall()][::-1]

def get_conversation_message_count(conv_id):
    """Get message count for a conversation."""
    with conn() as c:
        result = c.execute("SELECT COUNT(*) as count FROM chat WHERE conversation_id=?", (conv_id,)).fetchone()
        return result["count"] if result else 0

def get_conversation_tokens(conv_id):
    """Get total tokens for a conversation."""
    with conn() as c:
        result = c.execute("SELECT SUM(tokens) as total FROM chat WHERE conversation_id=?", (conv_id,)).fetchone()
        return result["total"] if result and result["total"] else 0


# === RULES (Comportementales IA) ===
def get_rules(active_only=True):
    """Get all behavioral rules ordered by priority."""
    with conn() as c:
        q = "SELECT * FROM rules"
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY priority DESC, name ASC"
        return [dict(r) for r in c.execute(q).fetchall()]

def add_rule(name, description, priority=0):
    """Add new behavioral rule."""
    with conn() as c:
        c.execute("INSERT INTO rules (name, description, priority) VALUES (?,?,?)",
                  (name, description, priority))
        c.commit()

def delete_rule(rule_name_or_id):
    """Delete rule by name or ID."""
    with conn() as c:
        try:
            rule_id = int(rule_name_or_id)
            c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        except ValueError:
            c.execute("DELETE FROM rules WHERE name=?", (rule_name_or_id,))
        c.commit()

def toggle_rule(rule_name_or_id):
    """Toggle rule active status."""
    with conn() as c:
        try:
            rule_id = int(rule_name_or_id)
            c.execute("UPDATE rules SET active = 1-active WHERE id=?", (rule_id,))
        except ValueError:
            c.execute("UPDATE rules SET active = 1-active WHERE name=?", (rule_name_or_id,))
        c.commit()

# === TRIGGERS (BLV-specific) ===
def get_triggers(active_only=True):
    """Get all BLV triggers ordered by priority."""
    with conn() as c:
        q = "SELECT * FROM triggers"
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY priority DESC, name ASC"
        return [dict(r) for r in c.execute(q).fetchall()]

def add_trigger(name, pattern, response, category=None, priority=0):
    """Add new BLV trigger."""
    with conn() as c:
        c.execute("INSERT INTO triggers (name, pattern, response, category, priority) VALUES (?,?,?,?,?)",
                  (name, pattern, response, category, priority))
        c.commit()

def delete_trigger(trigger_name_or_id):
    """Delete trigger by name or ID."""
    with conn() as c:
        try:
            trigger_id = int(trigger_name_or_id)
            c.execute("DELETE FROM triggers WHERE id=?", (trigger_id,))
        except ValueError:
            c.execute("DELETE FROM triggers WHERE name=?", (trigger_name_or_id,))
        c.commit()

def toggle_trigger(trigger_name_or_id):
    """Toggle trigger active status."""
    with conn() as c:
        try:
            trigger_id = int(trigger_name_or_id)
            c.execute("UPDATE triggers SET active = 1-active WHERE id=?", (trigger_id,))
        except ValueError:
            c.execute("UPDATE triggers SET active = 1-active WHERE name=?", (trigger_name_or_id,))
        c.commit()

# === FINDINGS ===
def add_event(pattern, worked=True, target=None, technique=None, impact=None, notes=None, payload=None, context=None, request_id=None):
    """Save test event with full details."""
    import hashlib

    # Generate hash for deduplication
    hash_input = f"{pattern}|{target}|{technique}|{impact}".encode('utf-8')
    event_hash = hashlib.sha256(hash_input).hexdigest()[:16]

    with conn() as c:
        # Check if hash exists (duplicate)
        existing = c.execute("SELECT id FROM events WHERE hash=?", (event_hash,)).fetchone()
        if existing:
            return  # Skip duplicate

        c.execute("""INSERT INTO events
                     (pattern, worked, target, technique, impact, notes, payload, context, request_id, hash)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (pattern, 1 if worked else 0, target, technique, impact, notes, payload, context, request_id, event_hash))
        c.commit()

# Aliases for backward compatibility
def add_finding(pattern, worked=True, target=None, context=None, request_id=None):
    """Legacy alias for add_event."""
    add_event(pattern, worked, target, context=context, request_id=request_id)

def get_events(worked_only=False, limit=20):
    """Get events, optionally only successful ones."""
    with conn() as c:
        q = "SELECT * FROM events"
        if worked_only:
            q += " WHERE worked=1"
        q += " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in c.execute(q, (limit,)).fetchall()]

# Alias for backward compatibility
def get_findings(worked_only=False, limit=20):
    """Legacy alias for get_events."""
    return get_events(worked_only, limit)

def search_events(keyword):
    """Search events by pattern, target, technique, or notes."""
    with conn() as c:
        return [dict(r) for r in c.execute(
            """SELECT * FROM events
               WHERE pattern LIKE ? OR target LIKE ? OR technique LIKE ? OR notes LIKE ?
               ORDER BY id DESC""",
            (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")).fetchall()]

# Alias for backward compatibility
def search_findings(keyword):
    """Legacy alias for search_events."""
    return search_events(keyword)

# === PROMPTS ===
def get_prompts(active_only=True):
    """Get all prompts ordered by priority."""
    with conn() as c:
        q = "SELECT * FROM prompts"
        if active_only:
            q += " WHERE active=1"
        q += " ORDER BY priority DESC, name ASC"
        return [dict(r) for r in c.execute(q).fetchall()]

def add_prompt(name, content, priority=0):
    """Add new prompt."""
    with conn() as c:
        c.execute("INSERT INTO prompts (name, content, priority) VALUES (?,?,?)",
                  (name, content, priority))
        c.commit()

def update_prompt(name, content):
    """Update prompt content."""
    with conn() as c:
        c.execute("UPDATE prompts SET content=? WHERE name=?", (content, name))
        c.commit()

def delete_prompt(name):
    """Delete prompt by name."""
    with conn() as c:
        c.execute("DELETE FROM prompts WHERE name=?", (name,))
        c.commit()

def toggle_prompt(name):
    """Toggle prompt active status."""
    with conn() as c:
        c.execute("UPDATE prompts SET active = 1-active WHERE name=?", (name,))
        c.commit()

# === HOOKS ===
def get_hooks(event=None, active_only=True):
    """Get hooks, optionally filtered by event."""
    with conn() as c:
        q = "SELECT * FROM hooks"
        conditions = []
        params = []

        if active_only:
            conditions.append("active=1")
        if event:
            conditions.append("event=?")
            params.append(event)

        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        q += " ORDER BY priority DESC, name ASC"

        return [dict(r) for r in c.execute(q, params).fetchall()]

def add_hook(name, event, matcher, check_type, action, check_value=None, message=None, priority=0):
    """Add new hook."""
    with conn() as c:
        c.execute("""INSERT INTO hooks (name, event, matcher, check_type, check_value, action, message, priority)
                     VALUES (?,?,?,?,?,?,?,?)""",
                  (name, event, matcher, check_type, check_value, action, message, priority))
        c.commit()

def update_hook(hook_id, **kwargs):
    """Update hook fields."""
    with conn() as c:
        fields = []
        values = []
        for key, val in kwargs.items():
            if key in ['event', 'matcher', 'check_type', 'check_value', 'action', 'message', 'priority']:
                fields.append(f"{key}=?")
                values.append(val)
        if fields:
            values.append(hook_id)
            c.execute(f"UPDATE hooks SET {', '.join(fields)} WHERE id=?", values)
            c.commit()

def delete_hook(hook_id):
    """Delete hook by ID."""
    with conn() as c:
        c.execute("DELETE FROM hooks WHERE id=?", (hook_id,))
        c.commit()

def toggle_hook(hook_id):
    """Toggle hook active status."""
    with conn() as c:
        c.execute("UPDATE hooks SET active = 1-active WHERE id=?", (hook_id,))
        c.commit()
