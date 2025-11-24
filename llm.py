"""LLM streaming with LiteLLM."""
import os
from litellm import completion
from db import get_requests, add_msg, get_findings, add_finding, get_rules, get_triggers, get_prompts

API_BASE = os.getenv("LITELLM_API_BASE")
API_KEY = os.getenv("LITELLM_API_KEY")
MODEL = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929")

# Tools for auto-learning
BLV_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "save_finding",
            "description": "Sauvegarde un pattern BLV testé. Appelle quand user confirme résultat test.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Le pattern testé (ex: state→authorize bypass)"},
                    "worked": {"type": "boolean", "description": "True si vulnérable, False si bloqué"},
                    "target": {"type": "string", "description": "Cible (ex: Cdiscount 3DS, PayPal checkout)"}
                },
                "required": ["pattern", "worked"]
            }
        }
    }
]

def handle_tool_call(tool_name, args):
    """Execute tool and return result."""
    if tool_name == "save_finding":
        add_finding(
            pattern=args.get("pattern"),
            worked=args.get("worked", True),
            target=args.get("target")
        )
        return f"✓ Finding saved: {args.get('pattern')}"
    return "Unknown tool"

LAST_PROMPT_TOKENS = 0
LAST_CACHE_READ_TOKENS = 0

def count_tokens(messages):
    """Estimate tokens (4 chars ≈ 1 token)."""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            content = "".join(str(c.get("text", "")) for c in content)
        total += len(str(content)) // 4 + 4  # +4 for message overhead
    return total

def build_prompt():
    parts = []

    # 1. Behavioral Rules (SQLite) - FIRST for max impact
    rules = get_rules(active_only=True)
    if rules:
        parts.append("# RÈGLES COMPORTEMENTALES\n")
        for r in rules:
            parts.append(f"- {r['description']}\n")
        parts.append("\n")

    # 2. BLV Triggers (SQLite)
    triggers = get_triggers(active_only=True)
    if triggers:
        parts.append("# TRIGGERS BLV\n")
        for t in triggers:
            parts.append(f"- {t['pattern']} → {t['response']}\n")
        parts.append("\n")

    # 3. Prompts (SQLite)
    prompts = get_prompts(active_only=True)
    for p in prompts:
        parts.append(p['content'] + "\n\n")

    # 4. Findings DB (SQL)
    findings = get_findings(worked_only=True, limit=10)
    if findings:
        parts.append("# PATTERNS VALIDÉS\n")
        for f in findings:
            status = "✓" if f['worked'] else "✗"
            parts.append(f"- {status} {f['pattern']}")
            if f.get('target'):
                parts.append(f" ({f['target']})")
            parts.append("\n")
        parts.append("\n")

    # 5. HTTP Requests DB (SQL)
    reqs = get_requests()
    if reqs:
        parts.append(f"# HTTP REQUESTS ({len(reqs)})\n")
        for r in reqs:
            parts.append(f"- {r['method']} {r['url']}\n")

    return "".join(parts)

def build_messages(history, new_msg):
    """Build message list with cache_control for system + history."""
    messages = []

    # System prompt with cache
    sys_prompt = build_prompt()
    if sys_prompt:
        messages.append({
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": sys_prompt,
                    "cache_control": {"type": "ephemeral"}
                }
            ]
        })

    # Cache all history except last 2 messages
    if len(history) > 2:
        for msg in history[:-2]:
            if msg["role"] == "user":
                messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": msg["content"],
                            "cache_control": {"type": "ephemeral"}
                        }
                    ]
                })
            else:
                messages.append(msg)

        # Last 2 messages (not cached)
        messages.extend(history[-2:])
    else:
        # History too short, no caching
        messages.extend(history)

    # New message (not cached)
    messages.append({"role": "user", "content": new_msg})

    # Count prompt tokens
    global LAST_PROMPT_TOKENS
    LAST_PROMPT_TOKENS = count_tokens(messages)

    return messages

def chat_stream(msg, history, thinking_enabled=False):
    messages = build_messages(history, msg)

    add_msg("user", msg)

    # Get current model from env (may have changed via /model)
    model = os.getenv("LITELLM_MODEL", MODEL)

    kwargs = {
        "model": model,
        "messages": messages,
        "stream": True,
        "api_base": API_BASE,
        "api_key": API_KEY,
        "timeout": 60,
        # Tools désactivés - on parse le texte à la place
    }

    # Add thinking parameter if enabled (only for Anthropic models)
    if thinking_enabled and "claude" in model.lower():
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": 4096}

    response = completion(**kwargs)

    text = ""
    thinking_detected = False
    last_chunk = None
    tool_calls = []

    for chunk in response:
        last_chunk = chunk

        if hasattr(chunk, 'choices') and chunk.choices:
            delta = chunk.choices[0].delta

            # Detect thinking phase (multiple possible attributes)
            if thinking_enabled and not thinking_detected:
                if (hasattr(delta, 'thinking') and delta.thinking) or \
                   (hasattr(delta, 'reasoning_content') and delta.reasoning_content) or \
                   (hasattr(delta, 'type') and delta.type == 'thinking'):
                    yield ("thinking", "")
                    thinking_detected = True

            # Handle tool calls
            if hasattr(delta, 'tool_calls') and delta.tool_calls:
                for tc in delta.tool_calls:
                    if hasattr(tc, 'function'):
                        tool_calls.append({
                            "name": tc.function.name if hasattr(tc.function, 'name') else None,
                            "arguments": tc.function.arguments if hasattr(tc.function, 'arguments') else "{}"
                        })

            # Handle normal content
            if hasattr(delta, 'content') and delta.content:
                text += delta.content
                yield ("content", delta.content)

    # Execute any tool calls
    import json
    for tc in tool_calls:
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                result = handle_tool_call(tc["name"], args)
                yield ("tool", result)
            except Exception as e:
                yield ("tool_error", str(e))

    # Extract cache info from last chunk (Anthropic format)
    global LAST_CACHE_READ_TOKENS
    if last_chunk and hasattr(last_chunk, 'usage'):
        usage = last_chunk.usage
        if hasattr(usage, 'cache_read_input_tokens'):
            LAST_CACHE_READ_TOKENS = usage.cache_read_input_tokens
        elif hasattr(usage, 'prompt_tokens_details'):
            details = usage.prompt_tokens_details
            if hasattr(details, 'cached_tokens'):
                LAST_CACHE_READ_TOKENS = details.cached_tokens
        else:
            LAST_CACHE_READ_TOKENS = 0
    else:
        LAST_CACHE_READ_TOKENS = 0

    add_msg("assistant", text, len(text)//4)
    
    # Parse and save findings from text (multiple formats)
    import re
    # Format: [FINDING:pattern|true|target]
    pattern_regex = r'\[FINDING:([^|\]]+)\|([^|\]]+)\|([^\]]*)\]'
    for match in re.finditer(pattern_regex, text, re.IGNORECASE):
        pat, worked, target = match.groups()
        add_finding(
            pattern=pat.strip(),
            worked=worked.strip().lower() in ('true', '1', 'yes', 'oui'),
            target=target.strip() if target.strip() else None
        )
        # Notify about saved finding
        yield ("tool", f"save_finding({pat.strip()}, worked={worked.strip()}, target={target.strip()})")
