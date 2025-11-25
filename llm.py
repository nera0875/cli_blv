"""LLM streaming with LiteLLM."""
import os
from litellm import completion
from anthropic import Anthropic
from db import get_requests, add_msg, get_findings, add_finding, get_rules, get_triggers, get_prompts, get_plans

API_BASE = os.getenv("LITELLM_API_BASE")
API_KEY = os.getenv("LITELLM_API_KEY")
MODEL = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929")

# Available models (match LiteLLM config names exactly)
MODELS = {
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "opus-4.5": "anthropic/claude-opus-4-5-20251101",  # Prefix required in LiteLLM
    "opus-4.1": "claude-opus-4-1-20250805",
    "haiku-4.5": "claude-haiku-4-5-20251001",
}

# Thinking budgets
THINKING_BUDGETS = {
    "none": 0,
    "quick": 4000,
    "normal": 16000,
    "deep": 32000,
    "ultra": 64000
}

# Global thinking config
THINKING_MODE = os.getenv("THINKING_MODE", "none")  # none, quick, normal, deep, ultra

# Tools for auto-learning
BLV_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "save_event",
            "description": """Sauvegarde un event de test BLV. Appelle quand user confirme résultat.

EXEMPLE OBLIGATOIRE:
User: "debit effectué carte2 avec PaRes carte1"
→ save_event(
    pattern="3DS PaRes replay cross-card",
    worked=True,
    target="Cdiscount",
    technique="Replay valid PaRes from card1 authentication to card2 transaction",
    impact="Payment bypass - unauthorized debit",
    notes="Card1 validated 3DS, PaRes replayed on card2 with 0 balance, debit successful"
)

TOUJOURS remplir: pattern, worked, target, technique, impact.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern descriptif (ex: 3DS2 PaRes replay cross-card, HMAC bypass state manipulation)"},
                    "worked": {"type": "boolean", "description": "True si vulnérable/bypass réussi, False si bloqué/refusé"},
                    "target": {"type": "string", "description": "Nom du site/app (ex: Cdiscount, PayPal, Stripe)"},
                    "technique": {"type": "string", "description": "Méthode technique précise (ex: Replay token cross-card, Drop validation + reuse requestId)"},
                    "impact": {"type": "string", "description": "Conséquence sécurité (ex: Payment bypass, IDOR account takeover, Double-spend)"},
                    "notes": {"type": "string", "description": "Détails contextuels du user et résultat observé"},
                    "payload": {"type": "string", "description": "Requête HTTP ou payload utilisé (optionnel)"}
                },
                "required": ["pattern", "worked", "target", "technique", "impact"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "show_analysis",
            "description": """Affiche analyse structurée dans Panel. OBLIGATOIRE pour toute analyse >50 mots.

Utilise pour: réponses hypothèses, analyses patterns, explications techniques.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Titre court (ex: 3DS Bypass Analysis)"},
                    "pattern": {"type": "string", "description": "Nom du pattern analysé"},
                    "target": {"type": "string", "description": "Cible (site/API)"},
                    "hypothesis": {"type": "string", "description": "Hypothèse technique"},
                    "tests": {"type": "array", "items": {"type": "string"}, "description": "Liste tests à effectuer (3-5 max)"},
                    "impact": {"type": "string", "description": "Impact si vulnérable"},
                    "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"], "description": "Niveau confiance"}
                },
                "required": ["title", "pattern", "hypothesis", "tests"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_test",
            "description": """Suggère un test précis avec steps. OBLIGATOIRE pour suggestions tests.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern à tester"},
                    "target": {"type": "string", "description": "Cible"},
                    "steps": {"type": "array", "items": {"type": "string"}, "description": "Étapes précises (3-5 max)"},
                    "variables": {"type": "array", "items": {"type": "string"}, "description": "Variables critiques à manipuler"},
                    "expected": {"type": "string", "description": "Résultat attendu si vulnérable"}
                },
                "required": ["pattern", "steps", "expected"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ask_clarification",
            "description": """Demande clarification user. OBLIGATOIRE si input ambigu/incomplet (ex: 'eazaze', <5 chars).""",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "Question claire (max 20 mots)"}
                },
                "required": ["question"]
            }
        }
    }
]

def execute_hooks(event, tool_name, args):
    """Execute hooks for given event and tool. Returns (action, message, updated_args)."""
    from db import get_hooks
    import json
    import re

    # Get matching hooks
    hooks = get_hooks(event=event, active_only=True)

    for hook in hooks:
        # Check if hook matches tool (exact match or wildcard)
        matcher = hook['matcher']
        if matcher != "*" and matcher != tool_name:
            # Try regex match
            try:
                if not re.match(matcher, tool_name):
                    continue
            except:
                continue  # Invalid regex, skip

        # Execute check based on check_type
        check_type = hook['check_type']
        check_value = hook['check_value']
        action = hook['action']
        message = hook['message'] or ""

        try:
            if check_type == "length":
                # Check text length (for field specified in check_value)
                field = check_value or "title"
                value = args.get(field, "")
                max_len = 50  # Default
                if ":" in check_value:
                    field, max_len = check_value.split(":")
                    max_len = int(max_len)
                    value = args.get(field, "")

                if len(value) > max_len:
                    return (action, message.format(field=field, max=max_len), args)

            elif check_type == "required_fields":
                # Check required fields exist and non-empty
                fields = json.loads(check_value) if check_value else []
                missing = [f for f in fields if not args.get(f)]
                if missing:
                    return (action, message.format(fields=", ".join(missing)), args)

            elif check_type == "min_count":
                # Check array has minimum items
                field, min_count = check_value.split(":") if ":" in check_value else (check_value, "1")
                value = args.get(field, [])
                if not isinstance(value, list) or len(value) < int(min_count):
                    return (action, message.format(field=field, min=min_count), args)

            elif check_type == "max_count":
                # Check array has maximum items
                field, max_count = check_value.split(":") if ":" in check_value else (check_value, "10")
                value = args.get(field, [])
                if isinstance(value, list) and len(value) > int(max_count):
                    return (action, message.format(field=field, max=max_count), args)

            elif check_type == "enum":
                # Check value is in allowed list
                field, allowed = check_value.split(":") if ":" in check_value else (check_value, "")
                value = args.get(field)
                allowed_values = allowed.split(",")
                if value and value not in allowed_values:
                    return (action, message.format(field=field, allowed=allowed), args)

        except Exception as e:
            # Hook execution error, log but continue
            pass

    # All hooks passed
    return ("allow", "", args)

def handle_tool_call(tool_name, args):
    """Execute tool and return result."""
    # Execute pre_tool hooks
    action, hook_msg, updated_args = execute_hooks("pre_tool", tool_name, args)
    if action == "deny":
        return f"❌ Hook bloqué: {hook_msg}"
    elif action == "warn":
        # Continue but show warning
        pass
    # Use updated args if modified by hooks
    args = updated_args

    if tool_name == "save_event" or tool_name == "save_finding":
        from db import add_event
        import json
        import sys

        # Validate required fields
        if not args.get("pattern") or not args.get("target"):
            return f"✗ Error: Missing required fields (pattern={args.get('pattern')}, target={args.get('target')})"

        add_event(
            pattern=args.get("pattern"),
            worked=args.get("worked", True),
            target=args.get("target"),
            technique=args.get("technique"),
            impact=args.get("impact"),
            notes=args.get("notes"),
            payload=args.get("payload")
        )

        # Build result message with Panel + smooth transition
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.syntax import Syntax
            import time

            console = Console(file=sys.stderr)

            # Spinner pendant traitement (transition smooth)
            with console.status("[cyan]🔧 Sauvegarde event...", spinner="dots"):
                time.sleep(0.3)  # Mini pause pour transition

            # Status emoji + message
            if args.get("worked"):
                emoji = "💥"
                status = "VULNERABLE"
                border_color = "red"
                result_msg = f"{emoji} {args.get('pattern')} → {status} on {args.get('target')}"
            else:
                emoji = "🛡️"
                status = "BLOCKED"
                border_color = "blue"
                result_msg = f"{emoji} {args.get('pattern')} → {status} by {args.get('target')}"

            # Panel content with JSON
            syntax = Syntax(json.dumps(args, indent=2), "json", theme="monokai", line_numbers=False)

            # Print Panel with result as title
            console.print(Panel(
                syntax,
                title=f"[bold]{result_msg}[/]",
                border_style=border_color,
                padding=(0, 1)
            ))

            return ""  # No additional message needed (already in Panel)
        except Exception:
            # Fallback si Rich pas dispo
            if args.get("worked"):
                return f"💥 {args.get('pattern')} → VULNERABLE on {args.get('target')}"
            else:
                return f"🛡️ {args.get('pattern')} → BLOCKED by {args.get('target')}"

    elif tool_name == "show_analysis":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            import time

            console = Console(file=sys.stderr)

            with console.status("[cyan]📊 Construction analyse...", spinner="dots"):
                time.sleep(0.2)

            # Highlight pattern keywords
            pattern_text = args.get("pattern", "Inconnu")
            for keyword in ['bypass', 'injection', 'replay', 'corruption', 'HMAC', '3DS']:
                if keyword in pattern_text:
                    pattern_text = pattern_text.replace(keyword, f'[bold red]{keyword}[/]', 1)

            tests = args.get("tests", [])
            tests_formatted = '\n'.join([f"  [cyan]▸[/] {test}" for test in tests])

            confidence = args.get("confidence", "MEDIUM")
            conf_color = {"LOW": "yellow", "MEDIUM": "yellow", "HIGH": "green"}.get(confidence, "yellow")

            analysis = f"""[bold cyan]═══════════════════════════════[/]
[bold white]{pattern_text}[/]
[bold cyan]═══════════════════════════════[/]

[red]●[/] [bold white]Cible[/] [dim]→[/] [bold magenta]{args.get('target', 'Inconnu')}[/]
[yellow]●[/] [bold white]Hypothèse[/] [dim]→[/] [italic yellow]{args.get('hypothesis', 'Inconnu')}[/]

[bold magenta]⚡ TESTS[/]
{tests_formatted}

[bold]─────────────────────────────[/]
[green]✓[/] [dim]Impact:[/] [bold]{args.get('impact', 'Inconnu')}[/]
[{conf_color}]◆[/] [dim]Confiance:[/] [bold {conf_color}]{confidence}[/]"""

            console.print(Panel(
                analysis,
                title=f"📊 {args.get('title', 'Analyse')}",
                border_style="cyan",
                padding=(1, 2),
                expand=False
            ))

            return ""
        except Exception as e:
            return f"Analyse: {args.get('pattern', 'Inconnu')}"

    elif tool_name == "suggest_test":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            import time

            console = Console(file=sys.stderr)

            with console.status("[cyan]🧪 Préparation test...", spinner="dots"):
                time.sleep(0.2)

            steps = args.get("steps", [])
            steps_formatted = '\n'.join([f"  [green]{i+1}.[/] {step}" for i, step in enumerate(steps)])

            variables = args.get("variables", [])
            vars_formatted = '\n'.join([f"  [yellow]•[/] {var}" for var in variables]) if variables else "  [dim]None specified[/]"

            test_panel = f"""[bold white]Pattern:[/] [bold cyan]{args.get('pattern', 'Unknown')}[/]
[bold white]Target:[/] [red]{args.get('target', 'Unknown')}[/]

[bold yellow]⚡ EXECUTION STEPS[/]
{steps_formatted}

[bold yellow]🎯 VARIABLES[/]
{vars_formatted}

[bold]─────────────────────────────[/]
[green]✓[/] [dim]Expected:[/] [bold]{args.get('expected', 'Unknown')}[/]"""

            console.print(Panel(
                test_panel,
                title="🧪 Test Suggestion",
                border_style="green",
                padding=(1, 2),
                expand=False
            ))

            return ""
        except Exception as e:
            return f"Test: {args.get('pattern', 'Unknown')}"

    elif tool_name == "ask_clarification":
        return f"❓ {args.get('question', 'Peux-tu préciser ?')}"

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

    # 2. Plans (Targets & Objectives)
    plans = get_plans(active_only=True)
    if plans:
        parts.append("# PLAN ACTIF\n")
        for p in plans:
            parts.append(f"## {p['name']}\n")
            parts.append(f"- Target: {p['target']}\n")
            parts.append(f"- Objectif: {p['objective']}\n")
        parts.append("\n")

    # 3. BLV Triggers (SQLite)
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

def chat_stream_anthropic(msg, history, thinking_budget, use_tools=True):
    """Direct Anthropic API streaming with Extended Thinking support."""
    # Initialize Anthropic client (API key from .env)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        raise ValueError("ANTHROPIC_API_KEY not set in .env")

    client = Anthropic(api_key=anthropic_key)

    # Build system prompt
    sys_prompt = build_prompt()

    # Build messages (Anthropic format) - filter empty content
    messages = []
    for h in history:
        content = h["content"]
        # Skip messages with empty content (tool calls without response)
        if content and content.strip():
            messages.append({
                "role": h["role"],
                "content": content
            })
    messages.append({"role": "user", "content": msg})

    # Add user message to DB
    add_msg("user", msg)

    # Get model ID (strip LiteLLM prefix if present)
    model = os.getenv("LITELLM_MODEL", MODEL)
    if model.startswith("anthropic/"):
        model = model.replace("anthropic/", "")

    # Build API call kwargs (stream=True implicit with .stream())
    # Get user config from .env
    user_max_tokens = int(os.getenv("MAX_TOKENS", "8192"))
    user_temperature = float(os.getenv("TEMPERATURE", "1.0"))

    # Determine max_tokens based on thinking mode
    if thinking_budget > 0:
        # Thinking enabled: use 64K total (thinking uses budget, rest for response)
        base_max_tokens = 64000
    else:
        # No thinking: use user config
        base_max_tokens = user_max_tokens

    kwargs = {
        "model": model,
        "max_tokens": base_max_tokens,
        "temperature": user_temperature,
        "system": [
            {
                "type": "text",
                "text": sys_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ],
        "messages": messages
    }

    # Add thinking
    if thinking_budget > 0:
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": thinking_budget
        }

    # Add tools
    if use_tools:
        kwargs["tools"] = [
            {
                "name": tool["function"]["name"],
                "description": tool["function"]["description"],
                "input_schema": tool["function"]["parameters"]
            }
            for tool in BLV_TOOLS
        ]

    # Stream response
    text = ""
    thinking_text = ""
    thinking_detected = False
    tool_calls_builder = {}
    usage_data = None

    with client.messages.stream(**kwargs) as stream:
        for event in stream:
            # Handle thinking blocks
            if hasattr(event, 'type'):
                if event.type == 'content_block_start':
                    if hasattr(event, 'content_block'):
                        block = event.content_block
                        if hasattr(block, 'type') and block.type == 'thinking':
                            thinking_detected = True
                            yield ("thinking_start", "")

                elif event.type == 'content_block_delta':
                    if hasattr(event, 'delta'):
                        delta = event.delta
                        if hasattr(delta, 'type'):
                            if delta.type == 'thinking_delta':
                                thinking_text += delta.thinking
                                yield ("thinking_chunk", delta.thinking)
                            elif delta.type == 'text_delta':
                                text += delta.text
                                yield ("content", delta.text)
                            elif delta.type == 'input_json_delta':
                                # Tool call arguments streaming
                                pass  # Handle below

                elif event.type == 'content_block_stop':
                    # Block finished
                    pass

            # Handle tool use (simpler in SDK)
            if hasattr(event, 'type') and event.type == 'content_block_start':
                if hasattr(event, 'content_block'):
                    block = event.content_block
                    if hasattr(block, 'type') and block.type == 'tool_use':
                        idx = event.index if hasattr(event, 'index') else 0
                        tool_calls_builder[idx] = {
                            "id": block.id,
                            "name": block.name,
                            "arguments": ""
                        }
                        yield ("tool_start", block.name)

            # Accumulate tool arguments
            if hasattr(event, 'type') and event.type == 'content_block_delta':
                if hasattr(event, 'delta') and hasattr(event.delta, 'type'):
                    if event.delta.type == 'input_json_delta':
                        idx = event.index if hasattr(event, 'index') else 0
                        if idx in tool_calls_builder:
                            tool_calls_builder[idx]["arguments"] += event.delta.partial_json

        # Extract usage after stream ends
        final_message = stream.get_final_message()
        if hasattr(final_message, 'usage'):
            usage_data = final_message.usage

    # Extract cache info and update globals
    global LAST_CACHE_READ_TOKENS, LAST_PROMPT_TOKENS
    if usage_data:
        # Anthropic SDK format
        LAST_PROMPT_TOKENS = getattr(usage_data, 'input_tokens', 0)
        LAST_CACHE_READ_TOKENS = getattr(usage_data, 'cache_read_input_tokens', 0)
    else:
        LAST_CACHE_READ_TOKENS = 0
        LAST_PROMPT_TOKENS = len(text) // 4  # Fallback estimate

    # Yield tool calls for cli.py to handle (with confirmation if needed)
    import json
    for idx in sorted(tool_calls_builder.keys()):
        tc = tool_calls_builder[idx]
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                # Yield for cli.py to confirm/execute
                yield ("tool_ready", {"name": tc["name"], "args": args})
            except Exception as e:
                yield ("tool_error", str(e))

    # Save assistant response with actual tokens
    output_tokens = getattr(usage_data, 'output_tokens', len(text)//4) if usage_data else len(text)//4
    add_msg("assistant", text, output_tokens)

    # Parse and save findings
    import re
    pattern_regex = r'\[FINDING:([^|\]]+)\|([^|\]]+)\|([^\]]*)\]'
    for match in re.finditer(pattern_regex, text, re.IGNORECASE):
        pat, worked, target = match.groups()
        add_finding(
            pattern=pat.strip(),
            worked=worked.strip().lower() in ('true', '1', 'yes', 'oui'),
            target=target.strip() if target.strip() else None
        )
        yield ("tool", f"save_finding({pat.strip()}, worked={worked.strip()}, target={target.strip()})")

def chat_stream(msg, history, thinking_enabled=False, use_tools=True):
    # Get current model from env (may have changed via /model)
    model = os.getenv("LITELLM_MODEL", MODEL)

    # Determine thinking budget
    global THINKING_MODE
    thinking_mode = os.getenv("THINKING_MODE", THINKING_MODE)
    budget = THINKING_BUDGETS.get(thinking_mode, 0)

    # Override if thinking_enabled explicitly passed
    if thinking_enabled and budget == 0:
        budget = THINKING_BUDGETS["normal"]
    elif not thinking_enabled:
        # Force disable thinking if explicitly False (e.g., /idea)
        budget = 0

    # Route to Anthropic SDK if Opus 4.5 (always, thinking or not)
    # Reason: LiteLLM doesn't support thinking, and consistent routing
    if "20251101" in model:
        # Use direct Anthropic API (thinking optional)
        yield from chat_stream_anthropic(msg, history, budget, use_tools)
        return

    # Otherwise use LiteLLM (existing implementation)
    messages = build_messages(history, msg)

    add_msg("user", msg)

    # Get user config from .env
    user_max_tokens = int(os.getenv("MAX_TOKENS", "8192"))
    user_temperature = float(os.getenv("TEMPERATURE", "1.0"))

    kwargs = {
        "model": model,
        "messages": messages,
        "stream": True,
        "api_base": API_BASE,
        "api_key": API_KEY,
        "timeout": 120,
        "max_tokens": user_max_tokens,
        "temperature": user_temperature
    }

    if use_tools:
        kwargs["tools"] = BLV_TOOLS

    # Note: LiteLLM doesn't support thinking yet, but keep for future
    if budget > 0 and "claude" in model.lower():
        kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}

    response = completion(**kwargs)

    text = ""
    thinking_text = ""
    thinking_detected = False
    last_chunk = None
    tool_calls_builder = {}  # index → {name, arguments}

    for chunk in response:
        last_chunk = chunk

        if hasattr(chunk, 'choices') and chunk.choices:
            delta = chunk.choices[0].delta

            # Handle thinking content streaming (Claude 4+ format)
            if budget > 0:
                # Check for thinking in content blocks
                if hasattr(delta, 'content') and isinstance(delta.content, list):
                    for block in delta.content:
                        if hasattr(block, 'type') and block.type == 'thinking':
                            if not thinking_detected:
                                yield ("thinking_start", "")
                                thinking_detected = True
                            if hasattr(block, 'thinking'):
                                thinking_text += block.thinking
                                yield ("thinking_chunk", block.thinking)
                        elif hasattr(block, 'type') and block.type == 'text':
                            if hasattr(block, 'text'):
                                text += block.text
                                yield ("content", block.text)
                # Legacy format
                elif hasattr(delta, 'thinking') and delta.thinking:
                    if not thinking_detected:
                        yield ("thinking_start", "")
                        thinking_detected = True
                    thinking_text += delta.thinking
                    yield ("thinking_chunk", delta.thinking)

            # Handle tool calls (streaming - accumulate by index)
            if hasattr(delta, 'tool_calls') and delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index if hasattr(tc, 'index') else 0

                    if idx not in tool_calls_builder:
                        tool_calls_builder[idx] = {"name": None, "arguments": "", "started": False}

                    if hasattr(tc, 'function'):
                        if hasattr(tc.function, 'name') and tc.function.name:
                            tool_calls_builder[idx]["name"] = tc.function.name
                            # Yield tool_start on first detection
                            if not tool_calls_builder[idx]["started"]:
                                yield ("tool_start", tc.function.name)
                                tool_calls_builder[idx]["started"] = True
                        if hasattr(tc.function, 'arguments') and tc.function.arguments:
                            tool_calls_builder[idx]["arguments"] += tc.function.arguments

            # Handle normal content (string format, when not in content blocks)
            if hasattr(delta, 'content') and delta.content and isinstance(delta.content, str):
                text += delta.content
                yield ("content", delta.content)

    # Yield tool calls for cli.py to handle (with confirmation if needed)
    import json
    for idx in sorted(tool_calls_builder.keys()):
        tc = tool_calls_builder[idx]
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                yield ("tool_ready", {"name": tc["name"], "args": args})
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
