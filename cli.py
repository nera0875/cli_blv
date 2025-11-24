"""BLV CLI - REPL shell."""
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import os
from pathlib import Path
from datetime import datetime
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.input.defaults import create_input
from prompt_toolkit.formatted_text import HTML
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich.status import Status
from datetime import datetime, timedelta
import requests
import xml.etree.ElementTree as ET
import questionary
from questionary import Style, Choice
import re

# Reduce ESC timeout to 10ms for instant response
try:
    _input = create_input()
    if hasattr(_input, 'vt100_input'):
        _input.vt100_input.flush_timeout = 0.01  # 10ms
except:
    pass

# Load .env
env = Path(".env")
if env.exists():
    for line in env.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()

import db
from llm import chat_stream
import llm

console = Console()
db.init()

# Global thinking toggle
THINKING_ENABLED = False

# TAB autocompletion
COMMANDS = ['/help', '/h', '/chat', '/c', '/prompt', '/p', '/rules', '/trigger', '/add', '/stats', '/s', '/import', '/i', '/model', '/clear', '/resume', '/tables', '/quit', '/q', '/back']
completer = WordCompleter(COMMANDS, ignore_case=True)
history = InMemoryHistory()

def sanitize_text(text):
    """Remove invalid Unicode surrogates (Windows clipboard issue)."""
    try:
        return text.encode('utf-8', errors='ignore').decode('utf-8')
    except:
        return text

# Questionary custom style
custom_style = Style([
    ('qmark', 'fg:#5f87af bold'),           # ? symbole
    ('question', 'fg:#00d7ff bold'),         # Question text
    ('answer', 'fg:#5fff5f bold'),           # Sélection finale
    ('pointer', 'fg:#ff8700 bold'),          # → pointeur (orange)
    ('highlighted', 'fg:#ffffff bg:#005f87 bold'),  # Ligne active (blanc sur bleu)
    ('selected', 'fg:#5fff5f'),              # Confirmé (vert)
])

def detect_test_list(text):
    """Retourne liste de tests si détectés, sinon None."""
    patterns = [
        r'^\s*(\d+)\.\s+(.+)',           # 1. Description
        r'^\s*#(\d+)\s+(.+)',             # #1 Description
        r'^\s*\[(\d+)\]\s+(.+)',          # [1] Description
    ]
    tests = []
    for line in text.split('\n'):
        for p in patterns:
            m = re.match(p, line)
            if m:
                # Clean and truncate description
                desc = m.group(2).strip()
                # Remove markdown bold/italic
                desc = re.sub(r'\*\*([^*]+)\*\*', r'\1', desc)
                desc = re.sub(r'\*([^*]+)\*', r'\1', desc)
                # Truncate at 70 chars
                if len(desc) > 70:
                    desc = desc[:67] + "..."
                tests.append({"id": m.group(1), "desc": desc})
                break
    return tests if len(tests) >= 2 else None

def detect_payload_shown(text):
    """Détecte si IA affiche un payload/test détaillé."""
    keywords = ["payload", "body modifié", "copie", "teste ça", "résultat attendu"]
    return any(k in text.lower() for k in keywords)

def safe_input(prompt_text):
    """Input wrapper that handles Esc (EOFError) gracefully."""
    try:
        return input(prompt_text)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled[/]")
        return None

# Global key bindings for ESC handling
kb = KeyBindings()

@kb.add('escape', eager=True)
def _(event):
    """Handle ESC key - exit immediately."""
    event.app.exit(result='__ESC__')

@kb.add('tab')
def _(event):
    """Toggle thinking mode (TAB)."""
    global THINKING_ENABLED
    THINKING_ENABLED = not THINKING_ENABLED
    event.app.invalidate()  # Force refresh display

@kb.add('s-tab')
def _(event):
    """Autocomplete (Shift+TAB)."""
    event.current_buffer.complete_next()

def bottom_toolbar():
    """Bottom toolbar showing thinking status."""
    status = "Thinking enabled" if THINKING_ENABLED else "Thinking disabled"
    return HTML(f'<b>{status}</b> (TAB to toggle)')

def safe_prompt(prompt_text, style_str="", **kwargs):
    """Prompt wrapper with ESC support and styled prompt."""
    from prompt_toolkit.formatted_text import ANSI

    # ANSI escape codes for colors
    if style_str == "violet":
        prompt_ansi = "\033[32m●\033[0m You: "  # Green circle
    elif style_str == "white":
        prompt_ansi = "\033[37m●\033[0m "  # White circle
    else:
        prompt_ansi = prompt_text

    try:
        result = prompt(ANSI(prompt_ansi), key_bindings=kb, bottom_toolbar=bottom_toolbar, **kwargs)
        if result == '__ESC__':
            console.print("\n[yellow]Cancelled[/]")
            return None
        return result
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled[/]")
        return None

def cmd_help():
    console.print(Panel(
        "[cyan]/chat[/] [dim]or[/] [yellow]/c[/]     - Stream chat with LLM\n"
        "[cyan]/prompt[/] [dim]or[/] [yellow]/p[/]   - Manage system prompts\n"
        "[cyan]/rules[/]                   - Manage behavioral rules\n"
        "[cyan]/trigger[/]                 - Manage BLV triggers\n"
        "[cyan]/import[/] [dim]or[/] [yellow]/i[/]   - Import Burp XML requests\n"
        "[cyan]/tables[/] [table]          - Show DB tables (interactive)\n"
        "[cyan]/model[/]                   - Switch LLM model\n"
        "[cyan]/clear[/]                   - Start new conversation\n"
        "[cyan]/resume[/]                  - Switch to previous conversation\n"
        "[cyan]/prune[/]                   - Delete empty conversations\n"
        "[cyan]/cost[/]                    - Display LiteLLM cost analytics\n"
        "[cyan]/stats[/] [dim]or[/] [yellow]/s[/]    - Display usage stats\n"
        "[cyan]/cls[/]                     - Clear screen\n"
        "[cyan]/menu[/]                    - Interactive menu (findings)\n"
        "[cyan]/help[/] [dim]or[/] [yellow]/h[/]     - Show this help\n"
        "[cyan]/quit[/] [dim]or[/] [yellow]/q[/]     - Exit CLI\n\n"
        "[dim]💡 Press Shift+TAB for autocomplete | TAB to toggle thinking[/]",
        title="[bold green]BLV Commands[/]",
        border_style="cyan"
    ))

def cmd_chat():
    console.clear()
    chat_history = InMemoryHistory()

    # Show token usage at start
    current_tokens = db.get_conversation_tokens(db.get_current_conversation())
    percentage = (current_tokens / 200000) * 100
    bar_length = 20
    filled = int((current_tokens / 200000) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)

    # Estimate cost (using Haiku 4.5 pricing: $1/1M input, $5/1M output)
    # Rough estimate: 75% input, 25% output
    input_tokens = int(current_tokens * 0.75)
    output_tokens = int(current_tokens * 0.25)
    cost_usd = (input_tokens / 1_000_000 * 1.0) + (output_tokens / 1_000_000 * 5.0)
    cost_eur = cost_usd * 0.95  # ~1 USD = 0.95 EUR

    # Get current model
    current_model = format_model(os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929"))

    # Show prompt tokens with cost estimate
    prompt_info = ""
    if llm.LAST_PROMPT_TOKENS > 0:
        # Get input price based on model
        model_name = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929").lower()
        if "haiku" in model_name:
            input_price_per_m = 0.25
        elif "opus" in model_name:
            input_price_per_m = 15.0
        else:  # sonnet
            input_price_per_m = 3.0

        prompt_cost_usd = (llm.LAST_PROMPT_TOKENS / 1_000_000) * input_price_per_m
        prompt_cost_eur = prompt_cost_usd * 0.95
        prompt_info = f"Prompt: {llm.LAST_PROMPT_TOKENS/1000:.1f}k (~€{prompt_cost_eur:.4f}) | "

    console.print(f"Model: [cyan]{current_model}[/] | {prompt_info}Tokens: {current_tokens:,}/200,000 [{bar}] {percentage:.1f}% | €{cost_eur:.4f}\n")

    # Show existing conversation history
    history = db.get_history(limit=999)
    if history:
        console.print("[dim]--- Previous messages ---[/]")
        for h in history:
            if h["role"] == "user":
                console.print(f"[green]●[/] You: {h['content'][:100]}{'...' if len(h['content']) > 100 else ''}")
            else:
                console.print(f"[white]●[/] {h['content'][:100]}{'...' if len(h['content']) > 100 else ''}")
        console.print("[dim]--- Continue chatting ---[/]\n")

    while True:
        try:
            # Reload history each iteration (handles /resume switch)
            hist = [{"role": h["role"], "content": h["content"]} for h in db.get_history()]

            msg = safe_prompt("", style_str="violet", history=chat_history, completer=completer)
            if msg is None:
                console.print("\n[yellow]Back to main[/]")
                break
            msg = sanitize_text(msg)
            if not msg.strip():
                continue

            # Intercept all commands before sending to LLM
            if msg.strip().startswith("/"):
                cmd = msg.strip().lower()

                if cmd == "/back":
                    break
                elif cmd in ["/q", "/quit"]:
                    console.print("\n[yellow]Back to main[/]")
                    break
                elif cmd == "/cls":
                    console.clear()
                    continue
                elif cmd == "/clear":
                    console.clear()
                    name = safe_input("New conversation name (or Enter for auto): ")
                    if name is None:
                        continue
                    name = name.strip()
                    conv_id = db.create_conversation(name if name else None)
                    db.set_current_conversation(conv_id)
                    chat_history = InMemoryHistory()
                    console.print("[green]🗑️ Nouvelle conversation[/]\n")
                    continue
                elif cmd == "/cost":
                    cmd_cost()
                    continue
                elif cmd in ["/stats", "/s"]:
                    cmd_stats()
                    continue
                elif cmd in ["/help", "/h"]:
                    cmd_help()
                    continue
                elif cmd.startswith("/prompt") or cmd.startswith("/p "):
                    parts = cmd.split(maxsplit=2)
                    if len(parts) == 1:
                        cmd_prompts()
                    elif parts[1] == "add" and len(parts) == 3:
                        content = questionary.text("Prompt content (or Ctrl+C to cancel):").ask()
                        if content:
                            db.add_prompt(parts[2], content)
                            console.print(f"[green]✓ Prompt '{parts[2]}' added[/]")
                    elif parts[1] == "edit" and len(parts) == 3:
                        prompts = db.get_prompts(active_only=False)
                        existing = next((p for p in prompts if p['name'] == parts[2]), None)
                        if existing:
                            content = questionary.text("New content:", default=existing['content']).ask()
                            if content:
                                db.update_prompt(parts[2], content)
                                console.print(f"[green]✓ Prompt '{parts[2]}' updated[/]")
                        else:
                            console.print(f"[red]Prompt '{parts[2]}' not found[/]")
                    elif parts[1] == "del" and len(parts) == 3:
                        db.delete_prompt(parts[2])
                        console.print(f"[green]✓ Prompt '{parts[2]}' deleted[/]")
                    elif parts[1] == "toggle" and len(parts) == 3:
                        db.toggle_prompt(parts[2])
                        console.print(f"[green]✓ Prompt '{parts[2]}' toggled[/]")
                    else:
                        console.print("[red]Usage: /prompt [add|edit|del|toggle] <name>[/]")
                    continue
                elif cmd == "/model":
                    cmd_model()
                    continue
                elif cmd == "/resume":
                    cmd_resume()
                    # After resume, reload history
                    hist = [{"role": h["role"], "content": h["content"]} for h in db.get_history()]
                    continue
                elif cmd == "/prune":
                    cmd_prune()
                    continue
                elif cmd == "/menu":
                    action = questionary.select(
                        "Menu BLV",
                        choices=[
                            "📝 Analyser les requêtes",
                            "🎯 Proposer des tests",
                            "📊 Voir events",
                            "🔍 Chercher pattern",
                            "← Retour"
                        ],
                        style=custom_style
                    ).ask()

                    if action and "Analyser" in action:
                        msg = "analyse les requêtes et trouve des vulnérabilités potentielles"
                        console.print(f"\n[dim]Auto: {msg}[/]\n")
                        # Sortir du if pour relancer stream
                    elif action and "Proposer" in action:
                        msg = "propose moi des tests BLV à faire sur ce flow"
                        console.print(f"\n[dim]Auto: {msg}[/]\n")
                        # Sortir du if pour relancer stream
                    elif action and "events" in action:
                        events = db.get_events(limit=50)
                        if events:
                            table = Table(title="Events", border_style="cyan")
                            table.add_column("ID", width=5)
                            table.add_column("Pattern", style="yellow")
                            table.add_column("Status", width=8)
                            table.add_column("Target")
                            for e in events:
                                status = "[green]✓[/]" if e['worked'] else "[red]✗[/]"
                                table.add_row(str(e['id']), e['pattern'], status, e.get('target', '-'))
                            console.print(table)
                        else:
                            console.print("[yellow]Aucun event[/]")
                        continue
                    elif action and "Chercher" in action:
                        keyword = questionary.text("Chercher :").ask()
                        if keyword:
                            events = db.search_events(keyword)
                            if events:
                                for e in events:
                                    status = "✓" if e['worked'] else "✗"
                                    console.print(f"[cyan]{status}[/] {e['pattern']} ({e.get('target', '-')})")
                            else:
                                console.print("[yellow]Aucun résultat[/]")
                        continue
                    else:  # Retour
                        continue
                else:
                    console.print(f"[red]Unknown command: {cmd}. Type /help[/]")
                    continue

            # Check token limit before sending
            current_tokens = db.get_conversation_tokens(db.get_current_conversation())
            if current_tokens >= 200000:
                console.print("\n[red]⚠️  Token limit reached (200k). Use /clear for new conversation.[/]")
                continue

            console.print()
            response = ""
            status_spinner = None
            first_content = True

            try:
                for chunk_type, chunk_content in chat_stream(msg, hist, THINKING_ENABLED):
                    if chunk_type == "thinking":
                        if not status_spinner:
                            status_spinner = console.status("[orange1 italic]Thinking...", spinner="dots")
                            status_spinner.start()
                    elif chunk_type == "tool":
                        # Afficher l'appel tool avec style
                        console.print(f"\n[dim cyan]🔧 {chunk_content}[/]")
                    elif chunk_type == "content":
                        if status_spinner:
                            status_spinner.stop()
                            status_spinner = None
                        if first_content:
                            console.print("[white]●[/] ", end="")
                            first_content = False
                        response += chunk_content
                        console.print(chunk_content, end="", soft_wrap=True)
            except Exception as e:
                if status_spinner:
                    status_spinner.stop()
                console.print(f"\n[red]✗ Error: {str(e)}[/]")
                if "rate limit" in str(e).lower() or "usage limit" in str(e).lower():
                    console.print("[yellow]💡 API limit reached. Try different model with /model[/]")
                continue

            if status_spinner:
                status_spinner.stop()
            console.print("\n")

            # Show token usage
            new_tokens = db.get_conversation_tokens(db.get_current_conversation())
            percentage = (new_tokens / 200000) * 100
            bar_length = 20
            filled = int((new_tokens / 200000) * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)

            # Estimate cost
            input_tokens = int(new_tokens * 0.75)
            output_tokens = int(new_tokens * 0.25)
            cost_usd = (input_tokens / 1_000_000 * 1.0) + (output_tokens / 1_000_000 * 5.0)
            cost_eur = cost_usd * 0.95

            # Get current model
            current_model = format_model(os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929"))

            # Show prompt tokens with cost estimate
            prompt_info = ""
            if llm.LAST_PROMPT_TOKENS > 0:
                # Calcul cache %
                cache_pct = (llm.LAST_CACHE_READ_TOKENS / llm.LAST_PROMPT_TOKENS * 100) if llm.LAST_PROMPT_TOKENS > 0 else 0

                # Get model price
                model_name = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929").lower()
                prices = {"haiku": 0.25, "sonnet": 3.0, "opus": 15.0}
                model_key = "haiku" if "haiku" in model_name else "sonnet" if "sonnet" in model_name else "opus"
                price = prices[model_key]

                # Coût avec cache (cached = 10% du prix)
                cached_tokens = llm.LAST_CACHE_READ_TOKENS
                uncached_tokens = llm.LAST_PROMPT_TOKENS - cached_tokens
                prompt_cost_usd = ((uncached_tokens * price) + (cached_tokens * price * 0.1)) / 1_000_000
                prompt_cost_eur = prompt_cost_usd * 0.95

                prompt_info = f"Prompt: {llm.LAST_PROMPT_TOKENS/1000:.1f}k ({cache_pct:.0f}% cached ~€{prompt_cost_eur:.4f}) | "

            console.print(f"Model: [cyan]{current_model}[/] | {prompt_info}Tokens: {new_tokens:,}/200,000 [{bar}] {percentage:.1f}% | €{cost_eur:.4f}")

            # Menu résultat après payload
            if detect_payload_shown(response):
                result = questionary.select(
                    "Résultat du test ?",
                    choices=["✓ Bypass (vulnérable)", "✗ Bloqué", "⏭ Skip"],
                    style=custom_style
                ).ask()

                if result and "Bypass" in result:
                    msg = "ça bypass, c'est vulnérable"
                    console.print(f"\n[dim]Auto: {msg}[/]\n")
                    continue
                elif result and "Bloqué" in result:
                    msg = "bloqué, ça marche pas"
                    console.print(f"\n[dim]Auto: {msg}[/]\n")
                    continue

        except KeyboardInterrupt:
            console.print("\n[yellow]Back to main[/]")
            break
        except EOFError:
            console.print("\n[yellow]Back to main[/]")
            break

def cmd_prompts():
    """Manage system prompts."""
    prompts = db.get_prompts(active_only=False)

    if not prompts:
        console.print("[yellow]No prompts. Use /prompt add[/]")
        return

    table = Table(title="System Prompts", border_style="cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Active", width=8)
    table.add_column("Priority", width=8)
    table.add_column("Size", width=10)

    for p in prompts:
        active = "[green]✓[/]" if p['active'] else "[dim]✗[/]"
        size = f"{len(p['content'])} chars"
        table.add_row(p["name"], active, str(p["priority"]), size)

    console.print(table)

    # Interactive menu
    action = questionary.select(
        "Action:",
        choices=[
            "➕ Ajouter prompt",
            "✏️  Éditer prompt",
            "🗑️  Supprimer prompt",
            "🔄 Toggle prompt",
            "← Retour"
        ],
        style=custom_style
    ).ask()

    if action and "Ajouter" in action:
        name = questionary.text("Nom du prompt:").ask()
        if not name:
            return
        content = questionary.text("Contenu (ou Ctrl+C annuler):").ask()
        if content:
            db.add_prompt(name, content)
            console.print(f"[green]✓ Prompt '{name}' ajouté[/]")
            cmd_prompts()

    elif action and "Éditer" in action:
        choices = [p['name'] for p in prompts]
        selected = questionary.select("Quel prompt éditer ?", choices=choices, style=custom_style).ask()
        if selected:
            existing = next((p for p in prompts if p['name'] == selected), None)
            if existing:
                content = questionary.text("Nouveau contenu:", default=existing['content']).ask()
                if content:
                    db.update_prompt(selected, content)
                    console.print(f"[green]✓ Prompt '{selected}' mis à jour[/]")
                    cmd_prompts()

    elif action and "Supprimer" in action:
        choices = [p['name'] for p in prompts]
        selected = questionary.select("Quel prompt supprimer ?", choices=choices, style=custom_style).ask()
        if selected:
            confirm = questionary.confirm(f"Supprimer '{selected}' ?").ask()
            if confirm:
                db.delete_prompt(selected)
                console.print(f"[green]✓ Prompt supprimé[/]")
                cmd_prompts()

    elif action and "Toggle" in action:
        choices = [f"{p['name']} ({'✓' if p['active'] else '✗'})" for p in prompts]
        selected = questionary.select("Quel prompt toggle ?", choices=choices, style=custom_style).ask()
        if selected:
            name = selected.split(" (")[0]
            db.toggle_prompt(name)
            console.print(f"[green]✓ Prompt toggled[/]")
            cmd_prompts()

    elif action and "Retour" in action:
        return

def cmd_add(parts):
    if len(parts) < 3:
        console.print(Panel("[red]Usage: /add NAME CONTENT[/]", border_style="red"))
        return
    name = sanitize_text(parts[1])
    content = sanitize_text(" ".join(parts[2:]))
    try:
        db.add_mindset(name, content)
        console.print(f"[green]✓ Added {name}[/]")
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            console.print(f"[red]✗ '{name}' already exists. Use different name.[/]")
        else:
            console.print(f"[red]✗ Error: {e}[/]")

def parse_burp_request(raw_request):
    """Parse HTTP request to extract headers and body."""
    lines = raw_request.split('\n')
    headers_lines = []
    body_start = 0

    for i, line in enumerate(lines[1:], 1):
        if line.strip() == '':
            body_start = i + 1
            break
        headers_lines.append(line)

    headers = '\n'.join(headers_lines)
    body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
    return headers, body

def parse_burp_xml(filepath):
    """Parse Burp XML file and extract requests."""
    tree = ET.parse(filepath)
    root = tree.getroot()
    requests = []

    for item in root.findall('item'):
        url = item.find('url').text or ''
        method = item.find('method').text or ''
        raw_request = item.find('request').text or ''
        raw_response = item.find('response').text or ''

        headers, body = parse_burp_request(raw_request)

        requests.append({
            'url': url,
            'method': method,
            'headers': headers,
            'body': body.strip(),
            'response': raw_response
        })

    return requests

def cmd_import():
    """Import Burp XML files."""
    path = safe_input('Import XML (drag or paste path): ')
    if path is None:
        return

    path = path.strip().strip('"').strip("'")
    if not path:
        console.print("[yellow]Import cancelled[/]")
        return

    # Convert Windows path to WSL path
    if path.startswith('C:\\') or path.startswith('C:/'):
        path = path.replace('C:\\', '/mnt/c/').replace('C:/', '/mnt/c/').replace('\\', '/')
    elif ':' in path and '\\' in path:
        # Handle other drive letters (D:\, E:\, etc)
        drive = path[0].lower()
        path = f'/mnt/{drive}/' + path[3:].replace('\\', '/')

    if not os.path.exists(path):
        console.print(f"[red]✗ File not found: {path}[/]")
        return

    try:
        requests = parse_burp_xml(path)
        for req in requests:
            db.add_request(req['url'], req['method'], req['headers'], req['body'], req['response'])
        console.print(f"[green]✓ Imported {len(requests)} request(s) from {Path(path).name}[/]")
    except Exception as e:
        console.print(f"[red]✗ Error importing: {e}[/]")

def fetch_available_models():
    """Fetch models from LiteLLM proxy."""
    import requests
    api_base = os.getenv("LITELLM_API_BASE")
    api_key = os.getenv("LITELLM_API_KEY")

    try:
        resp = requests.get(
            f"{api_base}/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5
        )
        if resp.status_code == 200:
            return [m["id"] for m in resp.json().get("data", [])]
    except:
        pass
    return []

def cmd_model():
    """Switch LLM model."""
    current = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929")

    models = fetch_available_models()
    if not models:
        models = ["claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"]

    # Build choices with current marker
    choices = [f"{m} {'✓' if m == current else ''}" for m in models]

    try:
        result = questionary.select(
            "Select LLM Model:",
            choices=choices
        ).ask()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Back to main[/]")
        return

    if not result:
        console.print("[yellow]Back to main[/]")
        return

    # Extract model name (remove ✓ if present)
    selected_model = result.replace(" ✓", "").strip()

    env_path = Path(".env")
    lines = env_path.read_text().splitlines()
    updated = []
    for line in lines:
        if line.startswith("LITELLM_MODEL="):
            updated.append(f"LITELLM_MODEL={selected_model}")
        else:
            updated.append(line)
    env_path.write_text("\n".join(updated) + "\n")

    os.environ["LITELLM_MODEL"] = selected_model
    console.print(f"[green]✓ Switched to {selected_model}[/]")

def cmd_clear():
    """Start new conversation."""
    console.clear()
    name = safe_input("New conversation name (or Enter for auto): ")
    if name is None:
        return

    name = name.strip()
    conv_id = db.create_conversation(name if name else None)
    db.set_current_conversation(conv_id)

    convs = db.get_conversations()
    conv_name = next((c['name'] for c in convs if c['id'] == conv_id), "New")
    console.print(f"[green]✓ Started conversation: {conv_name}[/]")
    console.print("[dim]No previous messages. Start fresh with /chat[/]")

def format_time_ago(created_at):
    """Format timestamp as 'X hours/days ago'."""
    if not created_at:
        return "unknown time"
    try:
        created = datetime.fromisoformat(created_at)
        now = datetime.now()
        delta = now - created

        if delta.days > 0:
            return f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        minutes = delta.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    except:
        return "unknown time"

def cmd_resume():
    """Switch to previous conversation - Claude Code style."""
    convs = db.get_conversations()
    if not convs:
        console.print("[yellow]No conversations yet[/]")
        return

    current_id = db.get_current_conversation()

    # Custom style (green theme)
    custom_style = Style([
        ('qmark', 'fg:#00ff00 bold'),
        ('question', 'bold'),
        ('answer', 'fg:#00ff00 bold'),
        ('pointer', 'fg:#00ff00 bold'),
        ('highlighted', 'fg:#00ff00'),
        ('selected', 'fg:#00ff00'),
    ])

    # Build rich choices
    choices = [Choice(title="[Delete conversations]", value="__DELETE__")]

    for conv in convs:
        msg_count = db.get_conversation_message_count(conv['id'])
        time_ago = format_time_ago(conv['created_at'])
        marker = "❯" if conv['id'] == current_id else " "

        # First message preview if exists
        first_msg = "No prompt"
        if msg_count > 0:
            with db.conn() as c:
                result = c.execute(
                    "SELECT content FROM chat WHERE conversation_id=? ORDER BY id LIMIT 1",
                    (conv['id'],)
                ).fetchone()
                if result and result[0]:
                    first_msg = result[0][:60]

        display = f"{marker} {conv['name']}\n  {time_ago} · {msg_count} messages · {first_msg}"
        choices.append(Choice(title=display, value=conv['id']))

    try:
        result = questionary.select(
            "Resume Session",
            choices=choices,
            style=custom_style,
            instruction="(Use arrows · / to search · Esc to exit)",
            use_shortcuts=True,
            use_indicator=True,
        ).ask()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Back to main[/]")
        return

    if not result:
        console.print("[yellow]Back to main[/]")
        return

    # Handle delete mode
    if result == "__DELETE__":
        # List conversations with numbers
        console.print("\n[bold]Conversations to delete:[/]")
        conv_list = []

        # Add "delete all empty" option
        console.print("[yellow]0[/] - Delete all empty (0 messages)")

        # Add all conversations with index
        for idx, conv in enumerate(convs, start=1):
            msg_count = db.get_conversation_message_count(conv['id'])
            console.print(f"[yellow]{idx}[/] - {conv['name']} ({msg_count} msgs)")
            conv_list.append((idx, conv['id'], msg_count))

        # Get user input
        try:
            selection = safe_input("\nEnter numbers to delete (e.g. 1,2,3 or 1 2 3): ")
            if selection is None:
                console.print("[yellow]Cancelled[/]")
                return
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Cancelled[/]")
            return

        if not selection.strip():
            console.print("[yellow]No selection[/]")
            return

        # Parse input (handle comma or space separated)
        indices = re.findall(r'\d+', selection)

        if not indices:
            console.print("[yellow]Invalid input[/]")
            return

        to_delete = []
        for idx_str in indices:
            idx = int(idx_str)
            if idx == 0:
                # Delete all empty
                to_delete.extend([c['id'] for c in convs if db.get_conversation_message_count(c['id']) == 0])
            elif 1 <= idx <= len(convs):
                to_delete.append(conv_list[idx-1][1])
            else:
                console.print(f"[red]Invalid index: {idx}[/]")

        to_delete = list(set(to_delete))  # Dedupe

        if not to_delete:
            console.print("[yellow]No valid conversations selected[/]")
            return

        # Confirm deletion
        confirm = questionary.confirm(
            f"Delete {len(to_delete)} conversations?"
        ).ask()

        if confirm:
            for conv_id in to_delete:
                db.delete_conversation(conv_id)
            console.print(f"[green]🗑️ Deleted {len(to_delete)} conversations[/]")
        else:
            console.print("[yellow]Cancelled[/]")
        return

    db.set_current_conversation(result)
    conv_name = next((c['name'] for c in convs if c['id'] == result), "Unknown")
    console.print(f"[green]✓ Switched to: {conv_name}[/]")

    # Auto-launch chat
    cmd_chat()

def cmd_prune():
    """Delete all empty conversations."""
    empty = [c for c in db.get_conversations() if db.get_conversation_message_count(c['id']) == 0]
    if not empty:
        console.print("[yellow]No empty conversations found[/]")
        return

    for c in empty:
        db.delete_conversation(c['id'])
    console.print(f"[green]🗑️ {len(empty)} empty conversations deleted[/]")

def format_model(name):
    """Format model name for display."""
    if "sonnet" in name.lower() or "20250929" in name:
        return "Sonnet 4.5"
    if "haiku" in name.lower() or "20251001" in name:
        return "Haiku 4.5"
    if "opus" in name.lower():
        return "Opus 4.1"
    return name

def cmd_cost():
    """Display LiteLLM cost analytics with Rich layout."""
    api_base = os.getenv("LITELLM_API_BASE", "http://89.116.27.88:5000")
    api_key = os.getenv("LITELLM_API_KEY", "sk-admin-key-2024")
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        # Calculate dates
        today = datetime.now().strftime("%Y-%m-%d")
        week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        # Fetch data
        spend_logs = requests.get(f"{api_base}/spend/logs?limit=10", headers=headers, timeout=5).json()

        # Calculate stats
        total_spend = sum(log.get("spend", 0) for log in spend_logs)
        today_spend = sum(log.get("spend", 0) for log in spend_logs if log.get("startTime", "").startswith(today))
        week_spend = sum(log.get("spend", 0) for log in spend_logs)

        # By model stats
        model_stats = {}
        cache_total_tokens = 0
        cache_read_tokens = 0

        for log in spend_logs:
            model = log.get("model", "unknown")
            spend = log.get("spend", 0)
            tokens = log.get("total_tokens", 0)
            cached = log.get("metadata", {}).get("additional_usage_values", {}).get("cache_read_input_tokens", 0)

            if model not in model_stats:
                model_stats[model] = {"spend": 0, "tokens": 0}
            model_stats[model]["spend"] += spend
            model_stats[model]["tokens"] += tokens

            cache_total_tokens += tokens
            cache_read_tokens += cached

        # === HEADER ROW ===
        total_panel = Panel(
            f"[bold green]${total_spend:.4f}[/]",
            title="Total (Last 10)",
            border_style="green"
        )

        today_panel = Panel(
            f"[bold cyan]${today_spend:.4f}[/]",
            title="Today",
            border_style="cyan"
        )

        week_panel = Panel(
            f"[bold yellow]${week_spend:.4f}[/]",
            title="This Week (Last 10)",
            border_style="yellow"
        )

        header_row = Columns([total_panel, today_panel, week_panel], equal=True)

        # === MIDDLE ROW ===
        # By Model Table
        model_table = Table(title="By Model", border_style="cyan")
        model_table.add_column("Model", style="cyan")
        model_table.add_column("Cost", style="green", justify="right")
        model_table.add_column("Tokens", style="yellow", justify="right")

        for model, stats in sorted(model_stats.items(), key=lambda x: x[1]["spend"], reverse=True):
            model_table.add_row(
                format_model(model),
                f"${stats['spend']:.6f}",
                f"{stats['tokens']:,}"
            )

        # Cache Stats Table
        cache_table = Table(title="Cache Stats", border_style="magenta")
        cache_table.add_column("Metric", style="magenta")
        cache_table.add_column("Value", style="green", justify="right")

        cache_percent = (cache_read_tokens / cache_total_tokens * 100) if cache_total_tokens > 0 else 0
        cache_table.add_row("Cached Tokens", f"{cache_read_tokens:,}")
        cache_table.add_row("Total Tokens", f"{cache_total_tokens:,}")
        cache_table.add_row("% Cached", f"{cache_percent:.1f}%")

        middle_row = Columns([Panel(model_table), Panel(cache_table)], equal=True)

        # === BOTTOM ROW ===
        requests_table = Table(title="Last 10 Requests", border_style="blue")
        requests_table.add_column("Time", style="dim")
        requests_table.add_column("Model", style="cyan")
        requests_table.add_column("Tokens", style="yellow", justify="right")
        requests_table.add_column("Cached", style="magenta", justify="right")
        requests_table.add_column("Cost", style="green", justify="right")

        for log in spend_logs[:10]:
            time = log.get("startTime", "")[:16].replace("T", " ")
            model = format_model(log.get("model", "unknown"))
            tokens = log.get("total_tokens", 0)
            cached = log.get("metadata", {}).get("additional_usage_values", {}).get("cache_read_input_tokens", 0)
            cost = log.get("spend", 0)

            requests_table.add_row(
                time,
                model,
                f"{tokens:,}",
                f"{cached:,}",
                f"${cost:.6f}"
            )

        bottom_row = Panel(requests_table, border_style="blue")

        # Display layout
        console.print()
        console.print(header_row)
        console.print()
        console.print(middle_row)
        console.print()
        console.print(bottom_row)
        console.print()

    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Failed to fetch cost data: {e}[/]")
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/]")

def cmd_clean():
    """Nettoie toutes les requêtes HTTP existantes."""
    console.print("[yellow]Nettoyage des requêtes HTTP...[/]")
    count = db.clean_existing_requests()
    console.print(f"[green]✓ {count} requête(s) nettoyée(s)[/]")

def cmd_rules():
    """Gestion des rules comportementales."""
    rules = db.get_rules(active_only=False)

    if not rules:
        console.print("[yellow]Aucune rule comportementale. Usage:[/]")
        console.print('  /rules add "nom_rule"')
        return

    table = Table(title="Règles Comportementales (IA)", border_style="cyan")
    table.add_column("ID", width=5)
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="yellow")
    table.add_column("Priority", width=8)
    table.add_column("Active", width=8)

    for r in rules:
        active = "[green]✓[/]" if r['active'] else "[dim]✗[/]"
        table.add_row(
            str(r['id']),
            r['name'],
            r['description'][:50],
            str(r['priority']),
            active
        )

    console.print(table)

    # Interactive menu
    action = questionary.select(
        "Action:",
        choices=[
            "➕ Ajouter rule",
            "🗑️  Supprimer rule",
            "🔄 Toggle rule",
            "← Retour"
        ],
        style=custom_style
    ).ask()

    if action and "Ajouter" in action:
        description = questionary.text("Description complète:").ask()
        if description:
            name = "_".join(description.split()[:3])
            db.add_rule(name, description)
            console.print(f"[green]✓ Rule '{name}' ajoutée[/]")
            cmd_rules()

    elif action and "Supprimer" in action:
        choices = [f"{r['id']} - {r['name']}" for r in rules]
        selected = questionary.select("Quelle rule supprimer ?", choices=choices, style=custom_style).ask()
        if selected:
            rule_id = int(selected.split(" - ")[0])
            db.delete_rule(rule_id)
            console.print(f"[green]✓ Rule supprimée[/]")
            cmd_rules()

    elif action and "Toggle" in action:
        choices = [f"{r['id']} - {r['name']} ({'✓' if r['active'] else '✗'})" for r in rules]
        selected = questionary.select("Quelle rule toggle ?", choices=choices, style=custom_style).ask()
        if selected:
            rule_id = int(selected.split(" - ")[0])
            db.toggle_rule(rule_id)
            console.print(f"[green]✓ Rule toggled[/]")
            cmd_rules()

    elif action and "Retour" in action:
        return

def cmd_triggers():
    """Gestion des triggers BLV."""
    triggers = db.get_triggers(active_only=False)

    if not triggers:
        console.print("[yellow]Aucun trigger. Usage:[/]")
        console.print('[cyan]/trigger add "nom" "pattern" "response"[/] [category]')
        return

    table = Table(title="Triggers BLV", border_style="magenta")
    table.add_column("ID", width=5)
    table.add_column("Name", style="cyan")
    table.add_column("Pattern", style="yellow")
    table.add_column("Response", style="green")
    table.add_column("Category", width=12)
    table.add_column("Active", width=8)

    for t in triggers:
        active = "[green]✓[/]" if t['active'] else "[dim]✗[/]"
        category = t['category'] if t['category'] else "-"
        table.add_row(
            str(t['id']),
            t['name'],
            t['pattern'][:30],
            t['response'][:30],
            category,
            active
        )

    console.print(table)

    # Interactive menu
    action = questionary.select(
        "Action:",
        choices=[
            "➕ Ajouter trigger",
            "🗑️  Supprimer trigger",
            "🔄 Toggle trigger",
            "← Retour"
        ],
        style=custom_style
    ).ask()

    if action and "Ajouter" in action:
        name = questionary.text("Nom:").ask()
        if not name:
            return
        pattern = questionary.text("Pattern:").ask()
        if not pattern:
            return
        response = questionary.text("Response:").ask()
        if not response:
            return
        category = questionary.text("Category (optionnel):").ask()

        db.add_trigger(name, pattern, response, category if category else None)
        console.print(f"[green]✓ Trigger '{name}' ajouté[/]")
        cmd_triggers()

    elif action and "Supprimer" in action:
        choices = [f"{t['id']} - {t['name']}" for t in triggers]
        selected = questionary.select("Quel trigger supprimer ?", choices=choices, style=custom_style).ask()
        if selected:
            trigger_id = int(selected.split(" - ")[0])
            db.delete_trigger(trigger_id)
            console.print(f"[green]✓ Trigger supprimé[/]")
            cmd_triggers()

    elif action and "Toggle" in action:
        choices = [f"{t['id']} - {t['name']} ({'✓' if t['active'] else '✗'})" for t in triggers]
        selected = questionary.select("Quel trigger toggle ?", choices=choices, style=custom_style).ask()
        if selected:
            trigger_id = int(selected.split(" - ")[0])
            db.toggle_trigger(trigger_id)
            console.print(f"[green]✓ Trigger toggled[/]")
            cmd_triggers()

    elif action and "Retour" in action:
        return

def cmd_tables(table_name=None):
    """Show database tables structure or content."""
    with db.conn() as c:
        if not table_name:
            # Show tables in Rich table with stats
            tables = c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()

            # Filter non-empty tables only
            table_names = []
            for t in tables:
                count = c.execute(f"SELECT COUNT(*) as cnt FROM {t['name']}").fetchone()['cnt']
                if count > 0:
                    table_names.append(t['name'])

            if not table_names:
                console.print("[yellow]Aucune table avec données[/]")
                return

            # Display table list horizontally with row counts
            tables_display = Table(title="[bold cyan]Tables disponibles[/]", border_style="cyan", show_header=True, expand=False)

            # Add each table as a column
            for name in table_names:
                count = c.execute(f"SELECT COUNT(*) as cnt FROM {name}").fetchone()['cnt']
                tables_display.add_column(name, style="yellow", justify="center", width=15)

            # Add row counts in a single row
            counts = [str(c.execute(f"SELECT COUNT(*) as cnt FROM {name}").fetchone()['cnt']) for name in table_names]
            tables_display.add_row(*counts)

            console.print(tables_display)

            # Then interactive selection
            selected = questionary.select(
                "Quelle table explorer ?",
                choices=table_names,
                style=custom_style
            ).ask()

            if selected:
                cmd_tables(selected)
            return
        else:
            # Show table content
            try:
                rows = c.execute(f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT 20").fetchall()

                # Auto-delete empty rows (all NULL except id)
                if rows:
                    empty_ids = []
                    for row in rows:
                        # Check if all columns except 'id' are NULL
                        non_id_values = [row[k] for k in row.keys() if k != 'id']
                        if all(v is None or str(v).strip() == '' for v in non_id_values):
                            empty_ids.append(row['id'])

                    if empty_ids:
                        for empty_id in empty_ids:
                            c.execute(f"DELETE FROM {table_name} WHERE id=?", (empty_id,))
                        c.commit()
                        console.print(f"[dim]🗑️  Auto-deleted {len(empty_ids)} empty row(s)[/dim]")
                        # Re-fetch after deletion
                        rows = c.execute(f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT 20").fetchall()

                # Display table if has rows
                if rows:
                    t = Table(title=f"[bold cyan]{table_name}[/bold cyan] (last 20 rows)", border_style="cyan", show_lines=True)

                    # Add columns dynamically
                    for col in rows[0].keys():
                        t.add_column(col, style="dim" if col in ["id", "created_at"] else "")

                    # Add rows
                    for row in rows:
                        t.add_row(*[str(row[k])[:100] if row[k] else "[dim]-[/]" for k in row.keys()])

                    console.print(t)
                    console.print(f"[dim]Showing {len(rows)} rows (max 20)[/dim]")
                else:
                    console.print(f"[yellow]Table '{table_name}' is empty[/yellow]\n")

                # Interactive menu (always show, even if empty)
                menu_choices = ["➕ Ajouter ligne"]
                if rows:
                    menu_choices.extend(["🔍 Voir détails row", "🗑️  Supprimer lignes"])

                    # Special: Delete all for conversations
                    if table_name == "conversations":
                        menu_choices.append("🗑️  Supprimer TOUT")

                # Special action for requests table: import XML
                if table_name == "requests":
                    menu_choices.insert(1, "📥 Importer Burp XML")

                menu_choices.extend(["📋 Voir structure table", "🔄 Rafraîchir", "← Retour"])

                action = questionary.select("Action:", choices=menu_choices, style=custom_style).ask()

                if action and "Ajouter" in action:
                    # Dynamic form based on table columns
                    cols_info = c.execute(f"PRAGMA table_info({table_name})").fetchall()
                    input_cols = [col for col in cols_info if col['name'] not in ['id', 'created_at']]

                    values = {}
                    for col in input_cols:
                        prompt_text = f"{col['name']}"
                        if col['type']:
                            prompt_text += f" ({col['type']})"
                        if col['dflt_value']:
                            prompt_text += f" [défaut: {col['dflt_value']}]"

                        val = questionary.text(prompt_text + ":").ask()

                        if val:
                            values[col['name']] = val
                        elif col['dflt_value']:
                            values[col['name']] = col['dflt_value']
                        else:
                            if col['notnull'] == 0:
                                values[col['name']] = None
                            else:
                                values[col['name']] = ""

                    # Build INSERT query
                    cols = ", ".join(values.keys())
                    placeholders = ", ".join(["?" for _ in values])
                    query = f"INSERT INTO {table_name} ({cols}) VALUES ({placeholders})"
                    c.execute(query, tuple(values.values()))
                    c.commit()
                    console.print(f"[green]✓ Ligne ajoutée[/]")
                    cmd_tables(table_name)

                elif action and "détails" in action:
                    display_cols = [k for k in rows[0].keys() if k not in ['id', 'created_at']]
                    main_col = display_cols[0] if display_cols else 'name'

                    choices = [f"{dict(row)['id']} - {str(dict(row).get(main_col, ''))[:50]}" for row in rows]
                    selected = questionary.select("Quelle ligne voir ?", choices=choices, style=custom_style).ask()

                    if selected:
                        row_id = int(selected.split(" - ")[0])
                        full_row = next((dict(r) for r in rows if dict(r)['id'] == row_id), None)

                        if full_row:
                            detail_table = Table(title=f"[bold cyan]Row {row_id} - Détails complets[/]", border_style="cyan", show_header=False)
                            detail_table.add_column("Field", style="yellow", width=20)
                            detail_table.add_column("Value", style="white")

                            for key, value in full_row.items():
                                detail_table.add_row(key, str(value) if value else "[dim]NULL[/dim]")

                            console.print(detail_table)
                            questionary.text("Appuyer sur Enter pour continuer...").ask()
                            cmd_tables(table_name)

                elif action and "Supprimer" in action:
                    display_cols = [k for k in rows[0].keys() if k not in ['id', 'created_at']]
                    main_col = display_cols[0] if display_cols else 'name'

                    choices = [f"{dict(row)['id']} - {str(dict(row).get(main_col, ''))[:50]}" for row in rows]
                    selected = questionary.checkbox(
                        "Sélectionner lignes (Espace=cocher, Enter=valider):",
                        choices=choices
                    ).ask()

                    if selected and len(selected) > 0:
                        confirm = questionary.confirm(f"Supprimer {len(selected)} ligne(s) ?").ask()
                        if confirm:
                            for sel in selected:
                                row_id = int(sel.split(" - ")[0])
                                c.execute(f"DELETE FROM {table_name} WHERE id=?", (row_id,))
                            c.commit()
                            console.print(f"[green]✓ {len(selected)} ligne(s) supprimée(s)[/]")
                            cmd_tables(table_name)

                elif action and "TOUT" in action:
                    # Delete all rows in table
                    total = c.execute(f"SELECT COUNT(*) as cnt FROM {table_name}").fetchone()['cnt']
                    confirm = questionary.confirm(f"[red]Supprimer TOUTES les {total} lignes de '{table_name}' ?[/]").ask()
                    if confirm:
                        c.execute(f"DELETE FROM {table_name}")
                        c.commit()
                        console.print(f"[green]✓ {total} ligne(s) supprimée(s)[/]")
                        cmd_tables(table_name)

                elif action and "Importer" in action:
                    cmd_import()
                    cmd_tables(table_name)

                elif action and "structure" in action:
                    cols = c.execute(f"PRAGMA table_info({table_name})").fetchall()
                    struct_table = Table(title=f"[bold cyan]Structure: {table_name}[/]", border_style="cyan")
                    struct_table.add_column("Column", style="yellow")
                    struct_table.add_column("Type", style="cyan")
                    struct_table.add_column("Constraints", style="green")

                    for col in cols:
                        constraints = []
                        if col['pk']: constraints.append("PK")
                        if col['notnull']: constraints.append("NOT NULL")
                        if col['dflt_value']: constraints.append(f"DEFAULT {col['dflt_value']}")
                        struct_table.add_row(col['name'], col['type'], " ".join(constraints))

                    console.print(struct_table)
                    questionary.text("Appuyer sur Enter pour continuer...").ask()
                    cmd_tables(table_name)

                elif action and "Rafraîchir" in action:
                    cmd_tables(table_name)

                elif action and "Retour" in action:
                    cmd_tables()  # Return to table selection menu

            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

def cmd_stats():
    reqs = len(db.get_requests())
    minds = len(db.get_mindsets())
    msgs = len(db.get_history(999))
    convs = len(db.get_conversations())

    table = Table(show_header=False, border_style="cyan")
    table.add_column("Metric", style="cyan", width=15)
    table.add_column("Value", style="green")
    table.add_row("Requests", str(reqs))
    table.add_row("Mindsets", str(minds))
    table.add_row("Messages", str(msgs))
    table.add_row("Conversations", str(convs))

    console.print(Panel(table, title="[bold]Statistics[/]", border_style="green"))

def get_footer():
    """Generate footer with shortcuts."""
    return Text.from_markup(
        "[cyan]/c[/] Chat  [cyan]/p[/] Prompts  [cyan]/i[/] Import  [cyan]/s[/] Stats  "
        "[cyan]/h[/] Help  [cyan]/q[/] Quit  [dim]| TAB = autocomplete[/]"
    )

def main():
    console.print(Panel(
        "[bold cyan]BLV CLI[/] - Pentest Copilot\n\n"
        "[cyan]/c[/] or [cyan]/chat[/]     - Stream chat with LLM\n"
        "[cyan]/p[/] or [cyan]/prompt[/]   - Manage system prompts\n"
        "[cyan]/i[/] or [cyan]/import[/]   - Import Burp XML requests\n"
        "[cyan]/model[/]                   - Switch LLM model\n"
        "[cyan]/cls[/]                     - Clear screen (visual only)\n"
        "[cyan]/clear[/]                   - Start new conversation\n"
        "[cyan]/resume[/]                  - Switch to previous conversation\n"
        "[cyan]/prune[/]                   - Delete all empty conversations\n"
        "[cyan]/cost[/]                    - Display LiteLLM cost analytics\n"
        "[cyan]/s[/] or [cyan]/stats[/]    - Display usage stats\n"
        "[cyan]/h[/] or [cyan]/help[/]     - Show help\n"
        "[cyan]/q[/] or [cyan]/quit[/]     - Exit CLI\n\n"
        "[dim]💡 Press TAB for autocomplete | /back in chat[/]",
        title="[bold green]Welcome[/]",
        border_style="green"
    ))
    console.print()

    while True:
        try:
            # Show footer
            console.print(get_footer(), style="dim")

            cmd = prompt("> ", history=history, completer=completer, complete_while_typing=True, enable_history_search=True)
            cmd = sanitize_text(cmd)
            if not cmd.strip():
                continue

            # Show all commands if just "/"
            if cmd == "/":
                # Print all available commands
                console.print("\n[cyan]Commandes disponibles:[/]")
                for c in sorted(COMMANDS):
                    console.print(f"  {c}", style="yellow")
                console.print("\n[dim]💡 Tapez TAB pour autocomplete interactif[/]\n")
                continue

            # Single letter + long commands
            if cmd in ["/quit", "/q"]:
                console.print("[yellow]Bye! 👋[/]")
                break
            elif cmd in ["/help", "/h"]:
                cmd_help()
            elif cmd in ["/chat", "/c"]:
                cmd_chat()
            elif cmd.startswith("/prompt") or cmd == "/p":
                parts = cmd.split(maxsplit=2)
                if len(parts) == 1 or cmd == "/p":
                    cmd_prompts()
                elif parts[1] == "add" and len(parts) == 3:
                    content = questionary.text("Prompt content (or Ctrl+C to cancel):").ask()
                    if content:
                        db.add_prompt(parts[2], content)
                        console.print(f"[green]✓ Prompt '{parts[2]}' added[/]")
                elif parts[1] == "edit" and len(parts) == 3:
                    prompts = db.get_prompts(active_only=False)
                    existing = next((p for p in prompts if p['name'] == parts[2]), None)
                    if existing:
                        content = questionary.text("New content:", default=existing['content']).ask()
                        if content:
                            db.update_prompt(parts[2], content)
                            console.print(f"[green]✓ Prompt '{parts[2]}' updated[/]")
                    else:
                        console.print(f"[red]Prompt '{parts[2]}' not found[/]")
                elif parts[1] == "del" and len(parts) == 3:
                    db.delete_prompt(parts[2])
                    console.print(f"[green]✓ Prompt '{parts[2]}' deleted[/]")
                elif parts[1] == "toggle" and len(parts) == 3:
                    db.toggle_prompt(parts[2])
                    console.print(f"[green]✓ Prompt '{parts[2]}' toggled[/]")
                else:
                    console.print("[red]Usage: /prompt [add|edit|del|toggle] <name>[/]")
            elif cmd in ["/import", "/i"]:
                cmd_import()
            elif cmd == "/model":
                cmd_model()
            elif cmd == "/cls":
                console.clear()
            elif cmd == "/clear":
                cmd_clear()
            elif cmd == "/resume":
                cmd_resume()
            elif cmd == "/prune":
                cmd_prune()
            elif cmd == "/cost":
                cmd_cost()
            elif cmd == "/clean":
                cmd_clean()
            elif cmd.startswith("/rules"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 1:
                    cmd_rules()
                elif parts[1].startswith("add "):
                    description = parts[1][4:].strip()
                    if description:
                        # Generate name from first 3 words
                        name = "_".join(description.split()[:3])
                        db.add_rule(name, description)
                        console.print(f"[green]✓ Rule '{name}' ajoutée[/]")
                    else:
                        console.print('[red]Usage: /rules add description[/]')
                elif parts[1] == "del":
                    # Interactive deletion
                    rules = db.get_rules(active_only=False)
                    if not rules:
                        console.print("[yellow]Aucune rule à supprimer[/]")
                    else:
                        choices = [f"{r['id']} - {r['name']}" for r in rules]
                        selected = questionary.select("Quelle rule supprimer ?", choices=choices).ask()
                        if selected:
                            rule_id = int(selected.split(" - ")[0])
                            db.delete_rule(rule_id)
                            console.print(f"[green]✓ Rule supprimée[/]")
                elif parts[1].startswith("del "):
                    # Direct deletion by ID or name
                    try:
                        target = parts[1].split(maxsplit=1)[1]
                        db.delete_rule(target)
                        console.print(f"[green]✓ Rule supprimée[/]")
                    except (ValueError, IndexError):
                        console.print("[red]Usage: /rules del <id|nom>[/]")
                elif parts[1] == "toggle":
                    # Interactive toggle
                    rules = db.get_rules(active_only=False)
                    if not rules:
                        console.print("[yellow]Aucune rule[/]")
                    else:
                        choices = [f"{r['id']} - {r['name']} ({'✓' if r['active'] else '✗'})" for r in rules]
                        selected = questionary.select("Quelle rule toggle ?", choices=choices).ask()
                        if selected:
                            rule_id = int(selected.split(" - ")[0])
                            db.toggle_rule(rule_id)
                            console.print(f"[green]✓ Rule toggled[/]")
                elif parts[1].startswith("toggle "):
                    # Direct toggle by ID or name
                    try:
                        target = parts[1].split(maxsplit=1)[1]
                        db.toggle_rule(target)
                        console.print(f"[green]✓ Rule toggled[/]")
                    except (ValueError, IndexError):
                        console.print("[red]Usage: /rules toggle <id|nom>[/]")
                else:
                    # Assume "add" if no subcommand - entire text is the description
                    description = parts[1].strip()
                    # Generate name from first 3 words
                    name = "_".join(description.split()[:3])
                    db.add_rule(name, description)
                    console.print(f"[green]✓ Rule '{name}' ajoutée[/]")
            elif cmd.startswith("/trigger"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 1:
                    cmd_triggers()
                elif parts[1].startswith("add "):
                    import shlex
                    try:
                        args = shlex.split(parts[1][4:])
                        if len(args) >= 3:
                            name = args[0]
                            pattern = args[1]
                            response = args[2]
                            category = args[3] if len(args) > 3 else None
                            db.add_trigger(name, pattern, response, category)
                            console.print(f"[green]✓ Trigger '{name}' ajouté[/]")
                        else:
                            console.print('[red]Usage: /trigger add "nom" "pattern" "response" [category][/]')
                    except ValueError as e:
                        console.print(f"[red]Parsing error: {e}[/]")
                        console.print('[red]Usage: /trigger add "nom" "pattern" "response" [category][/]')
                elif parts[1].startswith("del "):
                    try:
                        target = parts[1].split(maxsplit=1)[1]
                        db.delete_trigger(target)
                        console.print(f"[green]✓ Trigger supprimé[/]")
                    except (ValueError, IndexError):
                        console.print("[red]Usage: /trigger del <id|nom>[/]")
                elif parts[1].startswith("toggle "):
                    try:
                        target = parts[1].split(maxsplit=1)[1]
                        db.toggle_trigger(target)
                        console.print(f"[green]✓ Trigger toggled[/]")
                    except (ValueError, IndexError):
                        console.print("[red]Usage: /trigger toggle <id|nom>[/]")
                else:
                    console.print('[red]Usage: /trigger [add|del|toggle] "nom" "pattern" "response"[/]')
            elif cmd in ["/stats", "/s"]:
                cmd_stats()
            elif cmd.startswith("/tables"):
                parts = cmd.split(maxsplit=1)
                table_arg = parts[1] if len(parts) > 1 else None
                cmd_tables(table_arg)
            elif cmd == "/menu":
                action = questionary.select(
                    "Menu BLV",
                    choices=[
                        "💬 Ouvrir chat",
                        "📊 Voir events",
                        "🔍 Chercher event",
                        "📋 Voir rules",
                        "⚡ Voir triggers",
                        "← Retour"
                    ]
                ).ask()

                if action and "chat" in action:
                    cmd_chat()
                elif action and "events" in action:
                    events = db.get_events(limit=50)
                    if events:
                        table = Table(title="Events", border_style="cyan")
                        table.add_column("ID", width=5)
                        table.add_column("Pattern", style="yellow")
                        table.add_column("Status", width=8)
                        table.add_column("Target")
                        for e in events:
                            status = "[green]✓[/]" if e['worked'] else "[red]✗[/]"
                            table.add_row(str(e['id']), e['pattern'], status, e.get('target', '-'))
                        console.print(table)
                    else:
                        console.print("[yellow]Aucun event[/]")
                elif action and "Chercher" in action:
                    keyword = questionary.text("Mot-clé :").ask()
                    if keyword:
                        events = db.search_events(keyword)
                        if events:
                            for e in events:
                                status = "✓" if e['worked'] else "✗"
                                console.print(f"[cyan]{status}[/] {e['pattern']} ({e.get('target', '-')})")
                        else:
                            console.print("[yellow]Aucun résultat[/]")
                elif action and "rules" in action:
                    cmd_rules()
                elif action and "triggers" in action:
                    cmd_triggers()
            else:
                console.print("[red]Unknown command. Type /help or /h[/]")

        except KeyboardInterrupt:
            console.print("\n[yellow]Bye! 👋[/]")
            break
        except EOFError:
            break

if __name__ == "__main__":
    main()
