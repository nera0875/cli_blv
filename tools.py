"""Tools pour l'IA - accès bash/fichiers dans le projet."""
import subprocess
import os

PROJECT_DIR = "/home/gesti/projects/cli_blv"
DATA_DIR = os.path.join(PROJECT_DIR, "data")

# Créer data/ si n'existe pas
os.makedirs(DATA_DIR, exist_ok=True)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Exécuter une commande bash dans le dossier projet. Utilise pour grep, cat, echo, ls, awk, sed, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Commande bash à exécuter (ex: grep -r 'bypass' data/, cat data/findings.yaml)"
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_finding",
            "description": "Sauvegarder un pattern BLV testé. Appelle quand user confirme résultat d'un test.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Le pattern testé (ex: state→authorize bypass)"},
                    "worked": {"type": "boolean", "description": "True si vulnérable, False si bloqué"},
                    "target": {"type": "string", "description": "Cible (ex: Cdiscount, PayPal)"},
                    "context": {"type": "string", "description": "Contexte additionnel"}
                },
                "required": ["pattern", "worked"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings",
            "description": "Récupérer les patterns BLV sauvegardés qui ont marché.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Filtrer par keyword (optionnel)"}
                }
            }
        }
    }
]

# Commandes bash autorisées (sécurité)
ALLOWED_COMMANDS = ['grep', 'cat', 'echo', 'ls', 'head', 'tail', 'awk', 'sed', 'wc', 'find', 'sort', 'uniq']

def execute_tool(name: str, args: dict) -> str:
    """Exécuter un tool et retourner le résultat."""
    
    if name == "bash":
        command = args.get("command", "")
        
        # Sécurité: vérifier commande autorisée
        first_cmd = command.split()[0] if command.split() else ""
        if first_cmd not in ALLOWED_COMMANDS:
            return f"❌ Commande '{first_cmd}' non autorisée. Autorisées: {', '.join(ALLOWED_COMMANDS)}"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout + result.stderr
            return output if output.strip() else "(no output)"
        except subprocess.TimeoutExpired:
            return "❌ Timeout (10s)"
        except Exception as e:
            return f"❌ Error: {e}"
    
    elif name == "save_finding":
        from db import add_finding
        add_finding(
            pattern=args.get("pattern"),
            worked=args.get("worked", True),
            target=args.get("target"),
            context=args.get("context")
        )
        return f"✓ Finding saved: {args.get('pattern')}"
    
    elif name == "get_findings":
        from db import get_findings, search_findings
        search = args.get("search")
        if search:
            findings = search_findings(search)
        else:
            findings = get_findings(worked_only=True, limit=10)
        
        if not findings:
            return "Aucun finding trouvé."
        
        result = []
        for f in findings:
            status = "✓" if f['worked'] else "✗"
            line = f"{status} {f['pattern']}"
            if f.get('target'):
                line += f" ({f['target']})"
            result.append(line)
        return "\n".join(result)
    
    return f"❌ Unknown tool: {name}"
