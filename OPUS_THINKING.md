# Claude Opus 4.5 + Extended Thinking

## Opus 4.5 - Most Intelligent Model

**Model ID:** `claude-opus-4-5-20251101`
**Released:** Nov 24, 2025
**Pricing:** $5 input / $25 output per million tokens
**Context:** 200K window
**Extended Thinking:** ✓ Up to 64K tokens

### vs Sonnet 4.5

- **Intelligence:** Opus > Sonnet (frontier reasoning)
- **Speed:** Sonnet > Opus
- **Cost:** Opus 3x more than Sonnet ($5 vs $3 input)
- **Use Cases:**
  - Opus: Complex analysis, deep reasoning, agentic tasks
  - Sonnet: Balanced daily use, fast iterations

---

## Extended Thinking Mode

Extended thinking allows Claude to "think" before responding, improving:
- Complex reasoning
- Multi-step problem solving
- Code analysis
- Security research
- Pattern identification

### Thinking Budgets

| Budget | Tokens | Use Case |
|--------|--------|----------|
| **None** | 0 | Disabled (default) |
| **Quick** | 4K | Fast tasks, simple questions |
| **Normal** | 16K | Balanced (recommended) |
| **Deep** | 32K | Complex analysis |
| **Ultra** | 64K | Maximum reasoning |

### Cost Impact

**Example: Normal budget (16K) + Opus 4.5**

Input (with thinking):
- Prompt: 5K tokens @ $5/M = $0.025
- Thinking: 16K tokens @ $5/M = $0.080
- **Total input: ~$0.105**

Output:
- Response: 2K tokens @ $25/M = $0.050

**Total per request: ~$0.155** (vs $0.040 without thinking)

---

## Usage

### 1. Switch to Opus 4.5

```bash
/model
```
→ Select "Opus 4.5 (Most Intelligent - NEW!)"

### 2. Configure Thinking Budget

```bash
/thinking
```
→ Choose budget level

### 3. Chat

```bash
/chat
```

**Example output:**
```
● You: Analyse cette vulnérabilité XSS complexe

∴ Thinking... (spinner pendant thinking)
∴ Thought for 8s

● Claude répond avec analyse approfondie...
```

---

## When to Use Thinking Mode

### ✅ Good Use Cases

- **Complex BLV analysis:** Multi-step bypass chains
- **Pattern discovery:** Identifying subtle vulnerabilities
- **Code review:** Deep security analysis
- **Attack planning:** Sophisticated test scenarios
- **Research:** Understanding novel techniques

### ❌ Not Worth It

- Simple questions ("que faire maintenant?")
- Quick confirmations
- Already-clear payloads
- Repetitive tasks
- Fast iterations

---

## Tips

### Maximize Value

1. **Batch questions:** Ask complex, multi-part questions
2. **Context-rich:** Provide full details upfront
3. **Specific goals:** "Find ALL possible bypasses for..."
4. **Deep analysis:** Request step-by-step reasoning

### Minimize Cost

1. Use **Quick** (4K) for normal tasks
2. **Deep/Ultra** only for genuinely complex problems
3. Switch to **Sonnet** for iterations
4. Disable thinking (`/thinking` → None) when not needed

### Workflow Example

```bash
# Initial deep analysis with Opus + Ultra thinking
/model → Opus 4.5
/thinking → Ultra (64K)
/chat
> Analyse complète de ce flow 3DS avec tous les vecteurs

∴ Thought for 15s
[Detailed analysis with 8 attack vectors]

# Fast iterations with Sonnet
/model → Sonnet 4.5
/thinking → None
/chat
> Teste payload 3 maintenant
[Quick response]
```

---

## Troubleshooting

### Thinking not showing

1. Check budget: `/thinking` → Ensure not "None"
2. Check model: Only Claude models support thinking
3. Verify `.env`: `THINKING_MODE=normal` or higher

### Timeout errors

Extended thinking can take 30-60s. If timeouts:
- Timeout set to 120s (should be enough)
- Reduce budget: Ultra → Deep → Normal
- Check VPS LiteLLM logs

### Cost too high

Monitor with `/cost` and adjust:
- **High cost?** → Reduce budget or switch to Sonnet
- **Need quality?** → Keep Opus but use Quick (4K)
- **Iterations?** → Sonnet without thinking

---

## Configuration

**.env:**
```bash
LITELLM_MODEL=claude-opus-4-5-20251101
THINKING_MODE=normal  # none, quick, normal, deep, ultra
```

**Check current:**
```bash
/model   # Shows current model
/thinking  # Shows current budget (✓ marker)
```

---

## Model Comparison

| Model | Input $/M | Output $/M | Speed | Intelligence | Thinking |
|-------|-----------|------------|-------|--------------|----------|
| **Opus 4.5** | $5 | $25 | Slow | ★★★★★ | ✓ 64K |
| Opus 4.1 | $15 | $75 | Slow | ★★★★☆ | ✓ 64K |
| **Sonnet 4.5** | $3 | $15 | Fast | ★★★★☆ | ✓ 64K |
| Haiku 4.5 | $0.25 | $1.25 | Fastest | ★★★☆☆ | ✓ 64K |

**Recommendation:** Opus 4.5 + Normal (16K) for BLV research
