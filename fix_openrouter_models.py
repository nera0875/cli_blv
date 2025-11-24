#!/usr/bin/env python3
"""Fix OpenRouter models in LiteLLM proxy - remove openrouter/ prefix from litellm_params.model"""
import requests

API_BASE = "http://89.116.27.88:5000"
API_KEY = "sk-xHID9OmFQt_Bqe712cYi2w"

headers = {"Authorization": f"Bearer {API_KEY}"}

# 1. Get all models
print("📡 Fetching models from LiteLLM proxy...")
response = requests.get(f"{API_BASE}/model/info", headers=headers)
models = response.json().get("data", [])

print(f"Found {len(models)} models\n")

# Check OpenRouter models
openrouter_models = []
for model in models:
    model_name = model.get("model_name")
    litellm_params = model.get("litellm_params", {})
    internal_model = litellm_params.get("model", "")
    model_id = model.get("model_info", {}).get("id")

    if model_name and model_name.startswith("openrouter/"):
        print(f"📋 {model_name}")
        print(f"   ID: {model_id}")
        print(f"   litellm_params.model = {internal_model}")

        if internal_model.startswith("openrouter/"):
            print(f"   ❌ NEEDS FIX (has openrouter/ prefix)")

            # Store full model config for update
            fixed_litellm_params = litellm_params.copy()
            fixed_litellm_params["model"] = internal_model.replace("openrouter/", "", 1)

            openrouter_models.append({
                "id": model_id,
                "name": model_name,
                "current": internal_model,
                "fixed": internal_model.replace("openrouter/", "", 1),
                "model_info": model.get("model_info"),
                "litellm_params": fixed_litellm_params
            })
        else:
            print(f"   ✅ OK")
        print()

if not openrouter_models:
    print("✅ All OpenRouter models already correct!")
    exit(0)

print(f"\n{'='*60}")
print(f"Found {len(openrouter_models)} models to fix\n")

for m in openrouter_models:
    print(f"🔧 {m['name']}")
    print(f"   {m['current']} → {m['fixed']}")

print(f"\n{'='*60}\n")

# Apply fixes using LiteLLM Admin UI API
print("\n🔧 Applying fixes...\n")

for m in openrouter_models:
    try:
        # Update model via /model/update with full config
        update_data = {
            "model_info": m["model_info"],
            "litellm_params": m["litellm_params"]
        }

        response = requests.post(
            f"{API_BASE}/model/update",
            headers={**headers, "Content-Type": "application/json"},
            json=update_data
        )

        if response.status_code == 200:
            print(f"✅ Fixed {m['name']}")
        else:
            print(f"❌ Error {m['name']}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Exception {m['name']}: {e}")

print(f"\n{'='*60}")
print("✅ Done! Test with /chat in CLI")
print(f"{'='*60}")
