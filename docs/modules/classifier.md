# Module: `classifier`

**Purpose:** say what the observed evidence *is* (an analytics cookie, a
marketing pixel, a consent banner with accept and reject) without saying
whether it is lawful. Pure: Evidence Bundle + knowledge base → `Classification`.

Entry point: `classifier.classify.classify(bundle, kb=None) -> Classification`.

## Components

| File | Responsibility |
|---|---|
| `knowledge.py` | Loads and validates `data/*.yaml` and the pinned Open Cookie Database CSV; exact/prefix/regex name index; host-suffix index with optional path prefix; lexicon; SHA-256 of all data (ADR-0013) |
| `classify.py` | Cookies, Web Storage and third-party contacts per session; CMP detection; banner detection and control roles |
| `data/cookies.yaml` | Curated cookie/storage-key vendors with category, exemption overrides and documentation URLs |
| `data/trackers.yaml` | Curated third-party hosts (self-authored; see licence note in ADR-0013) |
| `data/cmp.yaml` | CMP signatures and consent-record cookies |
| `data/consent_lexicon.yaml` | FR/EN/ES/DE banner terms and button phrases; subscribe/login stems for "pay or consent" walls |
| `data/third_party/` | Open Cookie Database snapshot + its Apache-2.0 licence |

## Output (`domain/classification.py`)

- `ClassifiedCookie` / `ClassifiedStorageKey`: party (first/third by eTLD+1)
  and a `KnowledgeMatch`: category, vendor, `Exemption`
  (exempt/conditional/not_exempt/unknown), note, `source` (curated, OCD, none)
  and source reference.
- `ThirdPartyContact`: requests grouped by (site, vendor, category), first
  request time, resource types, up to three sample URLs, and `beacon_like`
  (ping/beacon, POST xhr/fetch, or image with a query string), a signal used
  only for unclassified sites.
- `CmpDetection`: CMP name and the signals that identified it.
- `BannerDetection`: the selected layer, its controls with roles
  (accept/reject/settings/close/subscribe/other), CMP, and confidence.
- `banner_evidence_captured`: false for bundles without a consent-UI snapshot.

## Banner detection

1. A layer is a candidate only if a control is in the first viewport and
   either (a) consent wording (lexicon banner terms, matched at word starts)
   appears in the layer's **own text, excluding control labels**, or (b) its
   element hint or frame host matches a CMP signature.
2. Control roles come from **exact** normalised label matches (accept,
   reject, settings, close), then subscribe stems. "Continuer sans accepter"
   is a reject phrase, not an accept.
3. Score: CMP 4, accept 3, reject 2, fixed/dialog/frame 1, consent wording 1.
   Ties go to the larger layer.
4. Confidence: **high** = CMP container with a recognised accept/reject;
   **medium** = consent wording with a recognised accept/reject; **low** = no
   recognised accept/reject (unknown language, unusual wording). Rules turn
   low-confidence banners into review, never into verdicts.

## Failure modes

| Situation | Behaviour |
|---|---|
| Malformed data file | `KnowledgeBaseError` at load (CI), never during a scan |
| Cookie/host not in any source | `unknown` → listed for review; never assumed exempt |
| Banner in closed shadow root / canvas / image | Not seen; EP-04 may FAIL with medium confidence, or review if a CMP was loaded |
| Banner language outside FR/EN/ES/DE | Low-confidence banner → review |

## Tests

`tests/unit/test_knowledge.py`, `tests/unit/test_classify.py` (pure, builders
in `tests/builders.py`). Real Chromium in `tests/integration/test_assessment.py`.
