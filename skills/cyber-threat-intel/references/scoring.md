# Threat Scoring

Multi-dimensional model. The structured weights live in [../spec.yaml](../spec.yaml) under `threat_scoring_engine`; this file is the human-readable explanation.

## Formula

```
score = (exploitability · 0.25) + (impact · 0.25) + (relevance · 0.30) + (urgency · 0.20)
```

## Dimensions

### Exploitability (weight 0.25)
| Factor | Levels |
|--------|--------|
| `exploit_maturity` | none=0, poc=40, weaponized=70, in_the_wild=100 |
| `attack_complexity` | high=20, medium=50, low=100 |
| `privileges_required` | high=20, low=50, none=100 |

### Impact (weight 0.25)
| Factor | Levels |
|--------|--------|
| `confidentiality` | none=0, low=33, high=100 |
| `integrity` | none=0, low=33, high=100 |
| `availability` | none=0, low=33, high=100 |

### Relevance (weight 0.30)
| Factor | Levels |
|--------|--------|
| `sector_targeting` | no=0, possible=50, confirmed=100 |
| `technology_match` | no=0, partial=50, exact=100 |
| `geographic_targeting` | no=0, possible=50, confirmed=100 |

### Urgency (weight 0.20)
| Factor | Levels |
|--------|--------|
| `active_exploitation` | none=0, targeted=70, widespread=100 |
| `trend_direction` | decreasing=20, stable=50, increasing=100 |
| `time_sensitivity` | months=20, weeks=50, days=80, hours=100 |

## Priority Mapping

| Score Range | Priority    | Suggested Response |
|-------------|-------------|--------------------|
| 90–100      | P1-CRITICAL | 0–4 hours          |
| 75–89       | P2-HIGH     | 4–24 hours         |
| 50–74       | P3-MEDIUM   | 1–7 days           |
| 25–49       | P4-LOW      | 7–30 days          |
| 0–24        | P5-INFO     | Awareness only     |
