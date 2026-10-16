# Sources and verification log

Citations used by rules that produce verdicts are checked against the
official source before they are encoded (ADR-0017). This log records what was
checked and when. `verified_on` in `catalog_meta.yaml` is the machine-readable
version, and the loader enforces it.

## Legal instruments (binding)

| Instrument | URL | Checked |
|---|---|---|
| Directive 2002/58/EC (ePrivacy), as amended by 2009/136/EC | https://eur-lex.europa.eu/eli/dir/2002/58/oj · https://eur-lex.europa.eu/eli/dir/2009/136/oj | 2026-10-16 (canonical ELI; EUR-Lex serves a bot check to scripts) |
| Regulation (EU) 2016/679 (GDPR) | https://eur-lex.europa.eu/eli/reg/2016/679/oj | 2026-10-16 |

## Case law and guidance

| Reference | What was checked | Checked |
|---|---|---|
| EDPB Guidelines 2/2023 on Technical Scope of Art. 5(3), v2.0 | Final version, adopted 7 Oct 2024; §3.1 "URL and pixel tracking" (PDF text) | 2026-10-16 |
| EDPB Report of the Cookie Banner Taskforce, 18 Jan 2023 | §3 paras 6-8 (Type A, no reject: "vast majority" on *any layer*), §4 paras 9-10, §6 paras 15-19, §8 paras 26-30, §9 paras 31-32 (PDF text) | 2026-10-16 |
| WP29 Opinion 04/2012 (WP 194) | Document reachable at ec.europa.eu | 2026-10-16 |
| CJEU C-673/17 *Planet49*, ECLI:EU:C:2019:801 | EUR-Lex CELEX 62017CJ0673 | 2026-10-16 |
| CJEU C-40/17 *Fashion ID*, ECLI:EU:C:2019:629 | EUR-Lex CELEX 62017CJ0040 | 2026-10-16 |
| CNIL délibération 2020-091 (lignes directrices) | PDF on cnil.fr | 2026-10-16 |
| CNIL délibération 2020-092 (recommandation), consolidated after délibération 2025-131 of 18 Dec 2025 | §2.3 refusal "même écran … même facilité", Figure 5 "continuer sans accepter"; §3 withdrawal; §5 audience measurement, "treize mois", 25 months retention (PDF text) | 2026-10-16 |
| CNIL page "solutions pour les outils de mesure d'audience" | Exemption conditions; 13 months presented as an example | 2026-10-16 |
| Conseil d'État, 19 juin 2026, n° 501417 | Rejects the challenge to Figure 5; refusal "continuer sans accepter" available with similar ease | 2026-10-16 |
| Conseil d'État, 19 juin 2020, n° 434684 | Annuls the general cookie-wall ban in délibération 2019-093 (Art. 1) | 2026-10-16 |
| CNIL SAN-2021-023 / SAN-2021-024 (Google, Facebook) | **Pending:** existence and date confirmed via secondary sources; official URL not yet located. Cited only by planned rule EP-06 | — |

## Data sources (classification)

| Dataset | Licence | Use |
|---|---|---|
| Open Cookie Database (jkwakman), commit `b15fa5db770e1e2fbd13ab08fa3983bcc5b521a2` | Apache-2.0 (licence file vendored) | Fallback cookie/storage-key classification |
| Curated cookies/hosts/CMP signatures (this project) | MIT | Primary classification; vendor documentation URLs checked 2026-10-16 (Hotjar's help centre blocks scripts, so its content was confirmed via secondary sources) |
| Disconnect, DuckDuckGo Tracker Radar | CC BY-NC-SA | **Not used** (non-commercial clause) |

## Reading on the horizon (not encoded)

Digital Omnibus proposal (Nov 2025) on moving terminal-equipment rules into
the GDPR, and the status of the ePrivacy Regulation withdrawal: tracked in
the design review (§2.5), not applied to any rule.
