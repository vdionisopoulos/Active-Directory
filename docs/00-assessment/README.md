# Level 0 — Assessment

> You cannot fix what you cannot see, and you cannot prove improvement without a baseline. Do this first.

## Free tools that give you a scored starting point

| Tool | What it does | Run time |
|------|--------------|----------|
| [PingCastle](https://www.pingcastle.com/) | Scores your domain against a risk model; produces an HTML report with prioritized findings | ~15 min |
| [Purple Knight](https://www.purple-knight.com/) (Semperis) | Indicators of Exposure & Compromise across AD/Entra | ~20 min |
| [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) | Graphs attack paths — "who can reach Domain Admin, and how" | Collection ~min, analysis ongoing |

## How to use the results

1. **Record your baseline score.** Screenshot the PingCastle score. You will re-run after each level to prove movement — this is your evidence that the work mattered.
2. **Don't fix everything the report screams about at once.** Map findings to the maturity levels in this repo. Most Level 1 and 2 findings will already be covered in order.
3. **Run BloodHound early, act on it in Level 3.** Seeing the attack paths now motivates the ACL work later.

## Exit criteria

- [ ] PingCastle report generated and score recorded.
- [ ] Purple Knight or equivalent IoE scan reviewed.
- [ ] BloodHound collection done; shortest paths to Tier 0 identified.

Proceed to [Level 1 — Baseline Hygiene](../01-baseline-hygiene/README.md).
