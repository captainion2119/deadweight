# Contributing

## Setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest
```

The tests run against [moto](https://github.com/getmoto/moto) and botocore stubs. They need no AWS
account and make no network calls to AWS.

## Rules

1. **Read-only.** Deadweight only calls `Describe*`, `List*`, `Get*` and similar read APIs. A change that
   creates, modifies, enables or deletes anything in an AWS account will not be merged. That includes
   "harmless" opt-ins such as enabling Compute Optimizer or creating a Config rule.
2. **No data reads.** Do not call APIs that return customer data (`secretsmanager:GetSecretValue`,
   `s3:GetObject` on anything other than the billing export, `sqs:ReceiveMessage`, …).
3. **No real account data in the repo.** Fixtures, tests, screenshots and examples use mocked accounts
   (`123456789012`). Scan output is git-ignored; keep it that way.
4. **`n/a` is not `$0`.** If a price or metric could not be determined, say so. Never substitute zero.
5. **Failures are reported, not swallowed.** A denied or failed call becomes a Coverage entry with its
   IAM action, so the user knows the inventory may be incomplete.

## Adding a collector

Collectors live in `deadweight/collectors/`, one file per service family. A collector is a function
registered with the `@collector` decorator:

```python
@collector("EFS", "storage", bill="Amazon Elastic File System", client="efs", actions=("elasticfilesystem:DescribeFileSystems",),
           desc="File systems by storage class; provisioned throughput")
def efs(ctx: Ctx) -> None:
    ...
```

- `bill` is the exact Cost Explorer `SERVICE` name the resources are billed under. It is what lets the
  bill be reconciled against the inventory, so check it against a real bill.
- `actions` lists every IAM action the collector calls. `--print-policy` is generated from it.
- `default=False` makes a collector opt-in. Use it for anything slow or very broad.

Then:

- If the service has an activity signal (a CloudWatch metric, a last-used date, a reference from another
  resource), add a rule to `deadweight/usage.py` so its resources get a usage state.
- Add the resource to `tests/fixture.py` and, if you added a rule, a test in `tests/test_units.py`.

## Layout

| Path | |
|---|---|
| `deadweight/collectors/` | one file per service family; `base.py` has the registry and helpers |
| `deadweight/scanner.py` | runs collectors in parallel, merges and de-duplicates |
| `deadweight/billing.py`, `costs.py`, `cur.py` | Cost Explorer, CUR and bill ↔ inventory reconciliation |
| `deadweight/usage.py`, `findings.py` | usage states and findings |
| `deadweight/pricing.py` | Pricing API lookups and the on-disk cache |
| `deadweight/report.py`, `html_report.py` | exports, saved-report loading, diff, HTML report |
| `deadweight/profiles.py` | AWS profile setup |
| `deadweight/ui.py`, `ui_kit.py` | the Textual interface |
| `deadweight/cli.py` | command line and headless mode |
