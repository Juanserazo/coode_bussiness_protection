# COODE BUSSINES PROTECTION

COODE BUSSINES PROTECTION is a managed cybersecurity project for small and midsize businesses in Colombia and Mexico. The MVP is a read-only Python CLI that assesses an authorized domain's email and website configuration and produces PDF and JSON reports.

## Installation

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and open PowerShell, Git Bash, or Bash on Linux, macOS, or WSL at the project root. Use Python 3.12, the version tested for this project. uv creates the virtual environment automatically.

```sh
uv sync --locked --python 3.12 --no-dev
```

`pyproject.toml` declares the dependencies. `uv.lock` records the resolved versions, including transitive dependencies. Commit both files when dependencies change.

PowerShell and Git Bash can share the Windows `.venv`. If you also use the same checkout from WSL, run `export UV_PROJECT_ENVIRONMENT=.venv-wsl` in the WSL shell before running `uv sync` or `uv run`. When configuring PyCharm, select `.venv\Scripts\python.exe` on Windows or `.venv/bin/python` on Linux and macOS. For the separate WSL environment, use `.venv-wsl/bin/python`.

## Running the diagnostic

### Guided mode

Run `coode_diagnostic.py` with no arguments from a terminal or through **Run** in PyCharm. Select the interpreter from your virtual environment and set the working directory to the project root. The diagnostic prompts are in Spanish.

Press Enter to accept `example.com` as the email domain. Press Enter again to use the same name for TLS and HTTPS. Use `--interactive` to keep the prompts while setting options such as `--output` or `--timeout`.

```powershell
uv run --locked --no-dev python .\coode_diagnostic.py --interactive --output .\reports
```

### Command-line arguments

Each shell example shows a test with `example.com` and an internal pilot run. Run the pilot only once the scope is authorized. It uses `coode.tech` for the email checks and `www.coode.tech` for the website checks.

#### PowerShell on Windows

```powershell
uv run --locked --no-dev python .\coode_diagnostic.py example.com --output .\reports
uv run --locked --no-dev python .\coode_diagnostic.py coode.tech --web-host www.coode.tech --output .\reports
```

#### Bash on Linux, macOS, or WSL

```bash
uv run --locked --no-dev python ./coode_diagnostic.py example.com --output ./reports
uv run --locked --no-dev python ./coode_diagnostic.py coode.tech --web-host www.coode.tech --output ./reports
```

#### Git Bash on Windows

```bash
uv run --locked --no-dev python ./coode_diagnostic.py example.com --output ./reports
uv run --locked --no-dev python ./coode_diagnostic.py coode.tech --web-host www.coode.tech --output ./reports
```

| Argument | Purpose |
|---|---|
| `DOMAIN` | DNS name for the email checks. Enter a hostname without a scheme, path, or port. |
| `--interactive` | Prompts for any missing domain or website name. |
| `--web-host` | DNS name for TLS and HTTPS. Defaults to the email domain in noninteractive mode. |
| `--output` | Output directory. Defaults to `reports/`. |
| `--timeout` | Timeout in seconds for queries and connections. Defaults to 5. It must be greater than 0 and no greater than 60. |

## Checks

| Control | Evidence |
|---|---|
| MX | Published mail servers or a null MX record indicating that the domain does not accept email. |
| SPF | Published SPF policy and whether multiple policies are present. |
| DMARC | Published DMARC policy and its `p` value. For example, `p=none` is flagged for review. |
| TLS | Certificate trust, hostname match, and expiration. A valid certificate expiring within 30 days is flagged for review. |
| HTTPS | First HTTP status from the website root. Redirect targets are outside the scope of the check. |

The DNS checks use `dnspython`. The web checks use `httpx` and Python's `ssl` and `socket` modules.

## Reading the reports

Each run creates a portrait PDF and a JSON file named after the email domain and a UTC timestamp. The PDF starts with a status summary and lists the evidence for each email and web check in Spanish. It includes suggested actions and verification steps where applicable. The JSON retains the existing field names and status values for integrations.

| Status in the report | Meaning |
|---|---|
| `verificado` | The check obtained evidence that met its criteria. |
| `requiere revisión` | The check found a condition to review with the administrator. |
| `no verificado` | The query or connection could not complete. See the evidence for details. |

The report reflects public DNS records and the website response observed at the time of the run.

## Project layout

| Path | Purpose |
|---|---|
| `coode_diagnostic.py` | CLI entry point for the Base diagnostic. |
| `coode_protection/` | Shared finding model, DNS and web checks, orchestration, and report generation. |
| `scripts/` | Internal tools. Run them from the project root with `python -m scripts.module_name`. |
| `tests/` | Automated tests with simulated network responses. |
| `reports/` | Local PDF and JSON output. Override the directory with `--output`. |

New tools can reuse `run_diagnostic` from `coode_protection.diagnostic` and `write_reports` from `coode_protection.reports`. Git ignores local reports, virtual environments, caches, and PyCharm project settings.

## Running the tests

The development environment includes pytest. The suite covers all five controls, the CLI, and the report formats with simulated network responses.

```sh
uv sync --locked --python 3.12
uv run --locked pytest -v
```

Use `example.com` for a separate live test. Check the statuses in the report to see which network checks completed.
