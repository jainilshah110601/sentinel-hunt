# Sentinel Hunt

A Python CLI for investigating one question against an Azure Log Analytics workspace. An analyst asks about a host, account, or network flow, reviews the proposed KQL, and decides whether to send the matching events to OpenAI. Each finding includes the source rows so another analyst can check the interpretation.

## Try a four-hour logon review

From the repository root, run the offline example with Python 3.10 or later.

```sh
python -m sentinel_hunt --demo
```

The sample contains three failed logons from 192.0.2.18 against two accounts on lab-ws01. The same source and close timestamps make the failures worth investigating. Three rows alone give little basis for calling them a password spray. The prewritten assessment records that uncertainty and identifies the next check. The replay exercises the same query builder and evidence resolver as a live hunt and requires only Python's standard library.

## Run against a workspace

Install the dependencies in a virtual environment. Configure an Azure identity that can query the relevant tables. For a local CLI session, sign in with `az login`. Supply the workspace ID and an OpenAI key through your shell's environment.

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export LOG_ANALYTICS_WORKSPACE_ID="your-workspace-id"
read -rsp "OpenAI key: " OPENAI_API_KEY
export OPENAI_API_KEY
python -m sentinel_hunt
```

The setup block uses Bash. On Windows, activate the environment with `.venv\Scripts\Activate.ps1` and set the two environment variables in PowerShell.

Try *“Review failed logons on lab-ws01 over the last four hours.”* OpenAI receives the question and proposes a table, target, and time window. Python builds the query from a fixed column catalog. For this example it retrieves recent logon events, including successes that could help interpret a failure. Review the printed target and time window before approving the query. An empty target searches the workspace.

| Investigation | Table | Target when supplied |
| --- | --- | --- |
| Process execution or file changes | DeviceProcessEvents, DeviceFileEvents | Device name |
| Endpoint connections or authentication | DeviceNetworkEvents, DeviceLogonEvents | Device name |
| Cloud resource operations | AzureActivity | Caller |
| Identity sign-ins | SigninLogs | User principal name |
| Network flows labelled MaliciousFlow | AzureNetworkAnalytics_CL | VM name |

Each hunt covers one table and 1–168 hours. The query selects up to 250 of the newest matching rows. A busy host can fill that sample before the beginning of the requested window. The CLI shows the event count, model, and payload size before the second API call. Projected fields can include account names, IP addresses, and command lines. Approving that step sends those fields to OpenAI.

## Evidence and response

Findings contain an assessment, confidence, ATT&CK technique when applicable, and a follow-up check. The program resolves the model's row numbers back to the original Azure records and rejects references outside the sample. A valid reference identifies the evidence an analyst should read. The interpretation still needs review.

Use `--output reports/hunt.json` to save a live report after analysis. Create the reports directory first. The CLI opens a new file exclusively to protect earlier reports. Use `--model MODEL` to select a model with JSON-object chat completion support.

Host containment is opt-in with `--offer-isolation`. A high-confidence finding in a device search with a named target enables a Defender lookup. The CLI requires a single matching device and asks the operator to type its full DNS name. A successful request prints the action ID. Check its completion in Defender. The Azure identity needs separate Defender permissions to look up the device and request isolation.

## Project layout

| File | Responsibility |
| --- | --- |
| `sentinel_hunt/cli.py` | Interactive hunt, offline replay, report export |
| `sentinel_hunt/analysis.py` | Search planning and evidence review with OpenAI |
| `sentinel_hunt/workspace.py` | Query execution and Azure result handling |
| `sentinel_hunt/query.py` | Supported tables, target matching, lookback and sample bounds |
| `sentinel_hunt/findings.py` | Finding validation and source-row resolution |
| `sentinel_hunt/defender.py` | Endpoint lookup and isolation submission |
| `examples/logon-review.json` | Synthetic events and expected interpretation |
| `tests/test_hunt.py` | Offline regression tests |

Run `python -m unittest -v` from the repository root.

## Original project captures

These images accompanied the earlier version. The revised CLI uses different prompts and output formatting.

![Decision flow](https://github.com/user-attachments/assets/12681ec8-5d91-4092-ac37-21251b00a91f)

![Hunt question and generated query](https://github.com/user-attachments/assets/28a880da-ad5c-45ac-b7ef-9aec2d41be72)

![Log retrieval and model selection](https://github.com/user-attachments/assets/78878fe1-a64b-415d-a8a1-4a558a3a5c06)

![Findings and ATT&CK mapping](https://github.com/user-attachments/assets/7d6035c3-ff72-4bb4-841f-1f0570c643c4)
