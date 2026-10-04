# AI-Powered Anomaly Detection Bot

A local network anomaly detection demonstration that trains an Isolation Forest, scores consistent network-flow features, stores events in SQLite, and displays an updating Dash dashboard.

## Start here

1. Install **Python 3.13**.
2. Clone this repository, or download its ZIP from GitHub and extract it into a normal folder.
3. Open the project folder and run **SETUP_WINDOWS.cmd** once to create an isolated environment and install the required libraries.
4. Double-click **START_DASHBOARD.cmd**.
5. Click **Start / resume** to replay 5,000 held-out flows through the saved model.
6. Watch the counters, charts, and recent-flow table update. Use **Pause**, **Start / resume**, and **Stop** to control replay.
7. Click **Export session** to save the full session as CSV. The table displays only the latest 300 flows; exports include every flow in the selected session.

The replay reads real held-out rows from `data/demo_flows.csv`, derived from the included CICIDS2017 dataset. It **does not send traffic or simulate an attack against a website**. Dataset labels are shown for comparison and are never inference inputs. No IP addresses or geographic locations are invented.

Setup installs packages into this project's `.venv`; it does not replace global packages. Internet access is needed for setup, but the dashboard and bundled demo run offline afterwards. The included model is already trained.

For command-line setup on Windows, run these commands from the project folder:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe dashboard.py
```

After setup, use `.\.venv\Scripts\python.exe` instead of `python` in the commands below.

## What was fixed

| Original issue | Working version |
|---|---|
| Model trained on flow measurements but predicted using packet size and ports | One shared, named 11-feature contract for CSV, PCAP, and live flows |
| Training used attack-heavy data without evaluation | Normal-only model fitting; separate validation and test partitions |
| No measured detection results | Saved precision, recall, F1, accuracy, ROC AUC, false-positive rate, and confusion matrix |
| Charts had misleading IP, geolocation, and severity titles | Charts show actual processing activity and actual flow measurements |
| Dashboard read the CSV once | Dashboard polls persisted prediction events every second |
| Hard-coded computer-specific CSV path | Paths resolve from the project location; folder can be moved |
| Text log without session structure | Persistent SQLite events, independent sessions, and complete CSV exports |
| Slack could slow packet processing | Explicit opt-in delivery, bounded queue, cooldown, and isolated delivery failures |

## Measured model results

Evaluation uses the CICIDS2017 `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, included as `data/network_traffic.csv.gz`. The full training dataset is compressed only to reduce repository size; its original CSV contents are unchanged. Pandas reads the compressed file directly, so no manual extraction is needed. The dataset SHA-256 in the evaluation report identifies the original, uncompressed CSV bytes.

| Measurement | Result |
|---|---:|
| Original rows | 225,745 |
| Usable rows | 225,743 |
| Invalid rows removed | 2 |
| Benign flows used to fit the forest | 57,727 |
| Validation flows | 46,003 |
| Test flows | 45,132 |
| Test accuracy | 96.83% |
| Test precision | 96.19% |
| Test recall | 98.30% |
| Test F1 | 97.24% |
| Test ROC AUC | 97.73% |
| Test false-positive rate | 5.10% |

The test contains 19,525 benign and 25,607 DDoS flows:

| Actual label | Predicted within baseline | Predicted anomaly |
|---|---:|---:|
| Benign | 18,529 | 996 |
| DDoS | 435 | 25,172 |

See **artifacts/evaluation.json** for exact values, source-file SHA-256, split information, parameters, versions, and limitations. These are measured dataset results, **not guaranteed performance on another network or another attack type**.

## How the model is trained

1. Strip whitespace from CSV column names and convert the selected features to numbers.
2. Reject missing, infinite, negative, or invalid-count rows.
3. Split approximately 60% / 20% / 20% by groups of identical feature vectors. The same feature vector cannot appear in multiple partitions.
4. Fit the forest only on benign rows in the training partition. Attack rows from that partition are excluded.
5. Transform every feature with `log1p` during both fitting and inference.
6. Use 250 trees, up to 1,024 observations per tree, and random seed 42.
7. Compute anomaly scores as `-model.score_samples(X)`: a larger score means more unusual.
8. Select the threshold that maximizes validation F1 while keeping the validation false-positive rate at or below 5%.
9. Freeze that threshold and measure the separate test partition. Test labels do not select the threshold.

The saved alert threshold is **0.5494280771068508**. A flow is flagged when its score is greater than or equal to that threshold. A score is **not** an attack probability.

Isolation Forest is an unsupervised algorithm. This complete workflow uses known benign labels to build the baseline and labeled validation examples to calibrate the threshold, so it should not be described as an entirely label-free system.

Retrain deterministically using the included compressed training dataset:

```powershell
python model_training.py
```

This replaces the model, report, held-out CSV, and demonstration CSV. Stop the dashboard before retraining; restart afterwards to load the new model.

## The shared flow features

A packet is one transmitted unit. A flow groups packets exchanged between two IP-address/port endpoints using the same protocol. Forward means the direction of the first observed packet; backward means the reverse direction.

| Feature | Unit / definition |
|---|---|
| `flow_duration_us` | Last packet time minus first packet time, in microseconds |
| `fwd_packets` | Number of forward packets |
| `bwd_packets` | Number of reverse packets |
| `fwd_bytes` | Sum of forward transport payload bytes |
| `bwd_bytes` | Sum of reverse transport payload bytes |
| `fwd_length_max` | Largest forward transport payload |
| `bwd_length_max` | Largest reverse transport payload |
| `fwd_length_min` | Smallest forward transport payload |
| `bwd_length_min` | Smallest reverse transport payload |
| `fwd_length_mean` | Forward payload total / forward packet count |
| `bwd_length_mean` | Reverse payload total / reverse packet count |

Lengths exclude Ethernet, IP, TCP, and UDP headers. Zero-payload acknowledgments still count as packets. If no backward packets exist, their length summaries are zero. Ports, addresses, labels, timestamps, and protocol names are metadata, not model inputs.

The common feature order and validation live in `bot/config.py` and `bot/features.py`. The model checks its saved feature schema and scikit-learn version at startup.

## PCAP mode

Try the bundled **synthetic functionality fixture** without a capture driver:

```powershell
python sniffer.py --pcap data/demo_capture.pcap
```

It contains 32 offline packets forming 10 bidirectional flows. The fixture checks that reading, aggregation, inference, and storage work; it is not an attack-accuracy benchmark and has no attack labels.

To process your own PCAP:

```powershell
python sniffer.py --pcap "C:\path\to\traffic.pcap"
```

The dashboard displays the latest session automatically. Use the session selector to inspect earlier sessions.

## Live capture mode

Windows packet capture uses Scapy and Npcap. Npcap was present on the computer used for verification. List interfaces:

```powershell
python sniffer.py --list-interfaces
```

Then select an interface using the exact name shown:

```powershell
python sniffer.py --interface "\Device\NPF_Loopback" --seconds 30
```

That example captures this machine's local loopback traffic. Use your listed Wi-Fi/Ethernet interface to capture that adapter's traffic. Capture permissions depend on your Npcap configuration; an elevated terminal may be necessary. An interview demonstration can use replay or PCAP without capture permissions.

The capture component runs separately from the dashboard. Open the dashboard and run one capture/replay input at a time. Omitting `--seconds` captures until Ctrl+C. Completed and remaining flows are saved on a normal stop.

The aggregator:

- Supports bidirectional **IPv4 TCP and UDP**.
- Completes a TCP flow after a reset or FIN packets in both directions.
- Completes idle flows after 30 seconds, or splits flows at 120 seconds of age.
- Flushes remaining flows at PCAP end or capture stop.
- Bounds active flows at 50,000 and the live packet queue at 20,000 packets; overflow counts are reported.
- Ignores fragmented packets, IPv6, unsupported transport protocols, and out-of-order packets rather than assigning misleading feature values.

Prediction occurs when a flow is finalized, so an idle-flow alert can take 30 seconds and a continuing flow can take up to 120 seconds. The dashboard refreshes once per second. This is **flow-based monitoring**, not a prediction for every packet.

Live segmentation approximates CICFlowMeter; its TCP closure, timeout handling, and capture position are not guaranteed to match the original dataset extractor exactly. The dataset's baseline can flag legitimate traffic from another network. Live capture was verified functionally on loopback; live attack-detection accuracy is unmeasured.

## Optional Slack notifications

Local events and dashboard alerts work without Slack. Slack credentials belong in the local `.env` file, which is excluded from version control.

1. Copy `.env.example` to `.env` in this project folder.
2. Set your own `SLACK_TOKEN` and `SLACK_CHANNEL`.
3. Give your Slack app permission to post messages and access the destination channel.
4. Explicitly start capture with `--slack`:

```powershell
python sniffer.py --interface "\Device\NPF_Loopback" --slack
```

Delivery is disabled otherwise, including during dataset replay. A 60-second cooldown per endpoint pair and destination port reduces repeated notifications. Slack failures leave local events intact. Actual delivery has not been verified with a Slack account; no messages were sent during development.

## Events and exports

Events are saved to `runtime/events.sqlite3`. The database is created automatically. A new replay or capture creates a new session; stopping does not erase earlier events.

Recorded fields include the processing timestamp, prediction, score, baseline context, model-inference time, all 11 features, and available capture metadata. Processing time is not the original dataset's collection time. Displayed times use IST; stored timestamps use UTC.

Baseline context compares features to the benign training distribution's 1st/99th percentiles. It is descriptive context, not a proof of the model's causal reasoning or an attack classification.

Exports include the entire selected session. Replay rows have blank endpoint fields because the provided CSV contains no source/destination IP fields. Captured rows have no ground-truth attack labels.

## Run the checks

From the project folder:

```powershell
python -m unittest discover -s tests -v
```

Checks cover known packet-to-flow measurements, reverse direction, TCP closure, UDP expiry, payload padding, excluded packets, flow capacity, invalid inputs, feature order, consistent CSV/packet inference, reproduced test metrics, threshold calibration, persistence, replay controls, dashboard callbacks, exports, default-disabled Slack, and a PCAP command from end to end.

## Files

```text
START_DASHBOARD.cmd       Windows start shortcut
SETUP_WINDOWS.cmd        Isolated dependency setup
launch.py                Preflight and browser launch
model_training.py        Training, validation, evaluation, model saving
sniffer.py               Live / PCAP capture command
dashboard.py             Dash UI and updating callbacks
bot/config.py            Paths and shared feature schema
bot/features.py          CSV loading and validation
bot/flows.py             Bidirectional packet aggregation
bot/model.py             Shared inference and baseline comparisons
bot/storage.py           SQLite sessions and events
bot/replay.py            Background dataset replay controls
bot/alerts.py            Optional queued Slack delivery
assets/style.css         Responsive dashboard styling
artifacts/               Trained model and evaluation report
data/                    Compressed original CSV, test flows, replay sample, PCAP fixture
tests/                   Functional and integration checks
runtime/                 Local events, created while running
```

## Troubleshooting

| Symptom | Action |
|---|---|
| Missing packages | Run SETUP_WINDOWS.cmd, then use START_DASHBOARD.cmd |
| Model version differs | Install the pinned requirements or retrain in your environment |
| Address already in use | Close the earlier dashboard window, or use `python dashboard.py --port 8051` |
| Capture fails or shows no adapter | Check Npcap/interface permissions; replay and PCAP still work |
| No immediate live events | Flows are finalized at TCP close, idle timeout, max age, or capture stop |
| Replay stopped after closing the launch window | Restart the dashboard and begin a new replay; saved events remain |
| Export appears unchanged | Confirm which session is selected; export uses that session |

The included Flask/Dash server binds to the local loopback address. This is a local demonstration, not an internet-facing production security service. No automated blocking is implemented.

## References and attribution

- [CICIDS2017 dataset description, University of New Brunswick](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter packet payload and timestamp extraction](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java)
- [Isolation Forest, scikit-learn](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Dash live updates](https://dash.plotly.com/live-updates)
- [Scapy installation and Windows capture requirements](https://scapy.readthedocs.io/en/latest/installation.html)

The original Apache 2.0 LICENSE.txt is preserved. Dataset attribution and terms are separate from the project's code license.
