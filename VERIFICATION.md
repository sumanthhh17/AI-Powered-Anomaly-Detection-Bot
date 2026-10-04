# Verification record

Verified on 3 October 2026 on the user's Windows computer with Python 3.13.3.

## GitHub package verification — 4 October 2026

The full training CSV is included as `data/network_traffic.csv.gz` and is read directly without manual extraction. Its decompressed SHA-256 matches the original source recorded in `artifacts/evaluation.json`: `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee`.

Compared the plain and compressed full datasets: every cleaned feature and label matched, with 225,745 input rows, 225,743 valid rows, and 2 dropped rows. The regression suite now includes a compressed-input equivalence and source-hash check; **all 16 tests passed** on the upload copy. The saved model and measured detection results are unchanged.

## Automated checks

Command: `python -m unittest discover -s tests -v`

**15 tests passed** after the final export change. The run completed in 7.064 seconds.

Coverage:

- Exact forward/reverse packet counts, payload summaries, duration, and TCP FIN closure.
- UDP expiration and zero-backward summaries.
- Exclusion of Ethernet padding from payload bytes.
- Exclusion of fragments and IPv6.
- Duration rollover, out-of-order packets, and bounded flow capacity.
- Rejection of missing/invalid features.
- Feature-order independence and matching packet/CSV inference.
- Reproduction of the saved test confusion matrix and F1 score.
- Validation-threshold false-positive budget.
- SQLite persistence and session isolation.
- Replay start, pause, resume, and stop.
- Dashboard routes, updating callback, and CSV attachment response.
- Slack disabled by default.
- The PCAP command running as a separate process from packet input to saved prediction.

## Browser checks

The local dashboard at `http://127.0.0.1:8050/` was opened in the Codex in-app browser.

- Started the real dataset replay using the UI.
- Confirmed counters, flow charts, reference labels, scores, and baseline context appeared.
- Paused replay and confirmed the paused state was visible.
- Confirmed the completed 5,000-flow session could be displayed after restarting the dashboard.
- Corrected a browser-specific blob-download issue by using a direct CSV attachment route.
- Downloaded the session CSV from the final UI and read the downloaded file: **5,000 rows, 25 columns, 2,946 flagged flows**.
- Confirmed no source IP addresses were invented in replay rows.
- Inspected and saved the full dashboard screenshot as `artifacts/dashboard-full.jpg`.

The exported demonstration session is included as `artifacts/example_session.csv`. Its 58.9% alert rate is a proportion of that replay sample, not model accuracy. This dataset sample contains many DDoS flows.

## Packet-input checks

**Offline PCAP:** `data/demo_capture.pcap` contains 32 synthetic packets. The capture command produced **10 expected bidirectional flows**, stored them, and completed normally with no ignored packets or capacity evictions. It flagged 6 flows. This fixture has no ground-truth attack labels and is a functionality check.

**Live loopback:** A five-second capture on `\Device\NPF_Loopback` successfully produced and stored **10 flows**, with **zero queue drops**, no ignored packets, and no capacity evictions. These loopback flows were all flagged relative to the CICIDS2017 baseline. This is not evidence that the local traffic was malicious; it illustrates why dataset results do not establish live-network accuracy. No attacks were generated.

## Model evaluation

The included model's metrics were reproduced from `data/test_flows.csv`:

- 45,132 test flows.
- Accuracy: 96.8293%.
- Precision: 96.1938%.
- Recall: 98.3012%.
- F1: 97.2361%.
- False-positive rate: 5.1012%.
- True normal: 18,529; false alerts: 996; missed attacks: 435; detected attacks: 25,172.

See `artifacts/evaluation.json` for exact values and methodology. Identical feature groups do not cross partitions; threshold selection uses validation data, not test labels.

## Scope

The system is a tested local demonstration. It does not provide 100% detection or a guarantee across networks. It supports IPv4 TCP/UDP flow extraction; it does not implement IPv6 analysis, fragment reassembly, complete CICFlowMeter equivalence, automatic blocking, or production-scale deployment.

Slack integration is implemented and optional. No original credentials were copied, no account delivery was tested, and no Slack messages were sent. A clean installation on a second computer has not been exercised; the package pins the versions used here and includes an isolated setup shortcut.
