# CyberSentinel

**Two-stage intrusion detection for Raspberry Pi edge telemetry.**

An unsupervised Isolation Forest gates traffic; a Random Forest classifies only what the first
stage flags. End-to-end **0.916 weighted F1** with **0.905 attack recall** across 5,600 rows.

<!-- Drop a screenshot of the SOC console here: outputs/console.png -->
<!-- Markdown: ![SOC console](outputs/console.png) -->

---

## At a glance

| | |
|---|---|
| **Accuracy** (end-to-end, 5,600 rows) | 0.8912 |
| **Weighted F1** | 0.9158 |
| **Attack recall** | 0.9047 |
| **Attack precision** | 0.7748 |
| **False positives** | 447 / 3,900 normal rows |
| **Cascade throughput gain** | classifier skips ~65% of rows |
| **Stack** | FastAPI · scikit-learn · pandas · React · TanStack Router · Tailwind |

Classifier accuracy is 1.00 on held-out attacks, so **every end-to-end error originates in the
anomaly stage** — which makes that the only part worth optimising. See
[Why DDoS recall is only 0.73](#why-ddos-recall-is-only-073).

---

## Why a cascade

Running a supervised classifier on every row is wasteful when ~70% of traffic is normal and the
labels for normal traffic are trivial. So Stage 1 is trained **only on normal traffic** and acts
as a gate; Stage 2 runs on the ~35% that looks unusual.

The trade is deliberate: you give up recall on attacks that look statistically normal, and you
get classification where it actually matters. It also means Stage 2 never sees a `none` label,
which is why the model has only three classes.

---

## Quick start

```bash
# 1. Backend — needs Python 3.14 (tested on 3.14.3)
pip install fastapi uvicorn pandas numpy scikit-learn joblib
uvicorn src.api.main:app --reload            # http://127.0.0.1:8000

# 2. Frontend — separate terminal
cd frontend && npm install && npm run dev    # http://127.0.0.1:5173
```

Open http://127.0.0.1:5173, adjust the six sliders, press **Run Detection**. The console POSTs to
`/predict` and renders the verdict, severity badge and threat gauge. Interactive API docs at
http://127.0.0.1:8000/docs.

> `requirements.txt` is unpinned and lists several packages that nothing in `src/` imports
> (xgboost, lightgbm, optuna, shap, mlflow, imbalanced-learn, matplotlib, seaborn). Only the
> seven packages above are needed to run the API, the training scripts and the inference script.
> The extras are for the notebooks — see [Limitations](#limitations).

### Retrain and evaluate

```bash
cd src
export PYTHONPATH=$PWD                       # Windows: $env:PYTHONPATH = (Get-Location).Path

python training/train_anomaly.py             # -> anomaly_model.pkl
python training/train_classifier.py          # -> classifier.pkl
python training/train_hybrid.py              # rebundles -> hybrid_model.pkl

python inference/predict_hybrid.py           # full evaluation report
```

---

## Architecture

```
  Raspberry Pi telemetry  (CPU, RAM, packet rates, TCP conns, failed auths)
            │
            ▼
  notebooks/  merge ─► clean ─► engineer 8 ratio features
            │
            ▼
  data/processed/engineered_dataset.csv        5,600 rows x 19 cols
            │
            ├──► Stage 1   IsolationForest   trained on normal only, contamination 0.15
            │                 flags ~35% as anomalous
            │                       │
            │                       ▼  flagged rows only
            │               Stage 2   RandomForest  crypto / ddos / portscan
            │                        + confidence gate (<0.65 -> suspicious_unknown)
            ▼                       ▼
         outputs/models/*.pkl ──► HybridDetector.predict
                                          │
                              ┌───────────┴───────────┐
                              ▼                       ▼
                      FastAPI  /predict        inference/predict_hybrid.py
                              │
                              ▼
                    React SOC console (threat gauge, verdict, raw JSON)
```

---

## Results

All figures produced by `src/inference/predict_hybrid.py` over the full dataset. Nothing here is
copied from notebook output.

### Stage 2 alone — Random Forest, attacks only, held-out 20%

| class | precision | recall | F1 |
|---|---|---|---|
| crypto | 1.00 | 1.00 | 1.00 |
| ddos | 1.00 | 1.00 | 1.00 |
| portscan | 1.00 | 1.00 | 1.00 |

Classification is effectively solved.

### Stage 1 — Isolation Forest, `contamination=0.15`

| metric | value |
|---|---|
| flagged as anomalous | 1,985 / 5,600 (35.4%) |
| attack recall | 0.9047 |
| attack precision | 0.7748 |
| false positives | 447 of 3,900 normal rows (FPR 0.1146) |
| attacks missed | 162 |

### End-to-end cascade

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| portscan | 1.00 | 1.00 | 1.00 | 600 |
| crypto | 0.78 | 0.99 | 0.87 | 500 |
| ddos | 1.00 | 0.73 | 0.85 | 600 |
| none | 0.96 | 0.89 | 0.92 | 3,900 |
| **overall** | **0.95** | **0.89** | **0.92** | 5,600 |

---

## Why DDoS recall is only 0.73

The most interesting result in the project, and the part I would defend hardest.

Each attack class is meant to have one loud feature — and DDoS's is `failure_rate`:

| feature | none | ddos | crypto | portscan |
|---|---|---|---|---|
| `failure_rate` | 0.0000 ± 0.0000 | **0.1159 ± 0.0616** | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| `process_cpu_ratio` | 0.02 | 0.00 | **50986.84** | 0.00 |
| `port_scan_intensity` | 0.03 | 0.00 | 0.00 | **2.0791** |

Stage 1 trains on normal traffic **only**, and `failure_rate` is identically zero across all
3,900 normal rows. Its variance within the training set is therefore 0, so `anomaly_model.py`
drops it as zero-variance. The detector keeps 5 features — and on those 5, DDoS is
indistinguishable from normal traffic:

```
ddos / none ratio:  0.00 · 0.06 · 1.05 · 1.02 · 1.01      (1.0 = no difference)
```

**Stage 1 is structurally blind to DDoS.** Its 0.73 recall is incidental, not earned.

### The obvious fix does not work

Keeping `failure_rate` rather than dropping it made results slightly *worse* at every matched
contamination:

| contamination | drop (shipped) | keep |
|---|---|---|
| 0.10 | acc 0.8950 · ddos 0.527 · 301 FP | acc 0.8862 · ddos 0.472 · 317 FP |
| **0.15** | **acc 0.8912 · ddos 0.735 · 447 FP** | acc 0.8832 · ddos 0.673 · 455 FP |
| 0.20 | acc 0.8700 · ddos 0.815 · 614 FP | acc 0.8643 · ddos 0.798 · 636 FP |

Retaining the column cannot help: a feature that is constant across the entire training set
produces no usable axis-aligned split, so IsolationForest learns nothing from it either way.
**Unsupervised novelty detection cannot learn a feature that is constant in its own training
distribution.** The fix has to break the degeneracy, not preserve the column:

- give Stage 1 a small labelled seed set per attack class, or
- swap it for a distance-based novelty model (LOF / kNN) that does not use axis-aligned splits, or
- invert the cascade — classifier handles known types, Stage 1 gates only unknowns

Not implemented. This is the clearest next step.

---

## Choosing contamination

`contamination` sets the Isolation Forest's decision offset. It is the single knob trading false
positives against missed attacks, so it was swept rather than guessed:

| contamination | flagged | attack recall | attack precision | FPR | false positives | acc | weighted F1 |
|---|---|---|---|---|---|---|---|
| 0.05 | 22.4% | 0.6547 | 0.8854 | 0.0369 | 144 | 0.8695 | 0.8342 |
| 0.08 | 27.9% | 0.7676 | 0.8344 | 0.0664 | 259 | 0.8832 | 0.8836 |
| 0.10 | 30.6% | 0.8312 | 0.8244 | 0.0772 | 301 | **0.8950** | 0.9060 |
| **0.15** | 35.4% | **0.9047** | 0.7748 | 0.1146 | 447 | 0.8912 | **0.9158** |
| 0.20 | 39.3% | 0.9329 | 0.7209 | 0.1574 | 614 | 0.8700 | 0.9044 |
| 0.25 | 42.7% | 0.9518 | 0.6767 | 0.1982 | 773 | 0.8473 | 0.8890 |
| 0.28 | 44.2% | 0.9576 | 0.6580 | 0.2169 | 846 | 0.8361 | 0.8808 |

**0.15 ships**: it maximises weighted F1 (0.9158) and attack recall (0.9047). The accuracy
optimum is 0.10, but taking it would mean missing 47% of all DDoS traffic. For an IDS a missed
attack is a breach and a false positive is analyst fatigue, so recall wins — but that is a policy
decision, not a metric one, which is why it is written down here.

---

## Leakage checks

A 1.00 accuracy means nothing if the model is cheating, so it was stress-tested.

**Label permutation.** Shuffled labels must collapse to chance:

| | 5-fold CV accuracy |
|---|---|
| true labels | 1.0000 |
| shuffled labels | 0.3440 ± 0.0092 |
| chance (3 classes) | 0.3333 |

Landing 0.011 above a 0.333 floor means this pipeline is not exploiting spurious correlation.

**Feature ablation.** Dropping the dominant feature `process_cpu_ratio` still scores 1.0000,
because `port_scan_intensity` and `failure_rate` independently cover portscan and DDoS. The
classes are separable by construction — which is the real reason accuracy is so high, and the
reason it would not survive contact with real traffic.

---

## Dataset

5,600 rows of Raspberry Pi telemetry across 10 capture files, 28 raw columns each.

| class | rows | share |
|---|---|---|
| none | 3,900 | 69.6% |
| ddos | 600 | 10.7% |
| portscan | 600 | 10.7% |
| crypto | 500 | 8.9% |

Raw sensor readings — CPU, RAM, context switches, interrupt rate, packet rates, TCP connection
counts, failed connection attempts, destination port fan-out — are reduced to 6 features.

### Feature engineering

Nine raw columns are collapsed into eight ratios:

| feature | formula |
|---|---|
| `packet_rate_total` | `packets_sent_per_sec + packets_recv_per_sec` |
| `packet_spike_ratio` | `packet_rate_total / rolling(10).mean()` |
| `connection_spike_ratio` | `tcp_connection_count / rolling(10).mean()` |
| `cpu_spike_ratio` | `cpu_user_pct / rolling(10).mean()` |
| `process_cpu_ratio` | `top_process_cpu_pct / (cpu_user_pct + 1e-5)` |
| `failure_rate` | `failed_connection_attempts / (tcp_connection_count + 1)` |
| `port_scan_intensity` | `unique_dst_port_count / (tcp_connection_count + 1)` |
| `load_per_connection` | `load_avg_1m / (tcp_connection_count + 1)` |

The models consume all of these except `packet_rate_total` and `load_per_connection`.
`process_cpu_ratio` spans six orders of magnitude (0 to 6.1e6), so it is `log1p`-transformed
before scaling — it is also the single strongest feature, isolating crypto-mining outright.

---

## API

| method | path | purpose |
|---|---|---|
| `GET` | `/` | service banner |
| `GET` | `/health` | liveness |
| `POST` | `/predict` | run the cascade on six features |
| `GET` | `/live_detection` | run the cascade on a random dataset row |

`POST /predict` accepts six floats and returns:

```json
{
  "anomaly_pred": 1,
  "anomaly_score": -0.2581,
  "attack_pred": "suspicious_unknown",
  "final_prediction": "suspicious_unknown",
  "confidence": 0.6205,
  "severity": "high"
}
```

It delegates to `HybridDetector.predict` — the same code path as `/live_detection` and the
inference script, so there is exactly one decision policy and no chance of divergence.

---

## Layout

```
src/
  models/
    anomaly_model.py         Stage 1 — IsolationForest, trained on normal traffic only
    classification_model.py  Stage 2 — RandomForest + LabelEncoder + StandardScaler
    hybrid_model.py          the cascade: gate, classify, gate on confidence, score severity
  training/
    train_anomaly.py         trains Stage 1
    train_classifier.py      trains Stage 2 on attacks only
    train_hybrid.py          rebundles both into one artifact
  inference/
    predict_hybrid.py        end-to-end evaluation report
  api/main.py                FastAPI app
data/raw/                    10 Raspberry Pi capture files
data/processed/              pipeline output; engineered_dataset.csv is the model input
outputs/models/              3 joblib artifacts
outputs/figures/             EDA plots
frontend/                    React + TanStack Router + Tailwind SOC console
notebooks/                   exploration record
```

`sys.path` must include `src/` — `hybrid_model.pkl` is a whole-object pickle that resolves
`models.hybrid_model.HybridDetector` by name, which `api/main.py` appends at line 282.

---

## Limitations

Stated plainly, because these are the questions worth asking.

1. **The classes are separable by construction.** `process_cpu_ratio` isolates crypto,
   `port_scan_intensity` isolates portscan, `failure_rate` isolates DDoS — each a single
   near-binary feature. The 1.00 classifier accuracy reflects dataset design, not a hard
   detection problem. Real traffic would not separate this cleanly.

2. **Part of the attack data is synthetic and replayed.** `run_5_ddos_synth.csv` is explicitly
   synthesised, and both it and `run_100_portscan.csv` reuse the `run_id` and timestamps of the
   baseline `run_5.csv`. Normal traffic is genuinely captured; attack traffic is overlaid on it.

3. **5,600 rows is small**, and Stage 1 is the bottleneck. The classifier is at ceiling, so
   further classifier work is pointless.

4. **Stage 1 caps end-to-end recall.** Because Stage 2 is perfect on held-out attacks, cascade
   recall is exactly Stage 1's recall.

5. **The notebooks are not runnable as saved.** `notebooks/03`–`07` require matplotlib, seaborn
   and jupyter, and contain stale imports and out-of-order cells. `src/` is the reproducible
   path; the notebooks are the exploration record.

6. **Single-device dataset.** All traffic comes from one Raspberry Pi. Multi-device or real
   network capture would be the next step for any deployment claim.