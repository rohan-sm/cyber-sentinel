# CyberSentinel

**A two-stage intrusion detection system for Raspberry Pi edge telemetry.**

An unsupervised Isolation Forest gates traffic, and a Random Forest classifies only what the
first stage flags. The point of the cascade is cost: the classifier never runs on the ~65% of
traffic that is plainly normal, so you keep most of the accuracy of a full classifier at a
fraction of the inference work.

```
  Raspberry Pi telemetry
            │
            ▼
  ┌───────────────────────┐
  │  Stage 1  Isolation   │   trained on normal traffic only
  │  Forest  (unsupervised)│   flags ~35% as anomalous
  └───────────┬───────────┘
              │  flagged rows only
              ▼
  ┌───────────────────────┐
  │  Stage 2  Random      │   crypto / ddos / portscan
  │  Forest  (supervised) │   + confidence gate
  └───────────┬───────────┘
              │
              ▼
        FastAPI  ──►  React SOC console
```

---

## Results

Measured by running `src/inference/predict_hybrid.py` over all 5,600 rows.
Reproduce with the commands in [Running it](#running-it).

### Stage 2 alone — Random Forest, attacks only, held-out 20%

| class | precision | recall | F1 |
|---|---|---|---|
| crypto | 1.00 | 1.00 | 1.00 |
| ddos | 1.00 | 1.00 | 1.00 |
| portscan | 1.00 | 1.00 | 1.00 |

Classification is effectively solved. **Every end-to-end error comes from Stage 1.**

### Stage 1 — Isolation Forest (`contamination=0.15`)

| metric | value |
|---|---|
| flagged as anomalous | 1985 / 5600 (35.4%) |
| attack recall | 0.9047 |
| attack precision | 0.7748 |
| false positives | 447 of 3900 normal rows (FPR 0.1146) |
| attacks missed | 162 |

### End-to-end cascade

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| crypto | 0.78 | 0.99 | 0.87 | 500 |
| ddos | 1.00 | 0.73 | 0.85 | 600 |
| portscan | 1.00 | 1.00 | 1.00 | 600 |
| none | 0.96 | 0.89 | 0.92 | 3900 |

**Accuracy 0.8912 · weighted F1 0.9158 · weighted precision 0.95**

---

## Why DDoS recall is only 0.73

This is the most interesting result in the project, so here is the full mechanism.

DDoS is separable from normal traffic by exactly one feature:

| feature | none | ddos | crypto | portscan |
|---|---|---|---|---|
| `failure_rate` | 0.0000 ± 0.0000 | **0.1159 ± 0.0616** | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| `process_cpu_ratio` | 0.02 | 0.00 | **50986.84** | 0.00 |
| `port_scan_intensity` | 0.03 | 0.00 | 0.00 | **2.0791** |

Crypto and portscan each have one loud feature. DDoS's only feature is `failure_rate`.

Stage 1 is trained on normal traffic **only**, and `failure_rate` is identically zero across all
3,900 normal rows — so its variance within the training set is 0 and `anomaly_model.py` drops it.
The detector keeps 5 features. On those 5, DDoS looks like normal traffic:

```
ddos / none ratio:  0.00 · 0.06 · 1.05 · 1.02 · 1.01     (1.0 = indistinguishable)
```

**Stage 1 is structurally blind to DDoS.** Its 0.73 recall is incidental, not earned.

I tested the obvious fix — keep `failure_rate` instead of dropping it. It made things slightly
*worse* at every matched contamination:

| contamination | drop `failure_rate` (shipped) | keep `failure_rate` |
|---|---|---|
| 0.10 | acc 0.8950 · ddos 0.527 · 301 FP | acc 0.8862 · ddos 0.472 · 317 FP |
| 0.15 | **acc 0.8912 · ddos 0.735 · 447 FP** | acc 0.8832 · ddos 0.673 · 455 FP |
| 0.20 | acc 0.8700 · ddos 0.815 · 614 FP | acc 0.8643 · ddos 0.798 · 636 FP |

The reason is that retaining the feature does not help: a column that is constant across the
whole training set produces no usable axis-aligned split, so IsolationForest still learns
nothing from it. **Unsupervised novelty detection cannot learn a feature that is constant in its
own training distribution.** The fix has to break the degeneracy, not keep the column:

- give Stage 1 a small labelled seed set per attack class, or
- replace it with a distance-based novelty model (LOF / kNN) that does not rely on axis-aligned
  splits, or
- invert the cascade and let the classifier handle known types, using Stage 1 only for unknowns

Not implemented — this is the clearest next step.

---

## Contamination sweep

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

**0.15 is shipped**: it maximises weighted F1 (0.9158) and attack recall (0.9047) at the cost
of a higher false-positive rate than 0.10. The choice is deliberate — for an IDS, a missed
attack is a breach while a false positive is analyst fatigue, and 0.10 would have meant missing
47% of all DDoS traffic.

---

## Leakage checks

A 1.00 accuracy is worthless if the model is cheating, so the classifier was stress-tested.

**Label permutation.** Shuffled labels should collapse to chance. They do:

| | 5-fold CV accuracy |
|---|---|
| true labels | 1.0000 |
| shuffled labels | 0.3440 ± 0.0092 |
| chance (3 classes) | 0.3333 |

Scoring 0.344 against a 0.333 floor means this pipeline is not exploiting spurious correlation.

**Feature ablation.** Removing the dominant feature `process_cpu_ratio` still scores 1.0000,
because `port_scan_intensity` and `failure_rate` separately cover portscan and DDoS. The three
attack classes are linearly separable by construction, which is the real reason accuracy is
high — see Limitations.

---

## Dataset

5,600 rows of Raspberry Pi telemetry across 10 capture files, 28 raw columns each.

| class | rows | share |
|---|---|---|
| none | 3,900 | 69.6% |
| ddos | 600 | 10.7% |
| portscan | 600 | 10.7% |
| crypto | 500 | 8.9% |

Raw sensor readings (CPU, RAM, context switches, packet rates, TCP connections, failed
connection attempts) are reduced to 6 features for the models.

### Feature engineering

Eight ratios derived from 9 raw columns:

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

The 6 features the models consume are everything except `packet_rate_total` and
`load_per_connection`. `process_cpu_ratio` spans six orders of magnitude (0 to 6.1e6), so it
is `log1p`-transformed before scaling.

---

## Limitations

Stated plainly, because they are the questions worth asking.

1. **The attack classes are separable by construction.** `process_cpu_ratio` isolates crypto,
   `port_scan_intensity` isolates portscan, `failure_rate` isolates DDoS — each with a single
   near-binary feature. Perfect classifier accuracy reflects dataset design, not a hard
   detection problem. On real traffic this would not hold.

2. **Part of the attack data is synthetic and replayed.** `run_5_ddos_synth.csv` is explicitly
   synthesised, and both it and `run_100_portscan.csv` reuse the `run_id` and timestamps of the
   baseline `run_5.csv`. Normal traffic is genuinely captured; attack traffic is partly overlaid
   on it.

3. **5,600 rows is small**, and Stage 1 is the bottleneck — see above. The classifier is
   already at ceiling, so all remaining work is in detection, not classification.

4. **Stage 1 caps everything.** Because Stage 2 is perfect on held-out attacks, end-to-end
   recall is exactly Stage 1's recall. Improving the classifier further is pointless.

5. **The notebooks are not runnable as saved.** `notebooks/03`–`07` need matplotlib, seaborn and
   jupyter, which are not in the virtualenv, and some contain stale imports and out-of-order
   cells. `src/` is the reproducible path; the notebooks are the exploration record.

---

## Running it

```bash
# 1. backend
uvicorn src.api.main:app --reload        # http://127.0.0.1:8000

# 2. frontend
cd frontend && npm install && npm run dev # http://127.0.0.1:5173
```

Retrain and evaluate:

```bash
cd src
$env:PYTHONPATH = (Get-Location).Path      # Windows; on macOS/Linux: export PYTHONPATH=$PWD

python training/train_anomaly.py           # writes anomaly_model.pkl
python training/train_classifier.py        # writes classifier.pkl
python training/train_hybrid.py            # rebundles hybrid_model.pkl

python inference/predict_hybrid.py         # full evaluation report
```

The console calls `POST /predict` with six floats and renders the verdict and threat gauge.

### API

| method | path | purpose |
|---|---|---|
| `GET` | `/` | service banner |
| `GET` | `/health` | liveness |
| `POST` | `/predict` | run the cascade on six features |
| `GET` | `/live_detection` | run the cascade on a random dataset row |

`POST /predict` returns `anomaly_pred`, `anomaly_score`, `attack_pred`, `final_prediction`,
`confidence` and `severity`. It delegates to `HybridDetector.predict`, the same code path as
`/live_detection` and the inference script — one decision policy, no divergence.

---

## Layout

```
src/
  models/
    anomaly_model.py         Stage 1 — IsolationForest, normal-only training
    classification_model.py  Stage 2 — RandomForest, LabelEncoder + scaler
    hybrid_model.py          the cascade that gates and combines them
  training/                  train_anomaly / train_classifier / train_hybrid
  inference/                 predict_hybrid — end-to-end evaluation
  api/main.py                FastAPI app
data/raw/                    10 Raspberry Pi capture files
data/processed/              pipeline output; engineered_dataset.csv is the model input
outputs/models/              3 joblib artifacts
outputs/figures/             EDA plots from the notebooks
frontend/                    React + TanStack Router + Tailwind SOC console
notebooks/                   exploration and analysis record
```

`sys.path` must include `src/` — `hybrid_model.pkl` is a whole-object pickle that resolves
`models.hybrid_model.HybridDetector` by name, and `api/main.py` appends that path at line 282.