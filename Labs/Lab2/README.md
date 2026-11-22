# Lab 2 Submission: Anomaly Detection for Cybersecurity Logs

## Contents
- `AnomalyDetectionComparison.ipynb`: the completed notebook, saved with outputs
- `Synthetic_PtH.csv`: the dataset, which must stay in the same folder as the notebook

## Scenario
Synthetic enterprise authentication logs: 10,000 events, 2.5% of them Pass-the-Hash lateral movement attacks (MITRE ATT&CK T1550.002, T1078). Normal events are mostly `WS -> SRV` Kerberos sessions, plus benign NTLM traffic (`IT-JUMP -> WS` admin sessions and direct-IP file share fallbacks).

## Method
- **Split:** chronological, with normal records divided 60/20/20 into train, validation and test. The test set also holds 50 attacks (2.5%).
- **Model A, Isolation Forest:** one-hot categorical features and scaled numeric features, trained on normal training data only.
- **Model B, Autoencoder:** trainable categorical embeddings and standardized numeric inputs, with an 8-dimensional latent layer. It is trained on normal training data only, and its score combines numeric and categorical reconstruction error.
- **Thresholds:** the 95th percentile of normal validation scores for both models.

## Results (test set, n = 2,000, 50 attacks)

| Measure | Isolation Forest | Autoencoder + embeddings |
|---|---:|---:|
| Detected anomalies | 96 | 183 |
| Precision | 0.1250 | 0.2732 |
| Recall | 0.2400 | 1.0000 |
| F1 score | 0.1644 | 0.4292 |
| False positives | 84 | 133 |
| False negatives | 38 | 0 |

On this dataset and with these settings, the Autoencoder had the higher F1 because it caught all 50 attacks. Isolation Forest had fewer false positives but missed 38 attacks. These results come from one run and should not be read as a general ranking of the two methods.
