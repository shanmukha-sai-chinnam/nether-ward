# Nether Ward Detection Benchmark Report

Empirical evaluation of Nether Ward security engines against curated benchmark datasets.

## Executive Summary

| Metric | Value | Target | Status |
| :--- | :---: | :---: | :---: |
| Total Samples Evaluated | 38 | - | Validated |
| Overall Accuracy | 100.0% | >= 95.0% | PASSED |
| Precision (PPV) | 100.0% | >= 98.0% | PASSED |
| Recall / Sensitivity (TPR) | 100.0% | >= 95.0% | PASSED |
| F1 Score | 1.000 | >= 0.950 | PASSED |
| False Positive Rate (FPR) | 0.0% | <= 2.0% | PASSED |
| Mean Inspection Latency | 4.06 ms | <= 50.0 ms | OPTIMAL |
| 95th Percentile Latency (p95) | 7.82 ms | <= 100.0 ms | OPTIMAL |

## Confusion Matrix

| | Predicted Threat | Predicted Clean | Total |
| :--- | :---: | :---: | :---: |
| **Actual Threat** | **TP:** 22 | **FN:** 0 | 22 |
| **Actual Clean** | **FP:** 0 | **TN:** 16 | 16 |
| **Total** | 22 | 16 | 38 |

## Category Breakdown

| Category | Samples | Malicious | Detected | Precision | Recall | F1 Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Agent Execution Sandbox | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| Canary & Decoy Tripwire | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| Filesystem ACL Confinement | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM01: Prompt Injection | 4 | 3 | 3 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM02: Sensitive Info Disclosure | 3 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM03: Supply Chain Risk | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM04: Data & Model Poisoning | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM05: Improper Output Handling | 3 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM06: Excessive Agency / Command Execution | 4 | 2 | 2 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM07: System Prompt Leakage | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM08: Vector & Context Exploitation | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM09: Obfuscated Payloads | 2 | 1 | 1 | 100.0% | 100.0% | 1.000 | PASSED |
| LLM10: Path Traversal & Escape | 4 | 3 | 3 | 100.0% | 100.0% | 1.000 | PASSED |
