# Misabort Source Code

This repository contains the source code for Misabort, a static analysis pipeline designed for pseudo-abortive vulnerability detection and semantic intent analysis of binary executables. 

The pipeline integrates static analysis, a trained CLAP model, and LLM-based evaluations to assess caller/callee behaviors and identify bugs.

## 📂 Core Analysis Modules

### 1. Feature Extraction & Rule-Based Filtering
* Callee_Functionality.py
  Performs Rule-Based Callee Functionality Analysis to determine the underlying behavior of target functions.
* Caller_Intent_Filterring.py
  Executes Rule-Based Caller Intent Filtering to narrow down the target callers based on their execution context.

### 2. Machine Learning & Semantic Intent Analysis
* Intent_context_extraction.py
  Extracts relevant code snippets and context from the binary. These extractions are used for training and testing the CLAP model.
* models/ (Directory)
  Contains the pre-trained CLAP model weights and architecture definitions.

### 3. Bug Assessment
* Rule_based_bug_assessment.py
  An angr-based script that utilizes symbolic execution and rule sets to perform localized bug assessment.
* LLM_based_bug_assessment.py
  Queries an LLM to perform semantic bug assessment on the identified code paths.
* request.yaml
  The prompt template and configuration file used by the LLM-based bug assessment script.

## ⚙️ Orchestration & Utilities

### Runners
* run.py
  The main entry point to batch process and orchestrate the rule-based scripts.
* run_llm.py
  A dedicated runner for orchestrating the LLM analysis and assessment phases.

### APIs & Data Management
* ida_api.py
  IDAPython utility scripts and API wrappers used to interface with IDA Pro for binary feature extraction and analysis.
* call_api.py & llm_analysis.py
  Helper scripts handling the API requests, response parsing, and core logic for interacting with the LLM backend.
* database.py
  Handles SQLite database connections, schema creation, and data insertion.
* static_analysis.db
  The SQLite database created automatically after the Rule-Based Caller Intent Filtering phase. It is incrementally filled to log state and save intermediate/final analysis results.
* config.py
  Global configuration parameters and environment variables for the pipeline.
* util.py
  General helper functions (e.g., file I/O, string processing, logging) shared across multiple modules.