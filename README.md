# SOCProbe

SOCProbe is a local SOC assessment tool for small and medium-sized business environments. It is designed to run on a Windows Server environment and assess security posture by auditing Active Directory and Windows Security Logs.

The tool performs a lightweight local readiness assessment and produces:
- security findings
- a structured JSON report
- a formatted PDF report
- a SOC readiness score

This project was built as a cybersecurity capstone proof of concept focused on a single-company local deployment model. It is not a multi-tenant platform or web dashboard. The current scope is a local desktop application and backend assessment engine. :contentReference[oaicite:0]{index=0}

## Core Features

- Active Directory connectivity and analysis
- Windows Security Log / Event Viewer integration
- Privileged group analysis
- Stale account detection
- Disabled privileged account detection
- Event telemetry summary
- Weighted rule-based SOC readiness scoring
- JSON report generation
- PDF report generation
- Local desktop UI for running scans and reviewing results
- Separate lab/demo simulator utility for generating controlled AD and Security Log activity

## Project Scope

### Current Capstone Scope
- Single-company local deployment
- Windows Server 2022 lab environment
- Local Python-based assessment tool
- Desktop UI for scan execution and result review
- JSON and PDF reporting
- Transparent weighted scoring model

### Future Scope
- Web dashboard
- Multi-company / multi-client support
- Historical trend dashboards
- Scheduled scans
- Backend API services
- Enterprise deployment model

## Architecture Overview

SOCProbe is organized around these main components:

- Config Loader
- AD Connector
- Event Log Reader
- Analysis Engine
- Scoring Engine
- Report Generator
- Desktop UI
- Activity Simulator

The tool connects to Active Directory using LDAP, reads Windows Security Log telemetry, analyzes identity and monitoring posture, calculates a readiness score, and generates reports. This matches the intended capstone architecture and goal of bridging security best practices with real environment validation. :contentReference[oaicite:1]{index=1}

## Scoring Model

SOCProbe uses a custom weighted rule-based scoring model.

**Formula:**

`Readiness Score = (Passed Control Weight / Total Control Weight) × 100`

### Current Control Weights
- Privileged group analysis = 30
- Stale account detection = 25
- Disabled privileged account detection = 15
- Log validation = 30

### Readiness Tiers
- 80–100 = High
- 60–79 = Moderate
- 40–59 = Low
- Below 40 = Poor

The checks are framework-informed, but the numerical scoring model itself is a custom academic model designed to be transparent, explainable, and defensible during the capstone presentation. The current generated report reflects this model directly. :contentReference[oaicite:2]{index=2}

## Main Files

### Entry Points
- `ui.py` - launches the main SOCProbe desktop application
- `main.py` - runs the backend assessment flow directly
- `launch_socprobe.pyw` - Windows launcher for the main app
- `socprobe_activity_simulator.py` - launches the separate activity simulator utility
- `launch_socprobe_activity_simulator.pyw` - Windows launcher for the simulator

### Main UI
- `socprobe_desktop.py` - final main desktop UI

### Documentation
- `PROJECT_EXPLANATION.md` - detailed walkthrough of the full project
- `README.md` - overview, setup, and usage
- `config.template.json` - sample configuration template

### Backend Modules
Located in `modules/`:
- `config_loader.py`
- `ad_connector.py`
- `event_log_reader.py`
- `log_validation.py`
- `analysis_engine.py`
- `privileged_group_analyzer.py`
- `stale_account_detector.py`
- `disabled_account_checker.py`
- `scoring_engine.py`
- `report_generator.py`

## Requirements

- Windows Server environment
- Python 3.11+ installed
- Active Directory available and reachable
- Permission to query AD
- Permission to read the Windows Security log
- Required Python packages installed from `requirements.txt`

## Setup

Clone the repository:

```bash
git clone https://github.com/siddahsa/SOCProbe.git
cd SOCProbe