# Performance Evaluation of MANET Routing Protocols under UDP Flooding DoS

This repository contains the **ns-3.48** simulation code, batch execution scripts, summary results and Python analysis scripts used for an MSc Cyber Security project evaluating the performance of Mobile Ad Hoc Network (MANET) routing protocols under UDP flooding Denial-of-Service (DoS) attacks.

The study compares the following routing protocols:

* AODV
* DSDV
* OLSR

The evaluation considers baseline performance, node mobility and increasing attacker density.

## Repository Structure

```text
analysis/
├── aodv_dsdv_analysis.py
└── olsr_analysis.py

results/
├── aodv-summary.csv
├── dsdv-summary.csv
└── olsr-summary.csv

scripts/
├── run_aodv_seeds.sh
├── run_dsdv_seeds.sh
└── run_olsr_seeds.sh

src/
└── manet-dos-compare-metrix-v2.cc
```

## Simulation Environment

The experiments were implemented and executed using **ns-3.48**.

The simulation is based on the ns-3 MANET routing comparison example and extends it with:

* Configurable UDP flooding DoS attackers
* AODV, DSDV and OLSR routing protocol selection
* Mobility-speed variation
* Attacker-density variation
* Repeated random-seed execution
* FlowMonitor-based performance measurement
* CSV output generation

## Experimental Design

Each routing protocol was evaluated using **10 random seeds**.

Eight configurations were executed for each seed, resulting in:

```text
10 seeds × 8 configurations = 80 runs per protocol
```

The experiments are organised into the following sets:

* **Set A — Baseline:** No attack at a maximum node speed of 10 m/s
* **Set B — One-attacker DoS:** One UDP flooding attacker at 10 m/s
* **Set C — Mobility without attack:** Mobility variation at 2, 5 and 10 m/s without DoS
* **Set D — Mobility under DoS:** Mobility variation at 2, 5 and 10 m/s with one attacker
* **Set E — Attacker-density sweep:** One, three and five attackers at 10 m/s

The 10 m/s configurations in Sets C and D are provided by Sets A and B respectively, while the one-attacker configuration in Set E is provided by Set B.

## Running the Simulation

The simulation source file must be placed inside the `scratch` directory of an **ns-3.48** installation.

For example:

```bash
cp src/manet-dos-compare-metrix-v2.cc ~/workspace/ns-3.48/scratch/
```

The batch scripts are designed to be executed from the ns-3 root directory.

Copy the scripts into the ns-3.48 root directory:

```bash
cp scripts/run_aodv_seeds.sh ~/workspace/ns-3.48/
cp scripts/run_dsdv_seeds.sh ~/workspace/ns-3.48/
cp scripts/run_olsr_seeds.sh ~/workspace/ns-3.48/
```

Move to the ns-3.48 root directory:

```bash
cd ~/workspace/ns-3.48
```

Run the AODV experiments:

```bash
bash run_aodv_seeds.sh
```

Run the DSDV experiments:

```bash
bash run_dsdv_seeds.sh
```

Run the OLSR experiments:

```bash
bash run_olsr_seeds.sh
```

Each script executes seeds 1–10 across the experimental configurations and produces protocol-specific CSV output.

## Summary Results

The `results` directory contains the summary CSV files:

```text
aodv-summary.csv
dsdv-summary.csv
olsr-summary.csv
```

Each summary file contains one row for each individual simulation run.

Each protocol therefore contains **80 summary rows**, corresponding to 10 seeds across eight experimental configurations.

The summary files are used as input to the Python analysis scripts.

## Data Analysis

The analysis scripts group the simulation results by experimental configuration and calculate the **mean** and **standard deviation** across the 10 random seeds.

Python's `statistics` module is used for the statistical calculations, while `matplotlib` is used to generate figures.

### AODV and DSDV Analysis

Run:

```bash
python3 analysis/aodv_dsdv_analysis.py results/aodv-summary.csv results/dsdv-summary.csv
```

This script compares AODV and DSDV and generates aggregated tables and performance figures.

### OLSR Analysis

Run:

```bash
python3 analysis/olsr_analysis.py results/olsr-summary.csv
```

This script performs the OLSR-specific analysis, including mobility and attacker-density evaluation.

## Performance Metrics

The main performance metrics evaluated are:

* Packet Delivery Ratio (PDR)
* Throughput
* Average end-to-end delay
* Transmitted packets
* Received packets

FlowMonitor is used to obtain performance statistics from the legitimate application traffic.

Legitimate UDP application traffic uses destination port **9**, while UDP flooding attack traffic uses destination port **9999**.

Attack traffic is excluded from the reported FlowMonitor performance calculations so that the measured results represent the performance of legitimate application traffic under attack conditions.

## UDP Flooding DoS Model

The DoS attack is implemented using additional UDP `OnOffHelper` applications.

When the attack is enabled, selected attacker nodes continuously transmit UDP traffic towards the configured target node during the attack period.

The number of attacking nodes can be varied using the simulation command-line parameters, allowing the effect of increasing attacker density to be evaluated.

## Repeated-Seed Execution

The experiments use a fixed ns-3 global random seed while varying the run number.

The same run numbers are reused across AODV, DSDV and OLSR to provide comparable randomised mobility conditions across the routing protocols.

Ten runs are performed for each experimental configuration.

## Requirements

The project requires:

* ns-3.48
* Python 3
* matplotlib

The Python standard-library `statistics` module is used for calculation of the mean and standard deviation.

## Project Purpose

This repository accompanies an MSc Cyber Security dissertation investigating the impact of UDP flooding DoS attacks on routing performance in Mobile Ad Hoc Networks.

The repository is provided to support reproducibility of the simulation experiments and the analysis presented in the dissertation.
