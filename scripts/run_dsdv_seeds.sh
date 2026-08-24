#!/usr/bin/env bash
# ==================================================================
# run_dsdv_seeds.sh
# Runs all five sets (A-E) for DSDV, seeds 1..SEEDS.
# Appends to dsdv-summary.csv (one summary row per run).
# Run from your ns-3 root directory:  bash run_dsdv_seeds.sh
# ==================================================================
set -e

SEEDS=10
PROTO=DSDV
SCEN="scratch/manet-dos-compare-metrix-v2"
SUMMARY="dsdv-summary.csv"

rm -f "$SUMMARY"

for seed in $(seq 1 $SEEDS); do
  echo "========  DSDV  SEED $seed  ========"

  # Set A: baseline, no attack, speed 10
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=false --numAttackers=0 --nodeSpeed=10 --seed=$seed --CSVfileName=dsdv-setA-normal-speed10-seed$seed.csv --summaryFile=$SUMMARY"

  # Set B: DoS, 1 attacker, speed 10
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=true --numAttackers=1 --nodeSpeed=10 --seed=$seed --CSVfileName=dsdv-setB-dos-attackers1-speed10-seed$seed.csv --summaryFile=$SUMMARY"

  # Set C: mobility no attack, speeds 2 and 5 (10 covered by A)
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=false --numAttackers=0 --nodeSpeed=2 --seed=$seed --CSVfileName=dsdv-setC-normal-speed2-seed$seed.csv --summaryFile=$SUMMARY"
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=false --numAttackers=0 --nodeSpeed=5 --seed=$seed --CSVfileName=dsdv-setC-normal-speed5-seed$seed.csv --summaryFile=$SUMMARY"

  # Set D: mobility under DoS, speeds 2 and 5 (10 covered by B)
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=true --numAttackers=1 --nodeSpeed=2 --seed=$seed --CSVfileName=dsdv-setD-dos-attackers1-speed2-seed$seed.csv --summaryFile=$SUMMARY"
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=true --numAttackers=1 --nodeSpeed=5 --seed=$seed --CSVfileName=dsdv-setD-dos-attackers1-speed5-seed$seed.csv --summaryFile=$SUMMARY"

  # Set E: attacker density 3 and 5, speed 10 (1 covered by B)
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=true --numAttackers=3 --nodeSpeed=10 --seed=$seed --CSVfileName=dsdv-setE-dos-attackers3-speed10-seed$seed.csv --summaryFile=$SUMMARY"
  ./ns3 run "$SCEN --protocol=$PROTO --enableDos=true --numAttackers=5 --nodeSpeed=10 --seed=$seed --CSVfileName=dsdv-setE-dos-attackers5-speed10-seed$seed.csv --summaryFile=$SUMMARY"

done

echo ""
echo ">>> DSDV done. Seeds 1..$SEEDS, 8 configs each = $((SEEDS*8)) runs."
