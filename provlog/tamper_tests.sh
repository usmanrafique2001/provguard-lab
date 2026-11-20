#!/usr/bin/env bash
# Runs the four tamper tests on copies of the Attack A log. The real evidence is never changed.
cd "$(dirname "$0")/.."
L=evidence/v2/events_attackA.jsonl
A=evidence/v2/anchors_attackA.jsonl
# The evidence logs were signed with this lab-only key, published so anyone can check them.
export PROVLOG_KEY=evidence/v2/demo.key
S1=00:00:00:00:00:00:00:01; S2=00:00:00:00:00:00:00:02
T=$(mktemp -d)
LAST=$(( $(grep -c . $L) - 1 ))

echo "### Original log"
python3 detector/replay.py $L $A

echo; echo "### Test 1: edit the incriminating entry (seq $LAST: h1 back on s1)"
cp $L $T/t1.jsonl
sed -i "$((LAST + 1))s/$S2/$S1/g" $T/t1.jsonl
python3 detector/replay.py $T/t1.jsonl $A

echo; echo "### Test 2: delete a middle entry (line 3)"
sed '3d' $L > $T/t2.jsonl
python3 detector/replay.py $T/t2.jsonl $A

echo; echo "### Test 3: cut off the last entry"
head -n $LAST $L > $T/t3.jsonl
echo "-- chain only:"; python3 detector/replay.py $T/t3.jsonl
echo "-- with checkpoint:"; python3 detector/replay.py $T/t3.jsonl $A

echo; echo "### Test 4: attacker with the key rewrites seq $LAST and re-signs the chain"
python3 provlog/forge.py $L $T/t4.jsonl $LAST $S2 $S1
echo "-- chain only:"; python3 detector/replay.py $T/t4.jsonl
echo "-- with checkpoint:"; python3 detector/replay.py $T/t4.jsonl $A
rm -rf $T
