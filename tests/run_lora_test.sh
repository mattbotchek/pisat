#!/bin/sh
set -eux
# Compile and run the receive-once test
sudo rm -f /run/pigpio.pid /var/run/pigpio.pid || true
sudo g++ /tmp/lora_receive_once.cpp -o /tmp/pisat_test_recv -lpigpio || true
sudo env LD_LIBRARY_PATH=/usr/local/lib /tmp/pisat_test_recv > /tmp/pisat_test_recv.log 2>&1 &
PID=$!
# wait for up to 25s
for i in $(seq 1 25); do
  if ! ps -p $PID > /dev/null 2>&1; then break; fi
  sleep 1
done
sleep 1
cat /tmp/pisat_test_recv.log || true
if grep -q "RECEIVED PING" /tmp/pisat_test_recv.log; then
  echo "TEST OK"
  exit 0
else
  echo "TEST FAIL"
  exit 2
fi
