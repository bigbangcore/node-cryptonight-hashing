#!/bin/bash -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR
node test.js
node test_k12.js
node test_sync-1.js
node test_sync-2.js
node test_sync-r.js
node test_sync-half.js
node test_sync-wow.js
node test_sync-msr.js
node test_sync-xao.js
node test_sync-rto.js
node test_sync-gpu.js
node test_sync-rwz.js
node test_sync-zls.js
node test_sync-double.js
node test_sync.js
node test_sync_light.js
node test_sync_light-1.js
node test_sync_heavy.js
node test_sync_heavy-xhv.js
node test_sync_heavy-tube.js
node test_sync_pico.js
node test_rx_defyx.js
node test_rx_wow.js
node test_rx_loki.js
node test_rx_switch.js
node test_ar2_chukwa.js
node test_ar2_wrkz.js

node test_perf.js
node test_perf_k12.js
node test_perf_light.js
node test_perf_heavy.js
node test_perf_gpu.js
node test_perf_rx_defyx.js
node test_perf_rx_wow.js
node test_perf_rx_loki.js
node test_perf_rx_switch.js
node test_perf_pico.js
node test_perf_double.js
node test_perf_ar2_chukwa.js
node test_perf_ar2_wrkz.js