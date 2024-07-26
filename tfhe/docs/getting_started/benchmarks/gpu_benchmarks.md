# GPU Benchmarks

This document details the GPU performance benchmarks of homomorphic operations using **TFHE-rs**.

All GPU benchmarks presented here were obtained on H100 GPUs, and rely on the multithreaded PBS algorithm. The cryptographic parameters `PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS` were used.

## 1xH100
Below come the results for the execution on a single H100.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/1pclBTWf23wfT50pfvdzIMTEiEHln7UxAh6dOX122i2w/edit?gid=0#gid=0" %}

The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1EdHoYkZVaVfvGWY60ifiZHcVregF9_oy7RHZkMkHHig/edit?gid=0#gid=0" %}

## 2xH100

Below come the results for the execution on two H100's.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/14VNBlpFjyggmdluQfVYkLVR10RiKhjP_DammKB5FuXw/edit?usp=sharing" %}


The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1jAKDP6bM09_HAkU8jrfXGpo3Lsh2E73HPSwVNAH0G4o/edit?usp=sharing" %}
