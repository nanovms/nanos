eyberg@bench:~$ ab -c 10 -n 1000 http://10.240.0.38:8080/
This is ApacheBench, Version 2.3 <$Revision: 1757674 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 10.240.0.38 (be patient)
Completed 100 requests
Completed 200 requests
Completed 300 requests
Completed 400 requests
Completed 500 requests
Completed 600 requests
Completed 700 requests
Completed 800 requests
Completed 900 requests
Completed 1000 requests
Finished 1000 requests


Server Software:
Server Hostname:        10.240.0.38
Server Port:            8080

Document Path:          /
Document Length:        22 bytes

Concurrency Level:      10
Time taken for tests:   0.055 seconds
Complete requests:      1000
Failed requests:        0
Total transferred:      139000 bytes
HTML transferred:       22000 bytes
Requests per second:    18313.68 [#/sec] (mean)
Time per request:       0.546 [ms] (mean)
Time per request:       0.055 [ms] (mean, across all concurrent requests)
Transfer rate:          2485.94 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.2      0       2
Processing:     0    0   0.1      0       1
Waiting:        0    0   0.1      0       1
Total:          0    1   0.2      1       2

Percentage of the requests served within a certain time (ms)
  50%      1
  66%      1
  75%      1
  80%      1
  90%      1
  95%      1
  98%      1
  99%      2
 100%      2 (longest request)
