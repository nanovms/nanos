#!/bin/bash

cd .. && make run-nokvm &

sleep 2

curl -i -f -XGET http://127.0.0.1:8080 | grep '200 OK' || exit 1
