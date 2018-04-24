all: hw web hwg

hwg: hwg.go
	go build hwg.go

hw: hw.c
	cc hw.c -o hw

web: web.c
	cc web.c -g -o web

clean:
	rm hw web hwg


