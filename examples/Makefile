all: hw web hwg webg

hwg: hwg.go
	go build hwg.go

hw: hw.c
	cc hw.c -o hw

web: web.c
	cc web.c -g -o web

webg: webg.go
	go build webg.go

clean:
	rm -f hw web hwg webg


