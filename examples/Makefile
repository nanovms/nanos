all: hw web hwg webg hws

hwg: hwg.go
	go build hwg.go

hw: hw.c
	cc hw.c -o hw

hws: hw.c
	cc hw.c -g -static -o hws

web: web.c
	cc web.c -g -o web

webg: webg.go
	go build webg.go

fst: fst.go
	go build fst.go

clean:
	rm -f hw web hwg webg


