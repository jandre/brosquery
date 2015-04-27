.phony:

deps:
	git submodule update --init --recursive
	cd ./third-party/osquery && make deps
	cd ./third-party/osquery && make

all: 
	mkdir -p build/ && cd build && cmake -Wno-dev .. && make
