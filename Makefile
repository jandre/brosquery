all: 
	mkdir -p build/ && cd build && cmake -Wno-dev .. && make --no-print-directory

deps:
	git submodule update --init --recursive
	cd ./third-party/osquery && make --no-print-directory deps
	cd ./third-party/osquery && make --no-print-directory
