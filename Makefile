CXXFLAGS := -Wall -std=c++14 -O2

all: auditon auditpipe commands

auditon: auditon.cpp
	xcrun clang++ $(CXXFLAGS) -lbsm -o $@ auditon.cpp

auditpipe: auditpipe.cpp
	xcrun clang++ $(CXXFLAGS) -lbsm -o $@ auditpipe.cpp

commands: commands.cpp
	xcrun clang++ $(CXXFLAGS) -lbsm -o $@ commands.cpp
