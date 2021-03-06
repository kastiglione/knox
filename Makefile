CXXFLAGS := -Wall -std=c++14 -O2

all: auditon auditpipe commands paudit pwait

auditon: auditon.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -lbsm -o $@ auditon.cpp

auditpipe: auditpipe.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -lbsm -o $@ auditpipe.cpp

commands: commands.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -lbsm -o $@ commands.cpp

paudit: paudit.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -lbsm -o $@ paudit.cpp

pwait: pwait.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -lbsm -o $@ pwait.cpp
