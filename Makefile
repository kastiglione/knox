CXXFLAGS := -Wall -std=c++14 -O2 -mmacos-version-min=10.10 -lbsm

all: auditon auditpipe commands paudit pwait

clean:
	rm -rf auditon auditpipe commands paudit pwait ./*.dSYM

auditon: auditon.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -o $@ auditon.cpp

auditpipe: auditpipe.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -o $@ auditpipe.cpp

commands: commands.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -o $@ commands.cpp

paudit: paudit.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -o $@ paudit.cpp

pwait: pwait.cpp
	xcrun -sdk macosx clang++ $(CXXFLAGS) -o $@ pwait.cpp
