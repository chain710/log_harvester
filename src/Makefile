CPP = g++
C = gcc

INCLUDE = -I../ -I/home/game/calypso
LIBS = 
C_ARGS = -g -Wall -D_FILE_OFFSET_BITS=64 -D__STDC_FORMAT_MACROS -D_REENTRANT $(INCLUDE) 

BINARY = demo
demo_dep = sha1.o base64.o log_agent.o harvester.o http_parser.o websocket_codec.o log_agent_global.o log_agent.pb.o
demo_lib = -L/home/game/calypso -lcalypso_main -L/home/game/jsoncpp/lib -ljsoncpp -llog4cplus -lgflags -lprotobuf -lpthread -ldl

ALL_OBJS = $(foreach d,$(BINARY),$($(subst .,_,$(d))_dep))

%.o : %.cpp
	$(CPP) $(C_ARGS) -c  $< -o $(patsubst %.cpp,%.o,$<)
%.o : %.cc
	$(CPP) $(C_ARGS) -c  $< -o $(patsubst %.cc,%.o,$<)
%.o : %.c
	$(C) $(C_ARGS) -c  $< -o $(patsubst %.c,%.o,$<)
	
all : $(BINARY)

$(BINARY) : $(ALL_OBJS)
	@echo "now building:" $@
	@echo "dep:" $($(subst .,_,$@)_dep)
	rm -f $@
	$(CPP) $(C_ARGS) -o $@ $($(subst .,_,$@)_dep) $(LIBS) $($(subst .,_,$@)_lib)

clean:
	rm -f $(ALL_OBJS) $(BINARY)

print:
	@echo "print all vars"
	@echo "all objs:" $(ALL_OBJS)
