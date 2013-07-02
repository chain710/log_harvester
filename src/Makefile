CPP = g++
C = gcc

INCLUDE = -I../
LIBS = 
C_ARGS = -g -Wall -D_FILE_OFFSET_BITS=64 -D__STDC_FORMAT_MACROS -D_REENTRANT $(INCLUDE) 

BINARY = demo
demo_dep = sha1.o base64.o demo_app.o harvester.o http_parser.o websocket_codec.o
demo_lib = -L../ -lcalypso_main -L/home/game/jsoncpp/lib -ljsoncpp -llog4cplus -lgflags -lpthread -ldl

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
