
# main Makefile
# troquei: -std=c99 para c11
CFLAGS = -std=c11 -g -pedantic -Wall -Wextra \
         -Wno-missing-field-initializers \
         -fdata-sections -ffunction-sections

ifdef disable-log
	CFLAGS += -DRA2IOT_LOG_DISABLE
endif
ifdef disable-log-color
	CFLAGS += -DRA2IOT_LOG_DISABLE_COLOR
endif


SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin


LIBINCLUDE = -I/usr/include \
             -I/usr/local/include
             

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu

LIBS =       coap-2-tinydtls \
             qcbor m \
             crypto ssl \
             mbedcrypto 


LDFLAGS_DYNAMIC = $(addprefix -l, $(LIBS))

LDFLAGS_STATIC = $(addprefix -l:lib, $(addsuffix .a, $(LIBS)))


ifdef address-sanitizer
	CFLAGS += -fsanitize=address
	LDFLAGS_STATIC += -fsanitize=address
	LDFLAGS_DYNAMIC += -fsanitize=address
endif



SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =  $(addsuffix .o, $(addprefix $(OBJDIR)/common/, ra2iot_log))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/util/, cbor_util coap_util io_util cli_util))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/ra2iot_libs/, ra2iot_memory_mgmt ra2iot_mbedtls ra2iot_crypto ra2iot_evidence_mgmt ra2iot_marshaling ra2iot_dto ra2iot_security))

verifier_target = ra2iot_attester
attester_target = ra2iot_verifier



#TARGETS = $(addprefix $(BINDIR)/, attester verifier)
TARGETS = $(addprefix $(BINDIR)/, $(attester_target) $(verifier_target))



.PHONY: all all.static libs clean cleanlibs cleanall

## --- targets ------------------------------------------------------------ ##

all: LDFLAGS = $(LDFLAGS_DYNAMIC)
all: $(TARGETS)



all.static: LDFLAGS = $(LDFLAGS_STATIC)
all.static: $(TARGETS)


## address sanitizer
ifdef address-sanitizer
	@echo "Enabling address sanitizer."
	CFLAGS += -fsanitize=address
	LDFLAGS += -fsanitize=address
endif


$(BINDIR)/$(attester_target): $(SRCDIR)/$(attester_target).c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections
ifdef strip
	strip --strip-unneeded $@
endif

$(BINDIR)/$(verifier_target): $(SRCDIR)/$(verifier_target).c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections
ifdef strip
	strip --strip-unneeded $@
endif



## --- objects ------------------------------------------------------------ ##

$(OBJDIR)/common/%.o: $(SRCDIR)/common/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

$(OBJDIR)/core/%.o: $(SRCDIR)/core/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

$(OBJDIR)/util/%.o: $(SRCDIR)/util/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c

$(OBJDIR)/ra2iot_libs/%.o: $(SRCDIR)/ra2iot_libs/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c



## --- libraries ---------------------------------------------------------- ##

libs: 
	$(MAKE) -C lib/

libs.static: 
	$(MAKE) -C lib/ all.static

libs.install: 
	$(MAKE) -C lib/ install

libs.uninstall: 
	$(MAKE) -C lib/ uninstall


## --- clean -------------------------------------------------------------- ##

clean:
	$(RM) bin/*
	$(RM) obj/common/*.*
	$(RM) obj/util/*.*
	$(RM) obj/ra2iot_libs/*.*
	$(RM) obj/*.*

cleanlibs: clean
	$(MAKE) -C lib/ clean

cleanall: cleanlibs clean
