
# main Makefile
# troquei: -std=c99 para c11
CFLAGS = -std=c11 -g -pedantic -Wall -Wextra \
         -Wno-missing-field-initializers \
         -fdata-sections -ffunction-sections

ifdef disable-log
	CFLAGS += -DCHARRA_LOG_DISABLE
endif
ifdef disable-log-color
	CFLAGS += -DCHARRA_LOG_DISABLE_COLOR
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
             mbedcrypto \
             util tss2-esys tss2-sys tss2-mu tss2-tctildr

# TCTI module to use (default is 'mssim')
TCTI_MODULE=tss2-tcti-mssim
ifdef with-tcti
	TCTI_MODULE=tss2-tcti-$(with-tcti)
	#@echo "Using tss2-tcti-"$(WITH_TCTI)
endif
LIBS += $(TCTI_MODULE)


LDFLAGS_DYNAMIC = $(addprefix -l, $(LIBS))

LDFLAGS_STATIC = $(addprefix -l:lib, $(addsuffix .a, $(LIBS)))


ifdef address-sanitizer
	CFLAGS += -fsanitize=address
	LDFLAGS_STATIC += -fsanitize=address
	LDFLAGS_DYNAMIC += -fsanitize=address
endif



SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =  $(addsuffix .o, $(addprefix $(OBJDIR)/common/, charra_log))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/core/, charra_helper charra_key_mgr charra_rim_mgr charra_marshaling))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/util/, cbor_util charra_util coap_util crypto_util io_util tpm2_util cli_util parser_util))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/ra_iot_libs/, ra_iot_memory_mgmt ra_iot_mbedtls ra_iot_crypto ra_iot_evidence_mgmt ra_iot_marshaling ra_iot_dto ra_iot_security))
#OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/ra_iot_libs/, ra_iot_memory_mgmt ra_iot_mbedtls ra_iot_crypto ra_iot_evidence_mgmt ra_iot_marshaling ra_iot_dto ra_iot_test ra_iot_security))
#OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/ra_iot_libs/test_ra_iot/, test_ra_iot))


#verifier_target = verifier
#attester_target = attester

verifier_target = ra_iot_attester
attester_target = ra_iot_verifier



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

$(OBJDIR)/ra_iot_libs/%.o: $(SRCDIR)/ra_iot_libs/%.c
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
	$(RM) obj/core/*.*
	$(RM) obj/util/*.*
	$(RM) obj/ra_iot_libs/*.*
	$(RM) obj/*.*

cleanlibs: clean
	$(MAKE) -C lib/ clean

cleanall: cleanlibs clean
