TOP_DIR = ../../../..
sinclude $(TOP_DIR)/tools/w800/conf.mk

ifndef PDIR
GEN_LIBS = libmcrypto$(LIB_EXT)
COMPONENTS_libmcrypto = aead/libaead$(LIB_EXT) \
											common/libccommon$(LIB_EXT) \
											cypto_sign/libccrypto_sign$(LIB_EXT)\
											digest/libcdigest$(LIB_EXT)\
											keyformat/libckeyformat$(LIB_EXT)\
											layer/libclayer$(LIB_EXT)\
											math/libcmath$(LIB_EXT)\
											prng/libcprng$(LIB_EXT)\
											pubkey/libcpubkey$(LIB_EXT)\
											scalcarmult/libscalarmult$(LIB_EXT)\
											symmetric/libcsymmetirc$(LIB_EXT)
endif

#DEFINES +=

sinclude $(TOP_DIR)/tools/w800/rules.mk

INCLUDES := $(INCLUDES) -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile