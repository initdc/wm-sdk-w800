TOP_DIR = ../../../../..
sinclude $(TOP_DIR)/tools/w800/conf.mk

ifndef PDIR
GEN_LIBS = libscalarmult$(LIB_EXT)
COMPONENTS_libscalarmult = curve25519/libccurve25519$(LIB_EXT)\
							cryptocore/libcrypto_core$(LIB_EXT)\
							ed25519/libed25519$(LIB_EXT)
endif

#DEFINES +=

sinclude $(TOP_DIR)/tools/w800/rules.mk

INCLUDES := $(INCLUDES) -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile