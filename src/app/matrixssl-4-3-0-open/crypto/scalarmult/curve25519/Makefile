TOP_DIR = ../../../../../..
sinclude $(TOP_DIR)/tools/w800/conf.mk

ifndef PDIR
GEN_LIBS = libccurve25519$(LIB_EXT)
COMPONENTS_libccurve25519 = ref10/libx25519_ref10$(LIB_EXT)\
							sandy2x/libcurve25519sandy2x$(LIB_EXT)
endif

#DEFINES +=

sinclude $(TOP_DIR)/tools/w800/rules.mk

INCLUDES := $(INCLUDES) -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile