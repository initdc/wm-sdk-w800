TOP_DIR = ../../..
sinclude $(TOP_DIR)/tools/w800/conf.mk

ifndef PDIR
GEN_LIBS = libmatrixssl-4-3-0-open$(LIB_EXT)
COMPONENTS_libmatrixssl-4-3-0-open = core/libmatrixsslcore$(LIB_EXT)\
							matrixssl/libcmatrixssl$(LIB_EXT)\
							crypto/libmcrypto$(LIB_EXT)
													
endif

#DEFINES +=

sinclude $(TOP_DIR)/tools/w800/rules.mk

INCLUDES := $(INCLUDES) -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile