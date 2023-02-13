TOP_DIR = ../../../../..
sinclude $(TOP_DIR)/tools/w800/conf.mk

ifndef PDIR
GEN_LIBS = libosdep$(LIB_EXT)
COMPONENTS_libosdep =  ANSI/libANSI$(LIB_EXT) \
											src/libossrc$(LIB_EXT)
endif

#DEFINES +=

sinclude $(TOP_DIR)/tools/w800/rules.mk

INCLUDES := $(INCLUDES) -I $(PDIR)include
PDIR := ../$(PDIR)
sinclude $(PDIR)Makefile