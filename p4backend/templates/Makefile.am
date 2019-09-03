bin_PROGRAMS=ipfixprobe ipfixprobe_nsf

ipfixprobe_SOURCES=cache.c \
	cache.h \
	ipfix.c \
	ipfix.h \
	main.c \
	parser.c \
	parser.h \
	plugin.c \
	plugin.h \
	regex.c \
	regex.h \
	types.h \
	xxhash.c \
	xxhash.h

ipfixprobe_LDADD=-lpcap

ipfixprobe_nsf_SOURCES=cache.c \
	cache.h \
	ipfix.c \
	ipfix.h \
	parser.c \
	parser.h \
	plugin.c \
	plugin.h \
	regex.c \
	regex.h \
	types.h \
	xxhash.c \
	xxhash.h \
	main-nsf.cpp \
	sdm-parser.h

ipfixprobe_nsf_LDADD= -lpcap -lnsf -lnfb -lfdt -lnuma -lpthread -lcrypto -lssl -lm -lstdc++ -lpcap

EXTRA_DIST=README.md

