SHARELIBLDFLAGS=-shared -fPIC
LIBCFLAGS=-Wall -Wstrict-prototypes -O2 -fPIC

CFLAGS += $(LIBCFLAGS) 
LDFLAGS +=-L../lib -lsdtsm

OPT = -O2
TGT = libsdtsmjni.so
OBJ = SdtSMJniApi.o

all:$(TGT)

$(TGT):$(OBJ)
	$(CC) $(SHARELIBLDFLAGS) -o $(TGT) $(OBJ) $(LDFLAGS)
	cp $(TGT) ../lib
	
SdtSMJniApi.o:SdtSMJniApi.c
	$(CC) -c $(CFLAGS) $? -o $@

	
clean:
	rm -rf *.o  *.bak $(TGT) 
	

