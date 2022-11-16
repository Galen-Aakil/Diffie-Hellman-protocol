LDFLAGS =  -L/usr/local/opt/openssl/lib
CPPFLAGS = -I/usr/local/opt/openssl/include

all: c s sc
c: DH_c.c
	gcc $< -lm -lcrypto -lssl -std=c99 -O2 -o $@ $(LDFLAGS) $(CPPFLAGS)
s: DH_s.c
	gcc $< -lm -lcrypto -lssl -std=c99 -O2 -o $@ $(LDFLAGS) $(CPPFLAGS)
sc: DH_sc.c
	gcc $< -lm -lcrypto -lssl -std=c99 -O2 -o $@ $(LDFLAGS) $(CPPFLAGS)
