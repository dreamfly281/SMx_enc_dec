$(ARCHS_STANDARD_32_BIT)
smx_app: sm2.c sm3.c smx_test.c
	gcc sm2.c sm3.c smx_test.c -o smx_test -I/usr/local/opt/openssl/include -lssl -lcrypto -L/usr/local/opt/openssl/lib
