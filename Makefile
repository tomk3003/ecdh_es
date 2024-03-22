BINARIES = bin/ecdh_es_decrypt bin/debug_ecdh_es_decrypt

all: $(BINARIES)

bin/ecdh_es_decrypt: src/ecdh_es_decrypt.c
	@mkdir -p `dirname $@`
	$(CC) $< -o $@

bin/debug_ecdh_es_decrypt: src/ecdh_es_decrypt.c
	@mkdir -p `dirname $@`
	$(CC) $< -o $@ -DDEBUG

test: all
	prove -l t

clean:
	-rm $(BINARIES) 2>/dev/null
	-rmdir bin

.PHONY: all test
