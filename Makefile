SUB_DIRS := sdtsm sdtsmjni

.PHONY: all

all:
	@if pwd | grep -q ' '; then echo 'Error: source code is stored in a path containing spaces' >&2; exit 1; fi

	@for DIR in $(SUB_DIRS); do \
		$(MAKE) -C $$DIR || exit $?; \
	done	
	
.PHONY: clean

clean:
	@if pwd | grep -q ' '; then echo 'Error: source code is stored in a path containing spaces' >&2; exit 1; fi

	@for DIR in $(SUB_DIRS); do \
		$(MAKE) -C $$DIR clean|| exit $?; \
	done
	
.PHONY: install

install:
	@if pwd | grep -q ' '; then echo 'Error: source code is stored in a path containing spaces' >&2; exit 1; fi

	@for DIR in $(SUB_DIRS); do \
		$(MAKE) -C $$DIR install|| exit $?; \
	done
