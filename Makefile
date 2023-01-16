##
# Interceptor
#
# @file
# @version 0.1
TARGET = interceptor.ko

all: build

build:
	@cd src && $(MAKE) build
	cp -f src/${TARGET} .

clean:
	@cd src && $(MAKE) clean
	rm -rf ${TARGET}

# end
