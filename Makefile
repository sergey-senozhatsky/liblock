NAME       := liblock
MAJOR      := 0
MINOR      := 1
VERSION    := $(MAJOR).$(MINOR)
CFLAGS     := -std=c++14 -O2 -g -Wall -Werror -fPIC
CXXFLAGS   := $(CFLAGS)
CC         := g++
LDFLAGS    := -shared -rdynamic
LDLIBS     := -Wl,-Bdynamic -lpthread -lunwind -Wl,-Bdynamic -lstdc++ -lgcc_s -ldl
SOURCE     := $(wildcard *.cpp)
OBJECT     := $(SOURCE:.cpp=.o)

LIBSO      = $(NAME).so
LIBSOM     = $(LIBSO).$(MAJOR)
LIBSOV     = $(LIBSO).$(VERSION)

all: $(LIBSOV) test

$(LIBSOV): $(OBJECT)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

test: test.o
	$(CC) $^ $(LDLIBS) -o $@
	echo "LD_PRELOAD=./$(LIBSOV) ./test"

clean:
	$(RM) *.o *.so*
	$(RM) test

re: clean all test
