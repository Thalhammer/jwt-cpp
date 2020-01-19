SRC = $(shell find . -name '*.cpp') $(shell find . -name '*.c')
HEADERS = $(shell find . -name '*.h')
EXCLUDE_SRC = 
FSRC = $(filter-out $(EXCLUDE_SRC), $(SRC))
OBJ = $(FSRC:=.o)

DEP_DIR = .deps

FLAGS = -fPIC -Wall -Wno-unknown-pragmas -Werror -I include
CXXFLAGS = -std=c++11
CFLAGS = 
LINKFLAGS = -lcrypto -lgtest -lpthread

ifeq ($(PREFIX),)
    PREFIX := /usr
endif

OUTFILE = test

.PHONY: clean debug release check install

all: debug

debug: FLAGS += -g
debug: $(OUTFILE)

release: FLAGS += -O2 -march=native
release: $(OUTFILE)

$(OUTFILE): $(OBJ)
	@echo Generating binary
	@$(CXX) -o $@ $^ $(LINKFLAGS)
	@echo Build done

%.cc.o: %.cc
	@echo Building $<
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

%.cpp.o: %.cpp
	@echo Building $<
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CXX) -c $(FLAGS) $(CXXFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

%.c.o: %.c
	@echo Building $<
	@$(CC) -c $(FLAGS) $(CFLAGS) $< -o $@
	@mkdir -p `dirname $(DEP_DIR)/$@.d`
	@$(CC) -c $(FLAGS) $(CFLAGS) -MT '$@' -MM $< > $(DEP_DIR)/$@.d

clean:
	@echo Removing binary
	@rm -f $(OUTFILE)
	@echo Removing objects
	@rm -f $(OBJ)
	@echo Removing dependency files
	@rm -rf $(DEP_DIR)

check: $(OUTFILE)
	./$(OUTFILE)

install:
	@echo Installing headers
	@install -d $(DESTDIR)$(PREFIX)/include/jwt-cpp/
	@install -m 644 include/jwt-cpp/*.h $(DESTDIR)$(PREFIX)/include/jwt-cpp
	@echo Install done

-include $(OBJ:%=$(DEP_DIR)/%.d)
