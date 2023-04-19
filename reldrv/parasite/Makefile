TARGET=$(shell uname -m)-unknown-linux-gnu

ELF_FILE=target/$(TARGET)/release/parasite

.PHONY: clean dis

all: parasite.h

parasite.h: $(ELF_FILE)
	compel hgen -f $(ELF_FILE) -o parasite.h

$(ELF_FILE): src/* src/commands/*
	cargo build --release --target $(TARGET)

clean:
	cargo clean
	rm -f parasite.h
