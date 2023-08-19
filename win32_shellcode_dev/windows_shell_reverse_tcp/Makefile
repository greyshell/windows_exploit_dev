SHELLCODE=windows7_shell_reverse_tcp
TEST=test-windows7_shell_reverse_tcp


all: build hex

all-test: test-build test-run

all-clean: clean test-clean


build: $(SHELLCODE).o
	ld -m elf_i386 -o $(SHELLCODE) $(SHELLCODE).o
	@echo "" 

$(SHELLCODE).o: $(SHELLCODE).asm
	nasm -f elf32 -o $(SHELLCODE).o $(SHELLCODE).asm
	@echo ""

run: $(SHELLCODE)
	./$(SHELLCODE)

debug: $(SHELLCODE)
	gdb -q ./$(SHELLCODE) -tui

disassemble: $(SHELLCODE)
	objdump -d $(SHELLCODE) -M intel

hex: $(SHELLCODE)
	@echo "Size of shellcode:"
	@size $(SHELLCODE)
	@echo ""
	@echo "Shellcode:"
	@objdump -d ./$(SHELLCODE)|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:| \
	cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed "s| $$||g" |sed "s/ /\\\\x/g"| \
	paste -d '' -s | sed "s|^|\"|" | sed "s|$$|\"|g" > $(SHELLCODE).txt
	@cat $(SHELLCODE).txt
	@echo ""

clean:
	rm -f $(SHELLCODE).txt
	rm -f $(SHELLCODE).o
	rm -f $(SHELLCODE)


test-build: $(TEST)

temp:
	@cat $(SHELLCODE).txt | sed 's|\\|\\\\|g' > temp

$(TEST): $(SHELLCODE).txt temp
	@cp /root/pentest/myScript/test.c.template ./
	@sed 's/SHELLCODE/$(shell cat temp)/' test.c.template > $(TEST).c
	gcc -m32 $(TEST).c -fno-stack-protector -z execstack -ggdb -o $(TEST)
	file  $(TEST)
	@echo ""
	i586-mingw32msvc-gcc $(TEST).c -lws2_32 -o $(TEST).exe
	file  $(TEST).exe
	@echo ""
	@rm -f temp
	@rm -f test.c.template 

test-run: $(TEST)
	./$(TEST)

test-debug: $(TEST)
	gdb -q ./$(TEST) -tui

test-clean:
	rm -f $(TEST)
	rm -f $(TEST).c
	rm -f $(TEST).exe
