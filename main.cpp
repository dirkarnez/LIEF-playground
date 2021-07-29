#include <iostream>
#include <memory>
#include <fstream>
#include <algorithm>
#include <iterator>

#include <LIEF/PE.hpp>

int main(int argc, char** argv) {
	const std::string name = "pe_from_scratch.exe";

	LIEF::PE::Binary binary64(name, LIEF::PE::PE_TYPE::PE32_PLUS);
	LIEF::PE::Builder temp(&binary64);
	LIEF::PE::Builder* builder64 = &temp;

	LIEF::PE::Section text_section{ ".text" };
	// https://github.com/TinyCC/tinycc/blob/mob/x86_64-asm.h
	std::vector<uint8_t> code = {
		0x48, 0x83, 0xC4, 0x48,				// add rsp, 0x48; Stack unwind
		0x48, 0x31, 0xC9,				// xor rcx, rcx; hWnd
		0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00,	// mov rdx, Message(0x402010)
		0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00,	// mov r8, Title(0x402000)
		0x4D, 0x31, 0xC9,				// xor r9, r9; MB_OK
		0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00,	// mov rax, MessageBoxA address(0x40305c)
		0xFF, 0x10,					// call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
		0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
		0x48, 0xC7, 0xC0, 0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
		0xFF, 0x10,					// call[rax]; ExitProcess(0)
		0xC3						// ret; Never reached
	};

	text_section.content(std::move(code));
	text_section.virtual_address(0x1000);
	text_section.add_type(LIEF::PE::PE_SECTION_TYPES::TEXT);
	binary64.add_section(text_section);

	LIEF::PE::Section data_section{ ".data" };
	data_section.add_type(LIEF::PE::PE_SECTION_TYPES::DATA);
	std::vector<uint8_t> data = {
		76, 73, 69, 70, 32, 105, 115, 32, 97, 119, 101, 115, 111, 109, 101, 0, 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 0
	};

	data_section.content(std::move(data));
	data_section.virtual_address(0x2000);
	binary64.add_section(data_section);

	binary64.optional_header().addressof_entrypoint(text_section.virtual_address());

	binary64.add_library("user32.dll").add_entry("MessageBoxA");
	binary64.add_library("kernel32.dll").add_entry("ExitProcess");
	std::cout << binary64.predict_function_rva("kernel32.dll", "ExitProcess") << std::endl;
	std::cout << binary64.predict_function_rva("user32.dll", "MessageBoxA") << std::endl;

	builder64->build_imports(true);
	builder64->patch_imports(false);
	builder64->build_tls(false);
	builder64->build_resources(false);
	builder64->build();
	builder64->write(name);

	std::cout << binary64.name() << std::endl;

	return 0;
}
