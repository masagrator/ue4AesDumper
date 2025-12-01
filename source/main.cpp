// Include the most common headers from the C standard library
#include <stdio.h>
#include <stdlib.h>

// Include the main libnx system header, for Switch development
#include <switch.h>
#include <sys/stat.h>
#include "dmntcht.h"
#include <algorithm>
#include <string>
#include <cstring>
#include "base64.hpp"
#include <math.h>
#include <array>
extern "C" {
#include "armadillo.h"
#include "strext.h"
}

DmntCheatProcessMetadata cheatMetadata = {0};
u64 mappings_count = 0;
MemoryInfo* memoryInfoBuffers = 0;
char path[128] = "";
uint8_t utf_encoding = 0;

bool isServiceRunning(const char *serviceName) {	
	Handle handle;	
	SmServiceName service_name = smEncodeName(serviceName);	
	if (R_FAILED(smRegisterService(&handle, service_name, false, 1))) 
		return true;
	else {
		svcCloseHandle(handle);	
		smUnregisterService(service_name);
		return false;
	}
}

template <typename T> T searchString(char* buffer, T string, u64 buffer_size, bool null_terminated = false, bool whole = false) {
	char* buffer_end = &buffer[buffer_size];
	size_t string_len = (std::char_traits<std::remove_pointer_t<std::remove_reference_t<T>>>::length(string) + (null_terminated ? 1 : 0)) * sizeof(std::remove_pointer_t<std::remove_reference_t<T>>);
	T string_end = &string[std::char_traits<std::remove_pointer_t<std::remove_reference_t<T>>>::length(string) + (null_terminated ? 1 : 0)];
	char* result = std::search(buffer, buffer_end, (char*)string, (char*)string_end);
	if (whole) {
		while ((uint64_t)result != (uint64_t)&buffer[buffer_size]) {
			if (!result[-1 * sizeof(std::remove_pointer_t<std::remove_reference_t<T>>)])
				return (T)result;
			result = std::search(result + string_len, buffer_end, (char*)string, (char*)string_end);
		}
	}
	else if ((uint64_t)result != (uint64_t)&buffer[buffer_size]) {
		return (T)result;
	}
	return nullptr;
}

std::string ue4_sdk = "";
bool isUE5 = false;
uint8_t key[32] = {0};

size_t checkAvailableHeap() {
	size_t startSize = 200 * 1024 * 1024;
	void* allocation = malloc(startSize);
	while (allocation) {
		free(allocation);
		startSize += 1024 * 1024;
		allocation = malloc(startSize);
	}
	return startSize - (1024 * 1024);
}

double calculateEntropy(uint8_t* data, size_t size) {
	double entropy = 0;
	for (size_t i = 0; i < size; i++) {
		if (data[i] == 0)
			continue;
		double p = (float)data[i] / (float)size;
		entropy -= p * (log(p) / log(256.d));
	}
	return entropy;
}

bool entropyCompare(std::array<uint8_t, 32> key1, std::array<uint8_t, 32> key2) {
	return calculateEntropy(&key1[0], 32) < calculateEntropy(&key2[0], 32);
}

bool checkIfUE4game() {
	size_t i = 0;
	while (i < mappings_count) {
		if ((memoryInfoBuffers[i].perm & Perm_R) == Perm_R && (memoryInfoBuffers[i].perm & Perm_Rx) != Perm_Rx && memoryInfoBuffers[i].type == MemType_CodeStatic) {
			if (memoryInfoBuffers[i].size > 200'000'000) {
				continue;
			}
			char test_4[] = "SDK MW+EpicGames+UnrealEngine-4";
			char test_5[] = "SDK MW+EpicGames+UnrealEngine-5";
			char* buffer_c = new char[memoryInfoBuffers[i].size];
			dmntchtReadCheatProcessMemory(memoryInfoBuffers[i].addr, (void*)buffer_c, memoryInfoBuffers[i].size);
			char* result = searchString(buffer_c, (char*)test_4, memoryInfoBuffers[i].size);
			if (result) {
				printf("%s\n", result);
				ue4_sdk = result;
				delete[] buffer_c;
				return true;
			}
			result = searchString(buffer_c, (char*)test_5, memoryInfoBuffers[i].size);
			if (result) {
				printf("%s\n", result);
				ue4_sdk = result;
				isUE5 = true;
				delete[] buffer_c;
				return true;
			}
			delete[] buffer_c;
		}
		i++;
	}
	printf("This game is not using Unreal Engine 4 or 5!\n");
	return false;
}

char* findStringInBuffer(char* buffer_c, size_t buffer_size, const char* description) {
	char* result = 0;
	result = (char*)searchString(buffer_c, (char*)description, buffer_size);
	return result;
}

uint8_t pattern[8] = {0x00, 0x04, 0x00, 0xAD, 0xC0, 0x03, 0x5F, 0xD6};

bool searchInRodata() {
	size_t i = 0;
	printf("Mapping %ld / %ld\r", i+1, mappings_count);
	consoleUpdate(NULL);
	std::vector<std::pair<uintptr_t, uintptr_t>> parts;
	while (i < mappings_count) {
		if ((memoryInfoBuffers[i].addr < cheatMetadata.main_nso_extents.base) || (memoryInfoBuffers[i].addr > cheatMetadata.main_nso_extents.base + cheatMetadata.main_nso_extents.size) || (memoryInfoBuffers[i].perm & Perm_Rx) != Perm_Rx) {
			i++;
			continue;
		}
		if (memoryInfoBuffers[i].size > 200'000'000) {
			i++;
			continue;
		}
		char* buffer_c = new char[memoryInfoBuffers[i].size];
		dmntchtReadCheatProcessMemory(memoryInfoBuffers[i].addr, (void*)buffer_c, memoryInfoBuffers[i].size);
		for (size_t x = 0; x < (memoryInfoBuffers[i].size - 4); x += 4) {
			if (!memcmp(&buffer_c[x], &pattern[0], 8)) {
				ad_insn *insn = NULL;
				uint32_t instruction = *(uint32_t*)(&buffer_c[x - 4]);
				ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 4), &insn);
				if (insn) {
					if (insn -> instr_id == AD_INSTR_LDR && insn -> operands[0].op_reg.rtbl[0][0] == 'q') {
						auto q_reg = insn -> operands[0].op_reg.rn;
						auto x_reg = insn -> operands[1].op_reg.rn;
						auto offset = insn -> operands[2].op_imm.bits;
						if (q_reg > 1) {
							continue;
						}
						ArmadilloDone(&insn);
						insn = 0;
						instruction = *(uint32_t*)(&buffer_c[x - 8]);
						ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 8), &insn);
						if (!insn) {
							continue;
						}
						if (insn -> instr_id != AD_INSTR_LDR || insn -> operands[0].op_reg.rtbl[0][0] != 'q') {
							ArmadilloDone(&insn);
							continue;
						}
						auto q_reg_2 = insn -> operands[0].op_reg.rn;
						if (q_reg_2 > 1 || q_reg == q_reg_2) {
							continue;
						}
						auto x_reg_2 = insn -> operands[1].op_reg.rn;
						size_t offset_2 = 0;
						if (insn -> num_operands > 2)
							offset_2 = insn -> operands[2].op_imm.bits;
						ArmadilloDone(&insn);
						insn = 0;
						instruction = *(uint32_t*)(&buffer_c[x - 12]);
						ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 12), &insn);
						if (!insn) {
							continue;
						}
						if (insn -> instr_id != AD_INSTR_ADRP) {
							ArmadilloDone(&insn);
							continue;
						}
						auto x_reg_adrp = insn -> operands[0].op_reg.rn;
						auto offset_adrp = insn -> operands[1].op_imm.bits;
						ArmadilloDone(&insn);
						if (x_reg != x_reg_adrp && x_reg_2 != x_reg_adrp) {
							continue;
						}
						if (x_reg == x_reg_2) {
							uintptr_t part_1_ptr = offset_adrp + (q_reg < q_reg_2 ? offset : offset_2);
							uintptr_t part_2_ptr = offset_adrp + (q_reg < q_reg_2 ? offset_2 : offset);
							parts.push_back(std::make_pair(part_1_ptr, part_2_ptr));
						}
						else {
							insn = 0;
							instruction = *(uint32_t*)(&buffer_c[x - 16]);
							ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 16), &insn);
							if (!insn) {
								continue;
							}
							if (insn -> instr_id != AD_INSTR_ADRP) {
								ArmadilloDone(&insn);
								continue;
							}
							auto x_reg_2_adrp = insn -> operands[0].op_reg.rn;
							auto offset_2_adrp = insn -> operands[1].op_imm.bits;
							ArmadilloDone(&insn);
							if (x_reg != x_reg_2_adrp && x_reg_2 != x_reg_2_adrp) {
								continue;
							}
							uint8_t q_reg_0_x_reg = !q_reg ? x_reg : x_reg_2;
							uint8_t q_reg_1_x_reg = !q_reg ? x_reg_2 : x_reg;
							uintptr_t part_1_ptr = (q_reg_0_x_reg == x_reg_adrp ? (offset_adrp + offset) : (offset_2_adrp + offset_2));
							uintptr_t part_2_ptr = (q_reg_1_x_reg == x_reg_adrp ? (offset_adrp + offset) : (offset_2_adrp + offset_2));
							parts.push_back(std::make_pair(part_1_ptr, part_2_ptr));
						}
					}
					else if (insn -> instr_id == AD_INSTR_LDP && insn -> operands[0].op_reg.rtbl[0][0] == 'q' && insn -> operands[1].op_reg.rtbl[0][0] == 'q') {
						auto x_reg = insn -> operands[2].op_reg.rn;
						ArmadilloDone(&insn);
						insn = 0;
						instruction = *(uint32_t*)(&buffer_c[x - 8]);
						ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 8), &insn);
						if (!insn) {
							continue;
						}
						if (insn -> instr_id != AD_INSTR_ADD || insn -> operands[0].op_reg.rn != x_reg || insn -> operands[2].type != AD_OP_IMM) {
							ArmadilloDone(&insn);
							insn = 0;
							continue;
						}
						auto addend = insn -> operands[2].op_imm.bits;
						auto x_reg_check = insn -> operands[1].op_reg.rn;
						ArmadilloDone(&insn);
						insn = 0;
						instruction = *(uint32_t*)(&buffer_c[x - 12]);
						ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 12), &insn);
						if (insn -> instr_id != AD_INSTR_ADRP || insn -> operands[0].op_reg.rn != x_reg_check) {
							ArmadilloDone(&insn);
							insn = 0;
							continue;
						}
						uintptr_t pointer = insn -> operands[1].op_imm.bits + addend;
						ArmadilloDone(&insn);
						insn = 0;						
						parts.push_back(std::make_pair(pointer, pointer + 16));
					}
					else {
						ArmadilloDone(&insn);
						continue;
					}
				}
				else printf("Decoding error!\n");
			}
		}
		delete[] buffer_c;
		i++;
	}
	if (parts.size()) {
		std::vector<std::array<uint8_t, 32>> keys;
		for (size_t i = 0; i < parts.size(); i++) {
			std::array<uint8_t, 32> key;
			dmntchtReadCheatProcessMemory(parts[i].first, (void*)&key[0], 16);
			dmntchtReadCheatProcessMemory(parts[i].second, (void*)&key[16], 16);
			keys.push_back(key);
		}
		std::sort(keys.begin(), keys.end(), entropyCompare);
		FILE* file = fopen(path, "w");
		if (file) {
			for (size_t x = 0; x < parts.size(); x++) {
				if (parts.size() > 1) {
					printf("Candidate %lu: ", x);
				}
				else printf("Key is: ");
				for (size_t i = 0; i < 32; i++) {
					printf("%02X", keys[x][i]);
				}
				printf("\n");
				std::string base64_encoded = base64_encode(&keys[x][0], 32);
				printf("Base64: %s\n\n", base64_encoded.c_str());
				for (size_t i = 0; i < 32; i++) {
					fprintf(file, "%02X", keys[x][i]);
				}
				fprintf(file, "\n");
				fprintf(file, "%s", base64_encoded.c_str());
				fprintf(file, "\n\n");
			}
			fclose(file);
			printf("Saved data to:\n%s\n", path);
		}
		else {
			printf("Couldn't open file:\n%s\n", path);
		}
		return true;
	}
	return false;
}

uint8_t patternV6[8] = {0x20, 0x69, 0xE8, 0x3C, 0x00, 0x68, 0xA8, 0x3C};

bool searchInRodataV6() {
	size_t i = 0;
	printf("Mapping %ld / %ld\r", i+1, mappings_count);
	consoleUpdate(NULL);
	std::vector<std::pair<uintptr_t, uintptr_t>> parts;
	while (i < mappings_count) {
		if ((memoryInfoBuffers[i].addr < cheatMetadata.main_nso_extents.base) || (memoryInfoBuffers[i].addr > cheatMetadata.main_nso_extents.base + cheatMetadata.main_nso_extents.size) || (memoryInfoBuffers[i].perm & Perm_Rx) != Perm_Rx) {
			i++;
			continue;
		}
		if (memoryInfoBuffers[i].size > 200'000'000) {
			i++;
			continue;
		}
		char* buffer_c = new char[memoryInfoBuffers[i].size];
		dmntchtReadCheatProcessMemory(memoryInfoBuffers[i].addr, (void*)buffer_c, memoryInfoBuffers[i].size);
		for (size_t x = 0; x < (memoryInfoBuffers[i].size - 4); x += 4) {
			if (!memcmp(&buffer_c[x], &patternV6[0], 8)) {
				ad_insn *insn = NULL;
				uint32_t instruction = *(uint32_t*)(&buffer_c[x - 4]);
				ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 4), &insn);
				if (insn) {
					if (insn -> instr_id != AD_INSTR_NOP) {
						ArmadilloDone(&insn);
						insn = 0;
						continue;
					}
					ArmadilloDone(&insn);
					insn = 0;
					uint32_t instruction = *(uint32_t*)(&buffer_c[x - 8]);
					ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 8), &insn);
					if (!insn) {
						continue;
					}
					if (insn -> instr_id != AD_INSTR_ADD || insn -> operands[0].op_reg.rn != 9 || insn -> operands[2].type != AD_OP_IMM) {
						ArmadilloDone(&insn);
						insn = 0;
						continue;
					}
					auto addend = insn -> operands[2].op_imm.bits;
					ArmadilloDone(&insn);
					insn = 0;
					instruction = *(uint32_t*)(&buffer_c[x - 12]);
					ArmadilloDisassemble(instruction, memoryInfoBuffers[i].addr + (x - 12), &insn);
					if (insn -> instr_id != AD_INSTR_ADRP || insn -> operands[0].op_reg.rn != 9) {
						ArmadilloDone(&insn);
						insn = 0;
						continue;
					}
					uintptr_t pointer = insn -> operands[1].op_imm.bits + addend;
					ArmadilloDone(&insn);
					insn = 0;
					parts.push_back(std::make_pair(pointer, pointer + 16));
				}
				else printf("Decoding error!\n");
			}
		}
		delete[] buffer_c;
		i++;
	}
	if (parts.size()) {
		std::vector<std::array<uint8_t, 32>> keys;
		for (size_t i = 0; i < parts.size(); i++) {
			std::array<uint8_t, 32> key;
			dmntchtReadCheatProcessMemory(parts[i].first, (void*)&key[0], 16);
			dmntchtReadCheatProcessMemory(parts[i].second, (void*)&key[16], 16);
			keys.push_back(key);
		}
		std::sort(keys.begin(), keys.end(), entropyCompare);
		FILE* file = fopen(path, "w");
		if (file) {
			for (size_t x = 0; x < parts.size(); x++) {
				if (parts.size() > 1) {
					printf("Candidate %lu: ", x);
				}
				else printf("Key is: ");
				for (size_t i = 0; i < 32; i++) {
					printf("%02X", keys[x][i]);
				}
				printf("\n");
				std::string base64_encoded = base64_encode(&keys[x][0], 32);
				printf("Base64: %s\n\n", base64_encoded.c_str());
				for (size_t i = 0; i < 32; i++) {
					fprintf(file, "%02X", keys[x][i]);
				}
				fprintf(file, "\n");
				fprintf(file, "%s", base64_encoded.c_str());
				fprintf(file, "\n\n");
			}
			fclose(file);
			printf("Saved data to:\n%s\n", path);
		}
		else {
			printf("Couldn't open file:\n%s\n", path);
		}
		return true;
	}
	return false;
}

// Main program entrypoint
int main(int argc, char* argv[])
{
	// This example uses a text console, as a simple way to output text to the screen.
	// If you want to write a software-rendered graphics application,
	//   take a look at the graphics/simplegfx example, which uses the libnx Framebuffer API instead.
	// If on the other hand you want to write an OpenGL based application,
	//   take a look at the graphics/opengl set of examples, which uses EGL instead.
	consoleInit(NULL);

	// Configure our supported input layout: a single player with standard controller styles
	padConfigureInput(1, HidNpadStyleSet_NpadStandard);

	// Initialize the default gamepad (which reads handheld mode inputs as well as the first connected controller)
	PadState pad;
	padInitializeDefault(&pad);

	bool error = false;
	if (!isServiceRunning("dmnt:cht")) {
		printf("DMNT:CHT not detected!\n");
		error = true;
	}
	pmdmntInitialize();
	uint64_t PID = 0;
	if (R_FAILED(pmdmntGetApplicationProcessId(&PID))) {
		printf("Game not initialized.\n");
		error = true;
	}
	pmdmntExit();
	if (error) {
		printf("Press + to exit.");
		while (appletMainLoop()) {   
			// Scan the gamepad. This should be done once for each frame
			padUpdate(&pad);

			// padGetButtonsDown returns the set of buttons that have been
			// newly pressed in this frame compared to the previous one
			u64 kDown = padGetButtonsDown(&pad);

			if (kDown & HidNpadButton_Plus)
				break; // break in order to return to hbmenu

			// Your code goes here

			// Update the console, sending a new frame to the display
			consoleUpdate(NULL);
		}
	}
	else {
		pmdmntExit();
		size_t availableHeap = checkAvailableHeap();
		printf("Available Heap: %ld MB\n", (availableHeap / (1024 * 1024)));
		consoleUpdate(NULL);
		dmntchtInitialize();
		bool hasCheatProcess = false;
		dmntchtHasCheatProcess(&hasCheatProcess);
		if (!hasCheatProcess) {
			dmntchtForceOpenCheatProcess();
		}

		Result res = dmntchtGetCheatProcessMetadata(&cheatMetadata);
		if (res)
			printf("dmntchtGetCheatProcessMetadata ret: 0x%x\n", res);

		res = dmntchtGetCheatProcessMappingCount(&mappings_count);
		if (res)
			printf("dmntchtGetCheatProcessMappingCount ret: 0x%x\n", res);
		else printf("Mapping count: %ld\n", mappings_count);

		memoryInfoBuffers = new MemoryInfo[mappings_count];

		res = dmntchtGetCheatProcessMappings(memoryInfoBuffers, mappings_count, 0, &mappings_count);
		if (res)
			printf("dmntchtGetCheatProcessMappings ret: 0x%x\n", res);

		if (checkIfUE4game()) {
			printf("\nTool works on assumption that PAKs are encrypted!\nNot finding key is not a proof that PAKs are not encrypted!\n");
			uint64_t BID = 0;
			memcpy(&BID, &(cheatMetadata.main_nso_build_id), 8);
			mkdir("sdmc:/switch/ue4AesDumper/", 777);
			snprintf(path, sizeof(path), "sdmc:/switch/ue4AesDumper/%016lX/", cheatMetadata.title_id);
			mkdir(path, 777);
			snprintf(path, sizeof(path), "sdmc:/switch/ue4AesDumper/%016lX/%016lX.log", cheatMetadata.title_id, __builtin_bswap64(BID));
			bool file_exists = false;
			FILE* text_file = fopen(path, "r");
			if (text_file) {
				file_exists = true;
				fclose(text_file);
			}
			if (file_exists) {
				printf("\nKey was already dumped!\nPress A to overwrite them.\nPress + to Exit\n\n");
			}
			else printf("\n----------\nPress A to Start\nPress + to Exit\n\n");
			consoleUpdate(NULL);
			bool overwrite = true;
			while (appletMainLoop()) {   
				padUpdate(&pad);

				u64 kDown = padGetButtonsDown(&pad);

				if (kDown & HidNpadButton_A)
					break;

				if (kDown & HidNpadButton_Plus) {
					dmntchtExit();
					consoleExit(NULL);
					return 0;
				}
				
			}
			if (overwrite) {
				printf("Searching RAM...\n\n");
				consoleUpdate(NULL);
				appletSetCpuBoostMode(ApmCpuBoostMode_FastLoad);
				bool found = searchInRodata();
				if (!found) found = searchInRodataV6();
				if (!found) printf("No decryption key was found!\n");
				printf(CONSOLE_BLUE "\n---------------------------------------------\n\n" CONSOLE_RESET);
				printf(CONSOLE_WHITE "Search is finished!\n");
				consoleUpdate(NULL);
				appletSetCpuBoostMode(ApmCpuBoostMode_Normal);
				delete[] memoryInfoBuffers;
			}
			//dumpPointers(UnityNames, UnityOffsets, cheatMetadata, unity_sdk);
		}
		dmntchtExit();
		printf("Press + to exit.");
		while (appletMainLoop()) {   
			// Scan the gamepad. This should be done once for each frame
			padUpdate(&pad);

			// padGetButtonsDown returns the set of buttons that have been
			// newly pressed in this frame compared to the previous one
			u64 kDown = padGetButtonsDown(&pad);

			if (kDown & HidNpadButton_Plus)
				break; // break in order to return to hbmenu

			// Your code goes here

			// Update the console, sending a new frame to the display
			consoleUpdate(NULL);
		}
	}

	// Deinitialize and clean up resources used by the console (important!)
	consoleExit(NULL);
	return 0;
}
