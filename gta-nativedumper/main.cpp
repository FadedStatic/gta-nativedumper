#include "console.hpp"
#include <fstream>
#include "scanner.hpp"

struct scr_command_hash {
	std::uintptr_t hash, handler;
};
struct ns {
	// its id is where it's at.
	std::vector<scr_command_hash> ns_hashes;
};

// avoid this because it's terribly fucking slow due to api calls
template <typename _Ty>
_Ty read_dyint(const process& proc, std::uintptr_t loc) {
	_Ty ret{ };
	std::size_t not_null_val;
	ReadProcessMemory(proc.curr_proc, (void*)loc, &ret, sizeof ret, &not_null_val);
	return ret;
}

std::pair<std::uintptr_t, scr_command_hash> resolve_native_info(const std::uintptr_t addr) {
	// returns next loc
}

ns resolve_namespace(const std::uintptr_t start_address, std::shared_mutex& ns_array_mutex, std::vector<ns>& ns_array) {

}

int main(int argc, char** argv) {
	process a = process("GTA5.exe");
	auto results = scanner::scan(a, "\xE8\x69\x69\x69\x69\x48\x8B\xD8\x48\x8D\x05\x69\x69\x69\x69\x48\x89\x03\x48\x8D\x05\xB5\xCC\x34\x00\x48\x89\x43\x08\x48\x8D\x05\x1A\x55\x2B\x00\x48\x89\x43\x10\x48\x8D", "x????xxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxx");

	if (results.empty()) {
		console::log<console::log_severity::error>("Could not find process.");
		return std::cin.get(), -5;
	}

	const auto start_addr = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::size_t fuckin_shit;
	ReadProcessMemory(a.curr_proc, (void*)results.at(0).loc, start_addr, 2048, &fuckin_shit);
	// if sig is wrong here's the asm for it
	/*
	call sub_xxxx
	mov rbx, rax
	lea rax, sub_xxxxxx
	mov [rbx], rax
	lea rax, sub_xxxxxx
	mov [rbx+8], rax
	lea rax, sub_xxxxxx
	mov [rbx+10h], rax
	...
	*/
	// build a list of namespaces

	std::vector<std::uintptr_t> namespaces;
	std::unordered_map<std::uintptr_t, bool> resolved_map;
	for (auto fuckinshit = reinterpret_cast<std::uint8_t*>((uintptr_t)start_addr + 8);;) {
		switch (*fuckinshit) {
		case 0x48:			
			if (*reinterpret_cast<std::uint16_t*>(fuckinshit + 1) == 0x4389) 
				fuckinshit += 4;
			else if (*reinterpret_cast<std::uint16_t*>(fuckinshit + 1) == 0x8389) 
				fuckinshit += 7;
			else if (*reinterpret_cast<std::uint16_t*>(fuckinshit + 1) == 0x389) 
				fuckinshit += 3;
			else if (*reinterpret_cast<std::uint16_t*>(fuckinshit + 1) == 0x58D) {
				const auto calculated = ((uintptr_t)fuckinshit - (uintptr_t)start_addr + results.at(0).loc) + *reinterpret_cast<std::int32_t*>(fuckinshit + 3) + 7;
				fuckinshit += 7;
				if (!resolved_map.contains(calculated)) {
					resolved_map.insert({ calculated, true });
					namespaces.emplace_back(calculated);
				}
				else {
					const auto pos = std::find(namespaces.begin(), namespaces.end(), calculated);
					if (pos != namespaces.end())
						namespaces.erase(pos);
				}
			}
			break;
		case 0x8D:
			fuckinshit += 3;
			break;
		case 0xBF:
		case 0xBE:
			fuckinshit += 5;
			break;
		case 0xE8:
			goto OUTSIDE;
		}
	}
OUTSIDE:
	
	console::log<console::log_severity::success>("Found %d namespaces. If this value is nonzero, good.", namespaces.size());
	
	std::shared_mutex ns_mutex;
	std::vector<ns> new_ns;

	for (const auto& ns : namespaces) {
		const auto next_ptr = ns + read_dyint<std::int32_t>(a, ns + 1) + 5;
		resolve_namespace(next_ptr, std::ref(ns_mutex), std::ref(new_ns));
	}
	return std::cin.get(), 0;
}