#include "console.hpp"
#include <fstream>
#include "scanner.hpp"

struct scr_command_hash {
	std::uintptr_t hash, handler;
};
struct ns {
	// its id is where it's at.
	std::vector<scr_command_hash> ns_hashes;
	ns(const scr_command_hash& hash) : ns_hashes{ hash } { }
};

// avoid this because it's terribly fucking slow due to api calls
template <typename _Ty>
_Ty read_dyint(const process& proc, std::uintptr_t loc) {
	_Ty ret{ };
	std::size_t not_null_val;
	ReadProcessMemory(proc.curr_proc, (void*)loc, &ret, sizeof ret, &not_null_val);
	return ret;
}

template <std::size_t sz>
std::vector<std::uint8_t> read_vec(const process& proc, std::uintptr_t loc) {
	std::vector<std::uint8_t> vec(sz, 0);
	std::size_t fuckin_ignore{};
	ReadProcessMemory(proc.curr_proc, (void*)loc, vec.data(), sz, &fuckin_ignore);
	return vec;
}

std::pair<std::uintptr_t, scr_command_hash> resolve_native_info(const process& proc, const std::uintptr_t addr, bool first = false) {
	// returns next loc
	const auto _read1 = read_vec<0x1A>(proc, addr);
	std::uintptr_t next_addr{ 0 }, cb_nxt{ 0 };
	std::vector<std::uint8_t> _read2{};
	scr_command_hash extracted{};
	for (int i = 0; i < _read1.size();) {
		if (*reinterpret_cast<const std::uint16_t*>(_read1.data() + i) == 0x8348) {
			if (!first)
				goto out_rni;
			i += 4;
		}
		if (*reinterpret_cast<const std::uint16_t*>(_read1.data() + i) == 0x8D48) {
			extracted.handler = addr + i + *reinterpret_cast<const std::int32_t*>(_read1.data() + i + 3) + 7;
			i += 7;
		}
		if (*reinterpret_cast<const std::uint16_t*>(_read1.data() + i) == 0xB948) {
			extracted.hash = *reinterpret_cast<const std::uint64_t*>(_read1.data() + i + 2);
			i += 10;
		}
		if (*reinterpret_cast<const std::uint8_t*>(_read1.data() + i) == 0xE9) {
			cb_nxt = addr + i + *reinterpret_cast<const std::int32_t*>(_read1.data() + i + 1) + 5;
			break;
		}
	}
	for (const auto& c : read_vec<0xB>(proc, cb_nxt)) {
		_read2.emplace_back(c);
	}
	for (int i = 0; i < _read2.size();) {
		switch (*reinterpret_cast<const std::uint8_t*>(_read2.data() + i)) {
		case 0xE8:
			i += 5; 
			break;
		case 0xE9:
			next_addr = cb_nxt + i + *reinterpret_cast<const std::int32_t*>(_read2.data() + i + 1) + 5;
			goto out_rni;
			break;
		case 0x90:
			i += 1;
			break;
		}

	}
	out_rni:
	return { next_addr, extracted };
}

void resolve_namespace(const process& proc, const std::uintptr_t start_address, std::shared_mutex& ns_array_mutex, std::vector<ns>& ns_array) {
	std::vector<scr_command_hash> ret{};
	std::pair<std::uintptr_t, scr_command_hash> control = resolve_native_info(proc, start_address, true);
	ret.push_back(control.second);
	while (control.first) {
		control = resolve_native_info(proc, control.first);
		ret.push_back(control.second); 
	}

	ns_array_mutex.lock();
	for (const auto& c : ret)
		ns_array.push_back(ns{ c });
	ns_array_mutex.unlock();
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

#define multi 
	std::vector<std::thread> threads_list;
	for (const auto& ns : namespaces) {
		const auto next_ptr = ns + read_dyint<std::int32_t>(a, ns + 1) + 5;

#ifdef multi
		std::thread new_thread( resolve_namespace, std::ref(a), next_ptr, std::ref(ns_mutex), std::ref(new_ns) );
		threads_list.push_back(std::move(new_thread));
#else
		resolve_namespace(std::ref(a), next_ptr, std::ref(ns_mutex), std::ref(new_ns));
#endif

	}

#ifdef multi
	int tct = 0;
	std::cout << threads_list.size() << "\r\n";
	for (auto& thread : threads_list) {
		std::cout << "Blame thread: " << tct++ << "\r\n";
		thread.join();
	}
#endif
	std::cout << "nigga blender";
	int ctr{ 0 };
	for (const auto& c : new_ns) {
		console::log<console::log_severity::info>("Ns %d has %d members.", ctr++, c.ns_hashes.size());
	}
	return std::cin.get(), 0;
}