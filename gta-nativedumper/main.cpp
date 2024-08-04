#include "console.hpp"
#include <fstream>
#include "scanner.hpp"
#include "json/json.h"

struct scr_command_hash {
	std::uint64_t hash;
	std::uint64_t handler;
	void serialize(Json::Value& root) const {
		// im revoking this fucking json library's hamster p rivileges
		root["hash"] = std::vformat("0x{:02X}", std::make_format_args(hash)).c_str();
		root["handler"] = std::vformat("0x{:02X}", std::make_format_args(handler)).c_str();
	}
};

struct ns {
	std::vector<scr_command_hash> ns_hashes;
	void serialize(Json::Value& root) const {
		Json::Value hashes;
		for (const auto& hash : ns_hashes) {
			Json::Value hash_json;
			hash.serialize(hash_json);
			hashes.append(hash_json);
		}
		root["ns_hashes"] = hashes;
	}
	explicit ns(const std::vector<scr_command_hash>& hashes) : ns_hashes(hashes) { }
};
template <std::integral _Ty>
_Ty read_dyint(const process& proc, const std::uintptr_t loc) {
	_Ty ret{ };
	std::size_t not_null_val{};
	ReadProcessMemory(proc.proc_handle, reinterpret_cast<void*>(loc), &ret, sizeof ret, &not_null_val);
	return ret;
}

template <std::size_t sz>
std::array<std::uint8_t, sz> read_bytes(const process& proc, const std::uintptr_t loc) {
	std::array<std::uint8_t, sz> arr;
	std::size_t not_null_val{};
	ReadProcessMemory(proc.proc_handle, reinterpret_cast<void*>(loc), arr.data(), sz, &not_null_val);
	return arr;
}

std::pair<std::uintptr_t, scr_command_hash> resolve_native_info(const process& proc, const std::uintptr_t addr, const bool first = false) {
	// returns next loc
	const auto init_func_bytes = read_bytes<26>(proc, addr);
	std::uintptr_t next_addr{ 0 }, cb_nxt{ 0 };

	scr_command_hash extracted{};
	for (std::size_t i = 0; i < init_func_bytes.size();) {
		const auto cursor = init_func_bytes.data() + i;
		if (const auto word = *reinterpret_cast<const std::uint16_t*>(cursor); word == instructions::rsp_sub) {
			if (!first)
				return { next_addr, extracted };
			i += 4;
		}
		else if (word == instructions::lea) {
			extracted.handler = addr + i + *reinterpret_cast<const std::int32_t*>(cursor + 3) + 7 - proc.proc_base;
			i += 7;
		}
		else if (word == instructions::hash_mov) {
			extracted.hash = *reinterpret_cast<const std::uint64_t*>(cursor + 2);
			i += 10;
		}
		else if (*reinterpret_cast<const std::uint8_t*>(cursor) == 0xE9) {
			cb_nxt = addr + i + *reinterpret_cast<const std::int32_t*>(init_func_bytes.data() + i + 1) + 5;
			break;
		}	
	}
	const auto next = read_bytes<0xB>(proc, cb_nxt);

	for (std::size_t i = 0; i < next.size();) {
		switch (*reinterpret_cast<const std::uint8_t*>(next.data() + i)) {
		case 0xE8:
			i += 5;
			break;
		case 0xE9:
			if (i + 5 > next.size()) return { next_addr, extracted };
			next_addr = cb_nxt + i + *reinterpret_cast<const std::int32_t*>(next.data() + i + 1) + 5;
			[[fallthrough]];
		case 0x48:
			return { next_addr, extracted };
		default:
			i++;
			break;
		}
	}

	return { next_addr, extracted };
}

void resolve_namespace(const process& proc, const std::uintptr_t start_address, std::mutex& ns_array_mutex, std::vector<ns>& ns_array) {
	std::lock_guard mutex_lock{ ns_array_mutex };
	std::vector<scr_command_hash> ret{};
	std::pair<std::uintptr_t, scr_command_hash> control = resolve_native_info(proc, start_address, true);
	ret.push_back(control.second);

	while (control.first) {
		control = resolve_native_info(proc, control.first);
		ret.push_back(control.second); 
	}

	ns_array.emplace_back(ret);
}

int main(int argc, char** argv) {
	const auto gta_proc = process("GTA5.exe");
	auto results = scanner::scan(gta_proc, "\xE8\x69\x69\x69\x69\x48\x8B\xD8\x48\x8D\x05\x69\x69\x69\x69\x48\x89\x03\x48\x8D\x05\xB5\xCC\x34\x00\x48\x89\x43\x08\x48\x8D\x05\x1A\x55\x2B\x00\x48\x89\x43\x10\x48\x8D", "x????xxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxx");

	if (results.empty()) {
		console::log<console::log_severity::error>("Could not scan for function.");
		return std::cin.get(), -5;
	}

	const auto start_addr = VirtualAlloc(nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::size_t sz_read{};
	ReadProcessMemory(gta_proc.proc_handle, reinterpret_cast<void*>(results.at(0).loc), start_addr, 2048, &sz_read);
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

	std::vector<std::uintptr_t> namespaces;
	std::unordered_map<std::uintptr_t, bool> resolved_map;
	for (auto idx = reinterpret_cast<std::uint8_t*>(reinterpret_cast<uintptr_t>(start_addr) + 8);;) {

		std::uint16_t word{ };
		switch (*idx) {
		case 0x48:
			word = *reinterpret_cast<std::uint16_t*>(idx + 1);
			if (word == 0x4389)
				idx += 4;
			else if (word == 0x8389)
				idx += 7;
			else if (word == 0x389)
				idx += 3;
			else if (word == 0x58D) {
				const auto calculated = (reinterpret_cast<std::uintptr_t>(idx) - reinterpret_cast<std::uintptr_t>(start_addr) + results.at(0).loc) + *reinterpret_cast<std::int32_t*>(idx + 3) + 7;
				idx += 7;
				if (!resolved_map.contains(calculated)) {
					resolved_map.insert({ calculated, true });
					namespaces.emplace_back(calculated);
				}
				else if (const auto pos = std::ranges::find(namespaces.begin(), namespaces.end(), calculated); pos != namespaces.end()) {
					namespaces.erase(pos);
				}
			}
			break;
		case 0x8D:
			idx += 3;
			break;
		case 0xBF:
		case 0xBE:
			idx += 5;
			break;
		case 0xE8:
			goto OUTSIDE;
		}
	}
OUTSIDE:
	
	console::log<console::log_severity::success>("Found %d namespaces. If this value is nonzero, good.", namespaces.size());
	
	std::mutex ns_mutex;
	std::vector<ns> new_ns;

	std::vector<std::thread> threads_list;
	for (const auto& ns : namespaces) {
		const auto next_ptr = ns + read_dyint<std::int32_t>(gta_proc, ns + 1) + 5;
		std::thread new_thread( resolve_namespace, std::ref(gta_proc), next_ptr, std::ref(ns_mutex), std::ref(new_ns) );
		threads_list.push_back(std::move(new_thread));
	}

	for (auto& thread : threads_list)
		thread.join();


	auto native_count = 0;
	for (std::size_t idx = 0u, sz = new_ns[idx].ns_hashes.size(); idx < new_ns.size(); ++idx, native_count += sz, sz = new_ns[idx].ns_hashes.size())
		console::log<console::log_severity::info>("Namespace %d has %d members.", idx, sz);

	Json::Value j;
	for (const auto& ns : new_ns) {
		Json::Value ns_json;
		ns.serialize(ns_json);
		j.append(ns_json);
	}

	console::log<console::log_severity::warn>("Total Natives: %d.", native_count);
	std::ofstream out("natives.json");
	out << j;
	out.close();
	console::log<console::log_severity::success>("Done! Wrote to natives.json");

	return std::cin.get(), 0;
}