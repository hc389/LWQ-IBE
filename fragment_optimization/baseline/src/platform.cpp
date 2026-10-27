#include "core.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#ifdef __GNUC__
#include <cpuid.h>
#include <cstring>
#endif
#else
#include <sys/resource.h>
#include <sys/utsname.h>
#ifdef __APPLE__
#include <mach/mach.h>
#elif defined(__linux__)
#include <fstream>
#include <unistd.h>
#include <sched.h>
#endif
#endif

namespace bench {
namespace {
constexpr std::uint64_t absolute_ceiling = 1500000000ULL; // Decimal GB, not GiB.
std::uint64_t memory_limit = 0;
#ifdef _WIN32
HANDLE memory_job = nullptr;
[[noreturn]] void windows_error(const char* operation) {
    throw std::runtime_error(std::string(operation) + " failed (Windows error " +
                             std::to_string(GetLastError()) + ")");
}
PROCESS_MEMORY_COUNTERS_EX memory_counters() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)))
        windows_error("GetProcessMemoryInfo");
    return counters;
}
#endif
std::uint64_t current_resident_bytes() {
#ifdef _WIN32
    return static_cast<std::uint64_t>(memory_counters().WorkingSetSize);
#elif defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS)
        throw std::runtime_error("Cannot read validation-process resident memory");
    return static_cast<std::uint64_t>(info.resident_size);
#elif defined(__linux__)
    std::ifstream statm("/proc/self/statm");
    std::uint64_t pages = 0, resident = 0;
    if (!(statm >> pages >> resident))
        throw std::runtime_error("Cannot read /proc/self/statm");
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) throw std::runtime_error("Cannot read page size");
    return resident * static_cast<std::uint64_t>(page_size);
#else
    throw std::runtime_error("Memory monitor unavailable on this validation platform");
#endif
}
} // namespace

void install_memory_limit(std::uint64_t bytes) {
    if (bytes < 256000000ULL || bytes > absolute_ceiling)
        throw std::invalid_argument("Memory limit must be 256..1500 decimal MB");
    if (memory_limit != 0) {
        if (memory_limit != bytes) throw std::runtime_error("Memory limit cannot be changed mid-run");
        return;
    }
#ifdef _WIN32
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) windows_error("CreateJobObjectW");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    // These are OS-enforced PRIVATE COMMIT limits, not RSS limits. No other
    // process is attached, and no unrelated process can be terminated here.
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(bytes);
    limits.JobMemoryLimit = static_cast<SIZE_T>(bytes);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        const DWORD code = GetLastError();
        CloseHandle(job);
        SetLastError(code);
        windows_error("SetInformationJobObject");
    }
    if (!AssignProcessToJobObject(job, GetCurrentProcess())) {
        const DWORD code = GetLastError();
        CloseHandle(job);
        SetLastError(code);
        windows_error("AssignProcessToJobObject (refusing unbounded run)");
    }
    // Intentionally retained for the process lifetime. No KILL_ON_JOB_CLOSE is
    // set; this job only denies allocations above the private-commit ceiling.
    memory_job = job;
#endif
    // Non-Windows builds allow correctness checks and bounded block wall-time
    // measurements, not full-mode runs. They have no Windows hard limit.
    memory_limit = bytes;
    platform_check(0);
}

void platform_check(std::uint64_t planned_bytes) {
    if (!memory_limit) throw std::runtime_error("Memory limit must be installed before allocation");
    const auto budget = std::min<std::uint64_t>(1200000000ULL, memory_limit - 128000000ULL);
    if (planned_bytes > budget)
        throw std::runtime_error("Planned allocations exceed the guarded memory budget");
    if (current_resident_bytes() >= absolute_ceiling)
        throw std::runtime_error("Resident-memory monitor reached the 1.5 GB stop threshold");
#ifdef _WIN32
    if (!memory_job) throw std::runtime_error("Windows Job Object is not active");
    if (memory_counters().PrivateUsage >= memory_limit)
        throw std::runtime_error("Private commit reached the configured memory limit");
#endif
}

Stamp clock_stamp() {
#ifdef _WIN32
    ULONG64 cycles = 0;
    LARGE_INTEGER now{}, frequency{};
    if (!QueryThreadCycleTime(GetCurrentThread(), &cycles)) windows_error("QueryThreadCycleTime");
    if (!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&frequency))
        windows_error("QueryPerformanceCounter/Frequency");
    // QPC seconds and scheduled thread cycles are independently measured.
    // Never convert cycles to seconds using a nominal CPU clock frequency.
    return {static_cast<std::uint64_t>(cycles),
            static_cast<double>(now.QuadPart) / static_cast<double>(frequency.QuadPart)};
#else
    return {0, std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count()};
#endif
}

std::uint64_t peak_memory_bytes() {
#ifdef _WIN32
    return static_cast<std::uint64_t>(memory_counters().PeakWorkingSetSize);
#else
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage)) throw std::runtime_error("getrusage failed");
#ifdef __APPLE__
    return static_cast<std::uint64_t>(usage.ru_maxrss);
#else
    return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024ULL;
#endif
#endif
}

bool cycle_counter_available() {
#ifdef _WIN32
    ULONG64 cycles = 0;
    return QueryThreadCycleTime(GetCurrentThread(), &cycles) != 0;
#else
    return false;
#endif
}

std::string cycle_counter_name() {
#ifdef _WIN32
    return "Windows QueryThreadCycleTime (scheduled thread cycles, user+kernel)";
#else
    return "unavailable: non-Windows wall-time measurement";
#endif
}

void set_single_thread_affinity(int core) {
    if (core == -1) return;
    if (core < 0 || core >= 64) throw std::invalid_argument("Core must be -1 or 0..63");
#ifdef _WIN32
    DWORD_PTR process_mask = 0, system_mask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask))
        windows_error("GetProcessAffinityMask");
    const DWORD_PTR mask = static_cast<DWORD_PTR>(1ULL) << core;
    if (!(mask & process_mask)) throw std::invalid_argument("Requested logical CPU is unavailable");
    if (!SetThreadAffinityMask(GetCurrentThread(), mask)) windows_error("SetThreadAffinityMask");
#elif defined(__linux__)
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) throw std::runtime_error("sched_setaffinity failed");
#else
    throw std::runtime_error("Explicit CPU affinity is supported only in Windows/Linux builds");
#endif
}

std::string platform_description() {
    std::ostringstream text;
#ifdef _WIN32
    text << "Windows native x64; ";
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    using RtlVersion = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto rtl_version = ntdll ? reinterpret_cast<RtlVersion>(GetProcAddress(ntdll, "RtlGetVersion")) : nullptr;
    if (rtl_version && rtl_version(&version) == 0)
        text << version.dwMajorVersion << '.' << version.dwMinorVersion << '.' << version.dwBuildNumber << "; ";
#ifdef __GNUC__
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (__get_cpuid_max(0x80000000U, nullptr) >= 0x80000004U) {
        char brand[49]{};
        for (unsigned int i = 0; i < 3; ++i) {
            __get_cpuid(0x80000002U + i, &a, &b, &c, &d);
            std::memcpy(brand + 16*i, &a, 4); std::memcpy(brand + 16*i + 4, &b, 4);
            std::memcpy(brand + 16*i + 8, &c, 4); std::memcpy(brand + 16*i + 12, &d, 4);
        }
        text << brand << "; ";
    }
#endif
    text << "JobObject private-commit cap=" << memory_limit
         << " bytes; RSS stop monitor=1500000000 bytes";
    if (memory_limit) {
        const auto counters = memory_counters();
        text << "; current_RSS=" << counters.WorkingSetSize
             << "; current_private_commit=" << counters.PrivateUsage;
    }
#else
    utsname name{};
    if (uname(&name) == 0) text << name.sysname << ' ' << name.release << ' ' << name.machine << "; ";
    text << "native wall-time / correctness measurements; no Windows cycle counts or OS-enforced memory-cap claim";
#endif
#ifdef __VERSION__
    text << "; compiler=" << __VERSION__;
#endif
    return text.str();
}
} // namespace bench
