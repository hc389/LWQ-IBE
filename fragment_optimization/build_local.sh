#!/usr/bin/env bash
# Native macOS/Linux helper. It does not invoke SageMath, conda, or WSL.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
host_os="$(uname -s)"
benchmark_prefix="${FLINT_PREFIX:-}"
if [[ -z "$benchmark_prefix" && "$host_os" == Darwin && -d '/Applications/SageMath-10-9.app/Contents/Frameworks/Sage.framework/Versions/10.9/local' ]]; then
    benchmark_prefix='/Applications/SageMath-10-9.app/Contents/Frameworks/Sage.framework/Versions/10.9/local'
fi
if [[ "$host_os" == Darwin ]]; then
    benchmark_cxx="${CXX:-clang++}"
else
    benchmark_cxx="${CXX:-g++}"
fi
compile_flags=(-O3 -std=c++17 -Wall -Wextra -DNDEBUG)
if [[ "$host_os" == Darwin ]]; then
    benchmark_sdk="$(xcrun --show-sdk-path)"
    if [[ -f "$benchmark_sdk/usr/include/c++/v1/array" ]]; then
        compile_flags+=(-isystem "$benchmark_sdk/usr/include/c++/v1")
    fi
fi
if [[ -n "$benchmark_prefix" ]]; then
    for header in gmpxx.h flint/arb.h openssl/evp.h; do
        if [[ ! -f "$benchmark_prefix/include/$header" ]]; then
            printf 'Missing dependency header: %s/include/%s\n' "$benchmark_prefix" "$header" >&2
            exit 1
        fi
    done
    compile_flags+=(-I "$benchmark_prefix/include" -L "$benchmark_prefix/lib" "-Wl,-rpath,$benchmark_prefix/lib")
    link_flags=(-lflint -lmpfr -lgmpxx -lgmp -lcrypto)
else
    if ! command -v pkg-config >/dev/null || ! pkg-config --exists flint openssl; then
        printf '%s\n' 'Set FLINT_PREFIX to a native prefix containing FLINT 3, GMP/MPFR and OpenSSL, or install their pkg-config files.' >&2
        exit 1
    fi
    # pkg-config output is compiler tokens, not shell code; no eval is used.
    read -r -a dependency_cflags <<< "$(pkg-config --cflags flint openssl)"
    read -r -a dependency_libs <<< "$(pkg-config --libs flint openssl)"
    compile_flags+=("${dependency_cflags[@]}")
    link_flags=("${dependency_libs[@]}" -lgmpxx -lgmp -lmpfr)
fi
mkdir -p -- "$project_dir/build/local"
sources=("$project_dir"/src/*.cpp)
"$benchmark_cxx" "${compile_flags[@]}" "${sources[@]}" -o "$project_dir/build/local/lwq_ibe_bench" "${link_flags[@]}"
printf 'Built native %s executable: %s/build/local/lwq_ibe_bench\n' "$host_os" "$project_dir"
printf '%s\n' 'No timing run has started. Next: build/local/lwq_ibe_bench --help'
