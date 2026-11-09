COMMAND: clang-18 -fsanitize=address,undefined -fno-omit-frame-pointer -Iinclude -I. harness libcrypto.a -pthread -ldl
compile_exit=0
run_exit=1
