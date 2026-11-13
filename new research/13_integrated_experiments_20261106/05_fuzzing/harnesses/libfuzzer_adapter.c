#include <stdint.h>
#include <stddef.h>
int FuzzerInitialize(int *, char ***);
int FuzzerTestOneInput(const uint8_t *, size_t);
int LLVMFuzzerInitialize(int *argc, char ***argv) { return FuzzerInitialize(argc, argv); }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return FuzzerTestOneInput(data, size); }
