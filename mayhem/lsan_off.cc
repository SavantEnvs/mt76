// Leak detection is not the bug class this fleet fuzzes for; ASan + UBSan stay on.
extern "C" int __lsan_is_turned_off() { return 1; }
