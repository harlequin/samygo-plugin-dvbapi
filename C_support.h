#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <ctype.h>

#define C_SUPPORT 1

#define BRANCH_B 0xea000000
#define BRANCH_BL 0xeb000000
void *C_find(void *h, const char *fn_name);
