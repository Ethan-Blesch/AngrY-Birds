#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main(){
	uint64_t addr;
	
	read(0, &addr, 8);
	
	read(0, addr, 8);
	
	return 0;
}

// gcc arbitrary_write.c -o arbitrary_write
// python test.py
