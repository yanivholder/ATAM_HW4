//
// Created by student on 1/15/21.
//
#include <stdio.h>

void printer(int n){
	if (n==0){
		return;
	}
	printer(n-1);
	printf("this is printer print #%d\n", n);

}

void fake_printer(){
	puts("only to screen from fake printer");
}

int main(){
	fake_printer();
    printer(3);
	
    return 0;
}


