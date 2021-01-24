//
// Created by student on 1/15/21.
//
#include <stdio.h>

void f(int n);
void g(int n);
void h(int n);



void f(int n){
	if (n==0){
		return;
	}
	g(n-1);
	printf("this is f print #%d\n", n);

}

void h(int n){
	
	if (n==0){
		return;
	}
	puts("this is from h");
	f(n);

}

void g(int n){
	
	if (n==0){
		return;
	}
	f(n-1);
	printf("this is g print #%d\n", n);

}

int main(){
	puts("this is from main 1");
    f(5);
    h(3);
	puts("this is from main 2");
	
    return 0;
}


