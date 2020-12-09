#include<stdio.h>
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
int main(){
	struct callback_head t;
	printf("%d\n",sizeof(t));
}
