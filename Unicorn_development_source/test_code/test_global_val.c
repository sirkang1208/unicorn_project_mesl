const int global = 5000;

int add(int a, int b){
	int c;
	c = a + b;
	return c;
}

int main(){
	int a = 10;
	int sum;
	sum = add(a,global);
	return 0;
}


