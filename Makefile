all: simon.o
	gcc simon.o -o simon
simon.o: simon.c
	gcc -c simon.c
clean:
	rm simon.o
spotless:
	rm simon.o
	rm simon
