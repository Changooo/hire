// src/check_dev.c
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    struct stat st;
    if (stat(argv[1], &st) < 0) {
        perror("stat");
        return 1;
    }

    printf("File: %s\n", argv[1]);
    printf("st_dev (raw):    %llu (0x%llx)\n",
           (unsigned long long)st.st_dev,
           (unsigned long long)st.st_dev);
    printf("Major:           %u\n", major(st.st_dev));
    printf("Minor:           %u\n", minor(st.st_dev));
    printf("st_ino:          %llu\n", (unsigned long long)st.st_ino);

    return 0;
}
