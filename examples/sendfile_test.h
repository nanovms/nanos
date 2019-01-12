#ifndef SENDFILE_TEST
#define SENDFILE_TEST

int sendfile(int inf, int outf, char *offs, size_t count);
int sendfile_file(void);
int sendfile_sock(void);
int sendfile_pipe(void);

#endif
