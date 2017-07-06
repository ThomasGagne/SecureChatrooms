#ifndef UTILITIES_H_
#define UTILITIES_H_

void write_file(char *filepath, const char *data);
void write_file_length( char *filepath, const char *data, int length);
void read_file(char *filepath, char *data);
void strip_newline(char *s);
char** str_split(char* a_str, char a_delim);

#endif
