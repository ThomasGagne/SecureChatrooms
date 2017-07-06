#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "utilities.h"

void write_file(char *filepath, const char *data) {

  FILE *fp = fopen(filepath, "ab");
  if(fp != NULL) {
    fputs(data, fp);
    fclose(fp);
  } else {
    printf("Error: Couldn't write to %s\n", filepath);
  }
}

void write_file_length(char *filepath, const char *data, int length) {
  FILE *fp = fopen(filepath, "ab");
  if(fp != NULL) {
    int i;
    for(i = 0; i < length; i++) {
      putc(*(data + i), fp);
    }
    fclose(fp);
  } else {
    printf("Error: Couldn't write to %s\n", filepath);
  }
}

void read_file(char *filepath, char *data) {
  long length;
  FILE * f = fopen (filepath, "rb");
  fseek (f, 0, SEEK_END);
  length = ftell (f);
  fseek (f, 0, SEEK_SET);
  fread (data, 1, length, f);
  fclose (f);

  /*
  FILE *fp = fopen(filepath, "ab");
  if(fp != NULL) {
    int i;
    for(i = 0; i < length; i++) {
      data[i] = getc(fp);
    }
    fclose(fp);
  } else {
    printf("Error: Couldn't write to %s\n", filepath);
  }
  */
}

// Strip CRLF
void strip_newline(char *s){
  while(*s != '\0'){
    if(*s == '\r' || *s == '\n'){
      *s = '\0';
    }
    s++;
  }
}

// https://stackoverflow.com/questions/9210528/split-string-with-delimiters-in-c
char** str_split(char* a_str, const char a_delim)
{
  char** result    = 0;
  size_t count     = 0;
  char* tmp        = a_str;
  char* last_comma = 0;
  char delim[2];
  delim[0] = a_delim;
  delim[1] = 0;

  /* Count how many elements will be extracted. */
  while (*tmp)
    {
      if (a_delim == *tmp)
        {
          count++;
          last_comma = tmp;
        }
      tmp++;
    }

  /* Add space for trailing token. */
  count += last_comma < (a_str + strlen(a_str) - 1);

  /* Add space for terminating null string so caller
     knows where the list of returned strings ends. */
  count++;

  result = malloc(sizeof(char*) * count);

  if (result)
    {
      size_t idx  = 0;
      char* token = strtok(a_str, delim);

      while (token)
        {
          assert(idx < count);
          *(result + idx++) = strdup(token);
          token = strtok(0, delim);
        }
      //assert(idx == count - 1);
      *(result + idx) = 0;
    }

  return result;
}
