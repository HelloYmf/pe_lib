#include <pe_parser.h>

FILE *pe_open(const char *filename)
{
  FILE *executable = fopen(filename, "r+b");
  if (!executable)
  {
    return NULL;
  }

  if (!pe_check(executable))
  {
    fclose(executable);
    return NULL;
  }

  return executable;
}

bool pe_check(FILE *executable)
{
  char signature[PE_SIGNATURE_SIZE];
  int32_t signature_address;

  fseek(executable, PE_SIGNATURE_ADDRESS_OFFSET, SEEK_SET);
  if (!fread(&signature_address, sizeof signature_address, 1, executable))
  {
    return false;
  }

  fseek(executable, signature_address, SEEK_SET);
  if (!fread(signature, PE_SIGNATURE_SIZE, 1, executable))
  {
    return false;
  }

  return !memcmp(signature, PE_SIGNATURE, PE_SIGNATURE_SIZE);
}

bool pe_write(const char* filename, char* buffer, size_t size)
{
  FILE* file = fopen(filename, "wb+");

  if (file != NULL) {
      size_t real_written = fwrite(buffer, 1, size, file);
      if (real_written != size)
          return false;
      fclose(file);
  } else {
      return false;
  }
  return true;
}