#include "hash.h"
#include "tables.h"
#include <hash_kernel.cl>
#include <oclUtils.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <CL/cl.h>
#include <stdbool.h>

#define COLWORDS     (STATEWORDS/8)
#define BYTESLICE(i) (((i)%8)*STATECOLS+(i)/8)

#if CRYPTO_BYTES<=32
static const u32 columnconstant[2] = { 0x30201000, 0x70605040 };
static const u8 shiftvalues[2][8] = { {0, 1, 2, 3, 4, 5, 6, 7}, {1, 3, 5, 7, 0, 2, 4, 6} };
#else
static const u32 columnconstant[4] = { 0x30201000, 0x70605040, 0xb0a09080, 0xf0e0d0c0 };
static const u8 shiftvalues[2][8] = { {0, 1, 2, 3, 4, 5, 6, 11}, {1, 3, 5, 11, 0, 2, 4, 6} };
#endif

#define mul2(x,t) \
{\
  t = x & 0x80808080;\
  x ^= t;\
  x <<= 1;\
  t = t >> 7;\
  t ^= (t << 1);\
  x ^= t;\
  x ^= (t << 3);\
}

void mixbytes(u32 a[8][COLWORDS], u32 b[8], int s)
{
  int i;
  u32 t0, t1, t2;

  for (i=0; i<8; i++)
    b[i] = a[i][s];

  /* y_i = a_{i+6} */
  for (i=0; i<8; i++)
    a[i][s] = b[(i+2)&7];

  /* t_i = a_i + a_{i+1} */
  for (i=0; i<7; i++)
    b[i] ^= b[(i+1)&7];
  b[7] ^= a[6][s];

  /* y_i = a_{i+6} + t_i */
  for (i=0; i<8; i++)
    a[i][s] ^= b[(i+4)&7];

  /* y_i = y_i + t_{i+2} */
  for (i=0; i<8; i++)
    a[i][s] ^= b[(i+6)&7];

  /* x_i = t_i + t_{i+3} */
  t0 = b[0];
  t1 = b[1];
  t2 = b[2];
  for (i=0; i<5; i++)
    b[i] ^= b[(i+3)&7];
  b[5] ^= t0;
  b[6] ^= t1;
  b[7] ^= t2;

  /* z_i = 02 * x_i */
  for (i=0; i<8; i++)
    mul2(b[i],t0);

  /* w_i = z_i + y_{i+4} */
  for (i=0; i<8; i++)
    b[i] ^= a[i][s];

  /* v_i = 02 * w_i */
  for (i=0; i<8; i++)
    mul2(b[i],t0);

  /* b_i = v_{i+3} + y_{i+4} */
  for (i=0; i<8; i++)
    a[i][s] ^= b[(i+3)&7];
}

long LoadOpenCLKernel(char const* path, char **buf)
{
    FILE  *fp;
    size_t fsz;
    long   off_end;
    int    rc;

    /* Open the file */
    fp = fopen(path, "r");
    if( NULL == fp ) {
        return -1L;
    }

    /* Seek to the end of the file */
    rc = fseek(fp, 0L, SEEK_END);
    if( 0 != rc ) {
        return -1L;
    }

    /* Byte offset to the end of the file (size) */
    if( 0 > (off_end = ftell(fp)) ) {
        return -1L;
    }
    fsz = (size_t)off_end;

    /* Allocate a buffer to hold the whole file */
    *buf = (char *) malloc( fsz+1);
    if( NULL == *buf ) {
        return -1L;
    }

    /* Rewind file pointer to start of file */
    rewind(fp);

    /* Slurp file into buffer */
    if( fsz != fread(*buf, 1, fsz, fp) ) {
        free(*buf);
        return -1L;
    }

    /* Close the file */
    if( EOF == fclose(fp) ) {
        free(*buf);
        return -1L;
    }


    /* Make sure the buffer is NUL-terminated, just in case */
    (*buf)[fsz] = '\0';

    /* Return the file size */
    return (long)fsz;
}

void memxor(u32* dest, const u32* src, u32 n)
{
  while(n--)
  {
    *dest ^= *src;
    dest++;
    src++;
  }
}

struct state {
  u8 bytes_in_block;
  u8 first_padding_block;
  u8 last_padding_block;
};

void setmessage(u8* buffer, const u8* in, struct state s, unsigned long long inlen)
{
  int i;
  for (i = 0; i < s.bytes_in_block; i++)
    buffer[BYTESLICE(i)] = in[i];

  if (s.bytes_in_block != STATEBYTES)
  {
    if (s.first_padding_block)
    {
      buffer[BYTESLICE(i)] = 0x80;
      i++;
    }

    for(;i<STATEBYTES;i++)
      buffer[BYTESLICE(i)] = 0;

    if (s.last_padding_block)
    {
      inlen /= STATEBYTES;
      inlen += (s.first_padding_block==s.last_padding_block) ? 1 : 2;
      for(i=STATEBYTES-8;i<STATEBYTES;i++)
        buffer[BYTESLICE(i)] = (inlen >> 8*(STATEBYTES-i-1)) & 0xff;
    }
  }
}

int hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
  __attribute__ ((aligned (8))) u32 ctx[STATEWORDS];
  __attribute__ ((aligned (8))) u32 buffer[STATEWORDS];
  unsigned long long rlen = inlen;
  struct state s = { STATEBYTES, 0, 0 };
  u8 i;
 




 /* set inital value */
  for(i=0;i<STATEWORDS;i++)
    ctx[i] = 0;
  ((u8*)ctx)[BYTESLICE(STATEBYTES-2)] = ((CRYPTO_BYTES*8)>>8)&0xff;
  ((u8*)ctx)[BYTESLICE(STATEBYTES-1)] = (CRYPTO_BYTES*8)&0xff;
  
  
  int err;                            // error code returned from api calls

   cl_device_id device_id;             // compute device id 
   cl_context context;                 // compute context
   cl_command_queue commands;          // compute command queue
   cl_program program;                 // compute program
   cl_kernel kernel;                   // compute kernel
  
  
   // get the list of GPU devices associated 
   // with context
   cl_uint dev_cnt = 0;
   clGetPlatformIDs(0, 0, &dev_cnt);
	
   cl_platform_id platform_ids[100];
   clGetPlatformIDs(dev_cnt, platform_ids, NULL);
	
   // Connect to a compute device
   int gpu = 1;
   err = clGetDeviceIDs(platform_ids[0], gpu ? CL_DEVICE_TYPE_GPU : CL_DEVICE_TYPE_CPU, 1, &device_id, NULL);
   if (err != CL_SUCCESS)
   {
       printf("Error: Failed to create a device group!\n");
       return EXIT_FAILURE;
   }
   
   // Create a compute context 
   context = clCreateContext(0, 1, &device_id, NULL, NULL, &err);
   if (!context)
   {
       printf("Error: Failed to create a compute context!\n");
       return EXIT_FAILURE;
   }
   
   
 // Create a command Queue commands
   commands = clCreateCommandQueue(context, device_id, 0, &err);
   if (!commands)
   {
       printf("Error: Failed to create a command commands!\n");
       return EXIT_FAILURE;
   }
 
 
   
   //Allocate device memory
   
   d_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, mem_size_buffer, NULL, &err);
   
   d_cond = clCreateBuffer(context, CL_MEM_READ_WRITE, mem_size_cond, NULL, &err);
   
   
   // Create the compute program from the source file
   char *KernelSource;
   long lFileSize;

   lFileSize = LoadOpenCLKernel("hash_kernel.cl", &KernelSource);
   if( lFileSize < 0L ) {
       perror("File read failed");
       return 1;
   }
   
   clProgram = clCreateProgramWithSource(context, 1, (const char **)&KernelSource, NULL, &err);
   
   if (!program)
   {
       printf("Error: Failed to create compute program!\n");
       return EXIT_FAILURE;
   }
   
   // Build the program executable
   err = clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
   if (err != CL_SUCCESS)
   {
       size_t len;
       char buffer[2048];
       printf("Error: Failed to build program executable!\n");
       clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
       printf("%s\n", buffer);
       exit(1);
   }
   
   // Create the compute kernel in the program we wish to run
   //
   kernel = clCreateKernel(program, "permutation", &err);
   if (!kernel || err != CL_SUCCESS)
   {
       printf("Error: Failed to create compute kernel!\n");
       exit(1);
   }
   
   //Allocate device memory
   
   d_buffer = clCreateBuffer(context, CL_MEM_READ_WRITE, mem_size_buffer, NULL, &err);
   
   d_cond = clCreateBuffer(context, CL_MEM_READ_WRITE, mem_size_cond, NULL, &err);
   
   
   /*Launch openCl kernel*/
   
   size_t localWorkSize[2], globalWorkSize[2];
   
   err = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&d_buffer);
   
   err |= clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&d_cond);
   
   if (err != CL_SUCCESS)
   {
       printf("Error: Failed to set kernel arguments! %d\n", err);
       exit(1);
   }
 
   
   localWorkSize[0] = 16;
   localWorkSize[1] = 16;
   globalWorkSize[0] = 1024;
   globalWorkSize[1] = 1024;
 
   err = clEnqueueNDRangeKernel(commands, kernel, 2, NULL, globalWorkSize, localWorkSize, 0, NULL, NULL);

   if (err != CL_SUCCESS)
   {
       printf("Error: Failed to execute kernel! %d\n", err);
       exit(1);
   }
 
   
  //Retrieve result from device
   err = clEnqueueReadBuffer(commands, d_C, CL_TRUE, 0, mem_size_C, h_C, 0, NULL, NULL);

   if (err != CL_SUCCESS)
   {
       printf("Error: Failed to read output array! %d\n", err);
       exit(1);
   }
  
  /* iterate compression function */
  while(s.last_padding_block == 0)
  {
    if (rlen<STATEBYTES)
    {
      if (s.first_padding_block == 0)
      {
        s.bytes_in_block = rlen;
        s.first_padding_block = 1;
        s.last_padding_block = (s.bytes_in_block < STATEBYTES-8) ? 1 : 0;
      }
      else
      {
        s.bytes_in_block = 0;
        s.first_padding_block = 0;
        s.last_padding_block = 1;
      }
    }
    else
      rlen-=STATEBYTES;

    /* compression function */
    setmessage((u8*)buffer, in, s, inlen);
    memxor(buffer, ctx, STATEWORDS);
	cond[0]=0
    kernel(buffer, cond);
    memxor(ctx, buffer, STATEWORDS);
    setmessage((u8*)buffer, in, s, inlen);
	cond[0]=1;
    kernel(buffer, cond);
    memxor(ctx, buffer, STATEWORDS);

    /* increase message pointer */
    in += STATEBYTES;
  }

  /* output transformation */
  for (i=0; i<STATEWORDS; i++)
    buffer[i] = ctx[i];
  kernel(buffer, 0);
  memxor(ctx, buffer, STATEWORDS);

  /* return truncated hash value */
  for (i = STATEBYTES-CRYPTO_BYTES; i < STATEBYTES; i++)
  out[i-(STATEBYTES-CRYPTO_BYTES)] = ((u8*)ctx)[BYTESLICE(i)];
   
 
   //Shutdown and cleanup
   
   
 
   clReleaseMemObject(d_buffer);
   clReleaseMemObject(d_cond);
   

   clReleaseProgram(program);
   clReleaseKernel(kernel);
   clReleaseCommandQueue(commands);
   clReleaseContext(context);




  return 0;
}
