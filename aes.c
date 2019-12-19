#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <wmmintrin.h>

uint8_t AES256_TEST_KEY[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xd7};

uint8_t TEST_IV[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

uint8_t TEST_PLAINTEXT[] = {0x9e, 0x83, 0xd6, 0xe3, 0x1e, 0x59, 0xa8, 0x72, 0xf3, 0xaf, 0x18, 0x27, 0x3f, 0x8d, 0xb2, 0xf9, 0xd8, 0xc0, 0x61, 0x1d, 0x75, 0x36, 0x18, 0xca, 0x68, 0x6d, 0x85, 0xe4, 0xf2, 0x70, 0xf1, 0xbf};



void AES_CBC_encrypt(
  const unsigned char *in,  // plaintext input data
  unsigned char *out,       // ciphertext output data
  unsigned char ivec[16],   // 16 byte initialization vector
  unsigned long length,     // length of input data in bytes
  unsigned char *key,       // encryption key (16, 24, or 32 bytes)
  int number_of_rounds      // Rijndael cipher rounds (10, 12, or 14)
) {
  __m128i feedback, data; // init 128 bit SIMD registers
  int i, j;

  // set number of blocks for CBC
  if (length % 16) {
    length = length / 16 + 1;
  } else {
    length /= 16;
  }

  // load IV into feedback register
  feedback = _mm_loadu_si128((__m128i*)ivec);

  // apply cipher to input file, block by block
  for(i = 0; i < length; i++) {

    // load first block of input into data register
    data = _mm_loadu_si128(&((__m128i*)in)[i]);

    // XOR data and feedback to get new input
    feedback = _mm_xor_si128(data, feedback);

    // XOR with key for this round to get cipher input
    feedback = _mm_xor_si128(feedback, ((__m128i*)key)[j]);

    // apply Rijndael cipher, rounds - 1 times
    for(j = 1; j < number_of_rounds; j++) {
      feedback = _mm_aesenc_si128(feedback, ((__m128i*)key)[j]);
    }

    // apply last round of Rijndael cipher
    feedback = _mm_aesenclast_si128(feedback,((__m128i*)key)[j]);

    // store final output as initial feedback for next block of CBC
    _mm_storeu_si128(&((__m128i*)out)[i], feedback);
  }
}

void AES_CBC_decrypt(
    const unsigned char *in,  // ciphertext input data
    unsigned char *out,       // plaintext output data
    unsigned char ivec[16],   // 16 byte initialization vector
    unsigned long length,     // length of input data in bytes
    unsigned char *key,       // encryption key (16, 24, or 32 bytes)
    int number_of_rounds      // Rijndael cipher rounds (10, 12, or 14)
) {
  __m128i data, feedback, last_in;  // init 128 bit SIMD registers 
  int i, j;

  // set number of blocks for CBC
  if (length % 16) {
    length = length / 16 + 1;
  } else {
    length /= 16;
  }


  feedback = _mm_loadu_si128((__m128i*)ivec);
  for(i = 0; i < length; i++) {
    last_in = _mm_loadu_si128((__m128i*)ivec);
    data = _mm_xor_si128(last_in, ((__m128i*)in)[i]);
    for(j = 1; j < number_of_rounds; j++) {
      data = _mm_aesdec_si128(data, ((__m128i*)key)[j]);
    }
    data = _mm_aesdeclast_si128(data, ((__m128i*)key)[j]);
    data = _mm_xor_si128(data, feedback);
    _mm_storeu_si128(&((__m128i*)out)[i], data);
    feedback = last_in;
  }
}

unsigned char randomUnsignedChar(int length) {
  unsigned char data[length - 1];
  int p = *data;
  srandom(time(NULL));
  for (int i = 0; i < length - 1; i++) {
    data[i] = (unsigned char) (rand() % 255 + 1);
  }
  data[length - 1] = 0;
  return p;
}

int main() {
  int piece = randomUnsignedChar(4096);
  printf("\n%c", piece);

}