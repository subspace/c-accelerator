#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <wmmintrin.h>


void encode(
  const uint8_t piece[4096],   // address of 4096 byte piece (plaintext data)
  uint8_t encoding[4096],      // address of 4096 byte encoding (ciphertext data)
  uint8_t iv[16],              // address of 16 byte initialization vector
  uint8_t key[32],             // address of 32 byte encoding key
  size_t blocks,               // number of blocks to iterate for CBC (256)
  size_t rounds                // number of rounds to iterate Rijndael cipher
) {
  __m128i feedback, data; // init 128 bit SIMD registers
  size_t i, j;

  // load IV into feedback register
  feedback = _mm_loadu_si128((__m128i*)iv);

  // apply cipher to input file, block by block
  for(i = 0; i < blocks; i++) {

    // load first block of input into data register
    data = _mm_loadu_si128(&((__m128i*)piece)[i]);

    // XOR data and feedback to get new input
    feedback = _mm_xor_si128(data, feedback);

    // XOR with key for this round to get cipher input
    feedback = _mm_xor_si128(feedback, ((__m128i*)key)[0]);

    // apply Rijndael cipher, rounds - 1 times
    for(j = 1; j < rounds; j++) {
      feedback = _mm_aesenc_si128(feedback, ((__m128i*)key)[0]);
    }

    // apply last round of Rijndael cipher
    feedback = _mm_aesenclast_si128(feedback,((__m128i*)key)[0]);

    // store final output as initial feedback for next block of CBC
    _mm_storeu_si128(&((__m128i*)encoding)[i], feedback);
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

void fillArray(u_int8_t* array, size_t size) {
  for (size_t i = 0; i < size; i++) {
    array[i] = (rand() % 255 + 1);
  }
}

void printArray(uint8_t* array, size_t size) {
  printf("\nPrinting array of size: %zu\n", size);
  for (size_t i = 0; i < size; i++) {
    printf("%d, ", array[i]);
  }
  printf("\n");
}

int main() {

  const size_t BLOCKS_PER_PIECE = 256;
  const size_t AES_ROUNDS = 14;
  const size_t ENCODING_ROUNDS = 384;

  // generate random piece
  const size_t PIECE_SIZE = 4096;
  u_int8_t piece[PIECE_SIZE];
  fillArray(piece, PIECE_SIZE);
  // printArray(piece, PIECE_SIZE);

  // generate random key
  const size_t KEY_SIZE = 32;
  u_int8_t key[KEY_SIZE];
  fillArray(key, KEY_SIZE);
  // printArray(key, KEY_SIZE);

  // generate random iv
  const size_t IV_SIZE = 16;
  u_int8_t iv[IV_SIZE];
  fillArray(iv, IV_SIZE);
  // printArray(iv, IV_SIZE);

  // generate empty encoding
  const size_t ENCODING_SIZE = 4096;
  uint8_t encoding[ENCODING_SIZE];

  clock_t start, end;
  double cpu_time_used;

  start = clock();

  for (size_t i = 0; i < ENCODING_ROUNDS; i++) {
    // encode piece with key and iv
    encode(piece, encoding, iv, key, BLOCKS_PER_PIECE, AES_ROUNDS);
  }

  end = clock();
  cpu_time_used = 1000 * ((double) (end - start)) / CLOCKS_PER_SEC;
  printf("\nCPU time used is %f ms", cpu_time_used);

  // printArray(encoding, ENCODING_SIZE);

  return 0;
}