/*
 * scrypt/src/scrypt.c --
 */

#include <stdlib.h>

#include "scrypt.h"

/**
 * \brief the inverse of the modulo function for S-box
 */
uint8_t inv[] = {15, 6, 13, 4, 11, 2, 9, 0, 7, 14, 5, 12, 3, 10, 1, 8}; 

/**
 *\brief extracts 4 MSB of 8-bit number 
 * \param x 8-bit cipher text
 * \returns MSB from the left of 8-bit number
 */
uint8_t
ext_left(uint8_t x)
{
    uint8_t ext = (x >> 4) & (15);
    return ext;
}

/**
 *\brief extract 4 MSB of 8-bit number 
 *\param x 8-bit cipher text
 *\returns MSB from the right of 8-bit number
*/
uint8_t
ext_right(uint8_t x)
{
    uint8_t ext = (x & 15);
    return ext;
}

/**
 *\brief Substitution function in SP-Network 
 * \returns 8-bit cipher text
 */
uint8_t
sub(uint8_t x)
{
    uint8_t res = (((x + 1) * 7) % 16);
    return res;
}

/**
 * \brief Permutation function in SP-Network
 * \param x - 8-bit cipher text
 * \returns 8-bit cipher text
 */
uint8_t
permutation(uint8_t x)
{
    uint8_t res = (x << 2) | (x >> 6);
    return res;
}

/**
 * \brief Permutation Inverse function in SP-Network
 * \param x - 8-bit cipher text
 * \returns 8-bit cipher text
 */
uint8_t
permutation_inv(uint8_t x)
{
    uint8_t res = ((x >> 2) | (x << 6));
    return res;
}

uint8_t
sc_enc8(uint8_t m, uint32_t k)
{
	uint8_t key_arr[4]; 
	//4 routines of 8-bit key
	for (int i = 0; i < 4; i++)
	{
		key_arr[i] = (uint8_t) ((k >> (24 - i * 8)) & (255));
	}

	//Round 0

	m = m ^ key_arr[0];
	
	//Rounds 1 & 2

	for(int i = 1; i < 3; i++)
	{	
		//substitution
		uint8_t l = ext_left(m);
		uint8_t r = ext_right(m);
		
		l = sub(l);
		r = sub(r);
		m = ((l<<4)|r);
		
		//permutation
		
		m = permutation(m);
		
		//key
		m = m ^ key_arr[i];
	}

	/*Round 3*/
	uint8_t l = ext_left(m);
	uint8_t r = ext_right(m);
	l = sub(l);
	r = sub(r);
	m = ((l<<4)|r);

	m = m ^ key_arr[3];

	return m;
}

//reverses enc8
uint8_t
sc_dec8(uint8_t c, uint32_t k)
{
    uint8_t key_arr[4];
	for (int i = 0; i < 4 ; i++)
	{
		key_arr[i] = (k >> (i * 8)) & (255);
	}

	//reverses all steps in bottom to top
	//key
	c = c ^ key_arr[0];
	
	//substitution
	uint8_t l = ext_left(c);
	uint8_t r = ext_right(c);
	l = inv[l];
	r = inv[r];
	c = ((l << 4) | r);

	//Reverses Round 2 and 1
	for (int i = 1; i < 3; i++)
	{
		//key		
		c = c ^ key_arr[i];
		
		//reverses permutation 
		c = permutation_inv(c);
		
		//reverses substitution
		uint8_t l = ext_left(c);
		uint8_t r = ext_right(c);	
		l = inv[l];
		r = inv[r];
		c = ((l << 4) | r);

	}

	//reverses Round 0
	c = c ^ key_arr[3];
	return c;
}

void
sc_enc_ecb(unsigned char *m, unsigned char *c, size_t len, uint32_t k)
{
    for(int i = 0; i < len; i++)
    {
        c[i] = sc_enc8(m[i], k);
    }
}

void
sc_dec_ecb(unsigned char *c, unsigned char *m, size_t len, uint32_t k)
{
    for(int i = 0; i < len; i++)
    {
        m[i] = sc_dec8(c[i], k);
    }
}

void
sc_enc_cbc(unsigned char *m, unsigned char *c, size_t len, uint32_t k, uint8_t iv)
{
    uint8_t t = iv;
    uint8_t blocks[len];
    for(int i = 0; i < len; i++)
    {
        blocks[i] = m[i];
    }

    for(int i = 0; i < len; i++)
    {
        blocks[i] = blocks[i] ^ t;
        c[i] = sc_enc8(blocks[i], k);
        t = c[i];
    }
}

void
sc_dec_cbc(unsigned char *c, unsigned char *m, size_t len, uint32_t k, uint8_t iv)
{
    uint8_t t = iv;
    uint8_t blocks[len];
    for(int i = 0; i < len; i++)
    {
        blocks[i] = c[i];
    }

    for(int i = 0; i < len; i++)
    {
        m[i] = sc_dec8(blocks[i], k);
        m[i] = m[i] ^ t;
        t = blocks[i];
    }
}
