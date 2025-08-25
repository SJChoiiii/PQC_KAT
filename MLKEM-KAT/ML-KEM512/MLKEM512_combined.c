#include <stdio.h>
#include "kem.h"
#include "type.h"
#include "fips202.h"
//#include "randombytes.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define gen_a(A,B)  PQCLEAN_MLKEM512_CLEAN_gen_matrix(A,B,0)
#define gen_at(A,B) PQCLEAN_MLKEM512_CLEAN_gen_matrix(A,B,1)


#define xof_absorb(STATE, SEED, X, Y) PQCLEAN_MLKEM512_CLEAN_kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) shake128_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) PQCLEAN_MLKEM512_CLEAN_kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) PQCLEAN_MLKEM512_CLEAN_kyber_shake256_rkprf(OUT, KEY, INPUT)

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

#define XOF_BLOCKBYTES SHAKE128_RATE

// ! 컴파일러가 0 또는 1 값을 추론하여 분기문을 사용하지 않도록 방지하기 위한 목적으로 추가된 코드
#define PQCLEAN_PREVENT_BRANCH_HACK(b)  __asm__("" : "+r"(b) : /* no inputs */);

#define randombytes(OUT, OUTLEN) rand2(OUT, OUTLEN)

const int16_t PQCLEAN_MLKEM512_CLEAN_zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};


static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

void rand2(uint8_t* buf, int len)
{
    for (int i = 0; i < len; i++) {
        buf[i] = i;
    }
}
void PQCLEAN_MLKEM512_CLEAN_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;

    // 함수의 입력에서 b = 1 - fail 이므로 c = c' 인 경우  b = 1, 아니라면 b = 0 가 됨

    // ! 컴파일러가 0 또는 1 값을 추론하여 분기문을 사용하지 않도록 방지하기 위한 목적으로 추가된 코드
    // 브랜치 예측 공격을 방지하려는 최적화 기법으로, 분기 예측을 방지하고, 연산을 더 안정적으로 수행하려는 목적입니다.
    //PQCLEAN_PREVENT_BRANCH_HACK(b);

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);  // b가 1(fail = 0) 이라면 ss에 true key K를, b가 0(fail = 1) 이라면 rejection key ss를 그대로 사용함
    }
}
void PQCLEAN_MLKEM512_CLEAN_cmov_int16(int16_t *r, int16_t v, uint16_t b) { // coef, ( q+1 / 2 ), msg bit
    b = -b;                 // bit를 0 -> 0 또는 1 -> -1(0b1111111111111111)로 가져와서
    *r ^= b & ((*r) ^ v);   // r값에 v(q + 1 / 2)를 그대로 가져와서 b랑 합치는 과정 즉,   0 -> 0, 1 -> ( q + 1 / 2 ) 로 변경
}



static uint32_t load24_littleendian(const uint8_t x[3]) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}
static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}
static uint64_t load64(const uint8_t *x) {
    uint64_t r = 0;
    for (size_t i = 0; i < 8; ++i) {
        r |= (uint64_t)x[i] << 8 * i;
    }

    return r;
}
static void store64(uint8_t *x, uint64_t u) {
    for (size_t i = 0; i < 8; ++i) {
        x[i] = (uint8_t) (u >> 8 * i);
    }
}



static void KeccakF1600_StatePermute(uint64_t *state) {
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2) {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}
static void keccak_absorb(uint64_t *s, uint32_t r, const uint8_t *m,size_t mlen, uint8_t p) 
{
    size_t i;
    uint8_t t[200];

    /* Zero state */
    for (i = 0; i < 25; ++i) {
        s[i] = 0;
    }

    while (mlen >= r) {
        for (i = 0; i < r / 8; ++i) {
            s[i] ^= load64(m + 8 * i);
        }

        KeccakF1600_StatePermute(s);
        mlen -= r;
        m += r;
    }

    for (i = 0; i < r; ++i) {
        t[i] = 0;
    }
    for (i = 0; i < mlen; ++i) {
        t[i] = m[i];
    }
    t[i] = p;
    t[r - 1] |= 128;
    for (i = 0; i < r / 8; ++i) {
        s[i] ^= load64(t + 8 * i);
    }
}
static void keccak_squeezeblocks(uint8_t *h, size_t nblocks, uint64_t *s, uint32_t r) {
    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (size_t i = 0; i < (r >> 3); i++) {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}

void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen) {
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE128_RATE, input, inlen, 0x1F);
}
void shake128_ctx_release(shake128ctx *state) {
    free(state->ctx);
}
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE128_RATE);
}
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen) {
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE256_RATE, input, inlen, 0x1F);
}
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE256_RATE);
}
void shake256_ctx_release(shake256ctx *state) {
    free(state->ctx);
}

static void keccak_inc_init(uint64_t *s_inc) {
    size_t i;

    for (i = 0; i < 25; ++i) {
        s_inc[i] = 0;
    }
    s_inc[25] = 0;
}
void shake256_inc_init(shake256incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

static void keccak_inc_absorb(uint64_t *s_inc, uint32_t r, const uint8_t *m, size_t mlen) {
    size_t i;

    /* Recall that s_inc[25] is the non-absorbed bytes xored into the state */
    while (mlen + s_inc[25] >= r) {
        for (i = 0; i < r - (uint32_t)s_inc[25]; i++) {
            /* Take the i'th byte from message
               xor with the s_inc[25] + i'th byte of the state; little-endian */
            s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
        }
        mlen -= (size_t)(r - s_inc[25]);
        m += r - s_inc[25];
        s_inc[25] = 0;

        KeccakF1600_StatePermute(s_inc);
    }

    for (i = 0; i < mlen; i++) {
        s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
    }
    s_inc[25] += mlen;
}
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHAKE256_RATE, input, inlen);
}

static void keccak_inc_finalize(uint64_t *s_inc, uint32_t r, uint8_t p) {
    /* After keccak_inc_absorb, we are guaranteed that s_inc[25] < r,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[25] >> 3] ^= (uint64_t)p << (8 * (s_inc[25] & 0x07));
    s_inc[(r - 1) >> 3] ^= (uint64_t)128 << (8 * ((r - 1) & 0x07));
    s_inc[25] = 0;
}
void shake256_inc_finalize(shake256incctx *state) {
    keccak_inc_finalize(state->ctx, SHAKE256_RATE, 0x1F);
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen, uint64_t *s_inc, uint32_t r) {
    size_t i;

    /* First consume any bytes we still have sitting around */
    for (i = 0; i < outlen && i < s_inc[25]; i++) {
        /* There are s_inc[25] bytes left, so r - s_inc[25] is the first
           available byte. We consume from there, i.e., up to r. */
        h[i] = (uint8_t)(s_inc[(r - s_inc[25] + i) >> 3] >> (8 * ((r - s_inc[25] + i) & 0x07)));
    }
    h += i;
    outlen -= i;
    s_inc[25] -= i;

    /* Then squeeze the remaining necessary blocks */
    while (outlen > 0) {
        KeccakF1600_StatePermute(s_inc);

        for (i = 0; i < outlen && i < r; i++) {
            h[i] = (uint8_t)(s_inc[i >> 3] >> (8 * (i & 0x07)));
        }
        h += i;
        outlen -= i;
        s_inc[25] = r - i;
    }
}
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, SHAKE256_RATE);
}

void shake256_inc_ctx_release(shake256incctx *state) {
    free(state->ctx);
}



void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    size_t nblocks = outlen / SHAKE256_RATE;
    uint8_t t[SHAKE256_RATE];
    shake256ctx s;

    shake256_absorb(&s, input, inlen);
    shake256_squeezeblocks(output, nblocks, &s);

    output += nblocks * SHAKE256_RATE;
    outlen -= nblocks * SHAKE256_RATE;

    if (outlen) {
        shake256_squeezeblocks(t, 1, &s);
        for (size_t i = 0; i < outlen; ++i) {
            output[i] = t[i];
        }
    }
    shake256_ctx_release(&s);
}

void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
    uint64_t s[25];
    uint8_t t[SHA3_256_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

    for (size_t i = 0; i < 32; i++) {
        output[i] = t[i];
    }
}
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen) {
    uint64_t s[25];
    uint8_t t[SHA3_512_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

    for (size_t i = 0; i < 64; i++) {
        output[i] = t[i];
    }
}


void PQCLEAN_MLKEM512_CLEAN_kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];

    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;

    shake256(out, outlen, extkey, sizeof(extkey));
}
void PQCLEAN_MLKEM512_CLEAN_kyber_shake256_rkprf(uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t input[KYBER_CIPHERTEXTBYTES]) {
    shake256incctx s;

    shake256_inc_init(&s);
    shake256_inc_absorb(&s, key, KYBER_SYMBYTES);
    shake256_inc_absorb(&s, input, KYBER_CIPHERTEXTBYTES);
    shake256_inc_finalize(&s);
    shake256_inc_squeeze(out, KYBER_SSBYTES, &s);
    shake256_inc_ctx_release(&s);
}

void PQCLEAN_MLKEM512_CLEAN_kyber_shake128_absorb(xof_state *state, const uint8_t seed[KYBER_SYMBYTES], uint8_t x, uint8_t y) {
    uint8_t extseed[KYBER_SYMBYTES + 2];

    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    shake128_absorb(state, extseed, sizeof(extseed));
}



static void cbd2(poly *r, const uint8_t buf[2 * KYBER_N / 4]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 8; i++) {
        t  = load32_littleendian(buf + 4 * i);
        d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            a = (d >> (4 * j + 0)) & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}
static void cbd3(poly *r, const uint8_t buf[3 * KYBER_N / 4]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 4; i++) {
        t  = load24_littleendian(buf + 3 * i);
        d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            r->coeffs[4 * i + j] = a - b;
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]) {
    cbd3(r, buf);
}
void PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]) {
    cbd2(r, buf);
}

void PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta1(r, buf);
}
void PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(poly *r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    PQCLEAN_MLKEM512_CLEAN_poly_cbd_eta2(r, buf);
}

static unsigned int rej_uniform(int16_t *r, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = val1;
        }
    }

    return ctr;
}

void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed) {
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            if (transposed) {
                xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            } else {
                xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }
            xof_ctx_release(&state);
        }
    }
}



void PQCLEAN_MLKEM512_CLEAN_poly_tobytes(uint8_t r[KYBER_POLYBYTES], const poly *a) 
{
    size_t i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        // map to positive standard representatives
        t0  = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_tobytes(r + i * KYBER_POLYBYTES, &a->vec[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_frombytes(poly *r, const uint8_t a[KYBER_POLYBYTES]) {
    size_t i;
    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i]   = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_frombytes(&r->vec[i], a + i * KYBER_POLYBYTES);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a) {
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = a->coeffs[8 * i + j];
            // t += ((int16_t)t >> 15) & KYBER_Q;
            // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
            t <<= 1;            // 1bit로 압축할거니까 1bit 올려주고
            t += 1665;          // 반올림
            t *= 80635;         // / q 대신해서 * 80635
            t >>= 28;           // / 2*28 로 / q 와 비슷한 연산을 진행해주고
            t &= 1;             // 맨 마지막 1bit만 남겨주기
            msg[i] |= t << j;   // 해당하는 값을 msg[i]에 저장하기
        }
    }
}
void PQCLEAN_MLKEM512_CLEAN_poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) { // m을 m*로 변경해주는 함수 -> 0 : 0, 1 : ( (q + 1) / 2 )
    size_t i, j;

    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = 0;   // 다항식의 한 계수에
            PQCLEAN_MLKEM512_CLEAN_cmov_int16(r->coeffs + 8 * i + j, ((KYBER_Q + 1) / 2), (msg[i] >> j) & 1); // coef, ( q+1 / 2 ), msg bit
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_compress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];


    for (i = 0; i < KYBER_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            // map to positive standard representatives
            u  = a->coeffs[8 * i + j];      // 계수를 가져와서          -q/2 ~ q/2
            u += (u >> 15) & KYBER_Q;       // 계수의 범위를 양수로 변경    0 ~ q - 1
            
            /*    t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15; */
            
            
            d0 = u << 4;    // 32bit에 12bit를 4bit 왼쪽으로 shift 한 값을 저장
            d0 += 1665;     // 반올림을 위해 q + 1 / 2 값을 더해주기
            
            // / kyber_q 대신 아래 2개를 진행해 줌
            // q * 80635의 값은 2^28보다 작은 가장 큰 q의 곱 모양임 -> coef 값을 가장 32bit에 가깝도록 함
            // 실직적으로 kyber_q 로 나누어 주는 것과 차이가 나는 부분은
            // kyber    :    0 ~ 104 : 0,  105 ~ 312 : 1, ... , 3017 ~ 3224 : 15, 3225 ~ 3328 : 0
            // ML-KEM   :    0 ~ 103 : 0,  104 ~ 312 : 1, ... , 3017 ~ 3224 : 15, 3225 ~ 3328 : 0
            // 으로 0을 의미하는 숫자의 갯수가 1개 줄어든 차이밖에 없음
            d0 *= 80635;    
            d0 >>= 28;      
            
            t[j] = d0 & 0xf; // 하위 4BIT 가져오기
        }

        r[0] = t[0] | (t[1] << 4);
        r[1] = t[2] | (t[3] << 4);
        r[2] = t[4] | (t[5] << 4);
        r[3] = t[6] | (t[7] << 4);
        r += 4;
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a) {
    unsigned int i, j, k;
    uint64_t d0;

    uint16_t t[4];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            for (k = 0; k < 4; k++) {
                t[k]  = a->vec[i].coeffs[4 * j + k];
                t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
                
                /*      t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff; */
                
                
                d0 = t[k];  // d0에 t[k]값 저장
                d0 <<= 10;  // * 2^d 진행
                d0 += 1665; // 반올림을 위한 q + 1 / 2 더해주고
                
                // / kyber_q 대신 아래 2개를 진행해 줌
                // q * 1290167 값은 2^32보다 작은 가장 큰 q의 곱 모양임 -> coef 값을 가장 42bit에 가깝게 함,    (2^32 : 4,294,967,296 , q * 1290167 : 4,294,965,943)
                // -> 결국 하위 32bit를 버린다면 10bit가 남게 됨
                d0 *= 1290167; 
                d0 >>= 32;

                t[k] = d0 & 0x3ff;
            }

            r[0] = (uint8_t)(t[0] >> 0);
            r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[4] = (uint8_t)(t[3] >> 2);
            r += 5;
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_decompress(poly *r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]) {
    size_t i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * KYBER_Q) + 8) >> 4;
        r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
        a += 1;
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]) {
    unsigned int i, j, k;

    uint16_t t[4];
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;

            for (k = 0; k < 4; k++) {
                r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * KYBER_Q + 512) >> 10;
            }
        }
    }
}



static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk, const uint8_t seed[KYBER_SYMBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);   // pk뒤에 seed값 연접
}
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, sk);
}

static void unpack_pk(polyvec *pk, uint8_t seed[KYBER_SYMBYTES], const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(pk, packedpk);
    memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_compress(r, b);
    PQCLEAN_MLKEM512_CLEAN_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_decompress(b, c);
    PQCLEAN_MLKEM512_CLEAN_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}



int16_t PQCLEAN_MLKEM512_CLEAN_montgomery_reduce(int32_t a) {
    int16_t t;

    t = (int16_t)a * QINV;
    t = (a - (int32_t)t * KYBER_Q) >> 16;
    return t;
}
int16_t PQCLEAN_MLKEM512_CLEAN_barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

    t  = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= KYBER_Q;
    return a - t;
}
static int16_t fqmul(int16_t a, int16_t b) {
    return PQCLEAN_MLKEM512_CLEAN_montgomery_reduce((int32_t)a * b);
}

void PQCLEAN_MLKEM512_CLEAN_poly_tomont(poly *r) {
    size_t i;
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}


void PQCLEAN_MLKEM512_CLEAN_ntt(int16_t r[256]) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {                  // 각 값의 쌍의 거리를 알려주는 index
        for (start = 0; start < 256; start = j + len) {     // 현재 Layer에 있는 group의 첫 시작 값을 
            zeta = PQCLEAN_MLKEM512_CLEAN_zetas[k++];       // 각 group에 맞는 zeta값을 가져와서 
            for (j = start; j < start + len; j++) {         // 해당 group에 대해서서
                t = fqmul(zeta, r[j + len]);                // t = b * zeta
                r[j + len] = r[j] - t;                      // b = a - b * zeta
                r[j] = r[j] + t;                            // a = a + b * zeta
            }
        }
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_reduce(poly *r) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(r->coeffs[i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_reduce(&r->vec[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_ntt(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_ntt(r->coeffs);
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_ntt(&r->vec[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_add(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_sub(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}


void PQCLEAN_MLKEM512_CLEAN_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
void PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(poly *r, const poly *a, const poly *b) {
    size_t i;
    for (i = 0; i < KYBER_N / 4; i++) {
        PQCLEAN_MLKEM512_CLEAN_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], PQCLEAN_MLKEM512_CLEAN_zetas[64 + i]);
        PQCLEAN_MLKEM512_CLEAN_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -PQCLEAN_MLKEM512_CLEAN_zetas[64 + i]);
    }
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b) {
    unsigned int i;
    poly t;

    PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        PQCLEAN_MLKEM512_CLEAN_poly_add(r, r, &t);
    }

    PQCLEAN_MLKEM512_CLEAN_poly_reduce(r);
}





void PQCLEAN_MLKEM512_CLEAN_invntt(int16_t r[256]) {
    unsigned int start, len, j, k;
    int16_t t, zeta;
    const int16_t f = 1441; // mont^2/128

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = PQCLEAN_MLKEM512_CLEAN_zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = PQCLEAN_MLKEM512_CLEAN_barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
    }

    for (j = 0; j < 256; j++) {
        r[j] = fqmul(r[j], f);
    }
}

void PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(poly *r) {
    PQCLEAN_MLKEM512_CLEAN_invntt(r->coeffs);
}
void PQCLEAN_MLKEM512_CLEAN_polyvec_invntt_tomont(polyvec *r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&r->vec[i]);
    }
}



int PQCLEAN_MLKEM512_CLEAN_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;    // 계산하는 방식만 바뀜 결론은 똑같음
}



void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES], uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES], const uint8_t coins[KYBER_SYMBYTES]) 
{
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    memcpy(buf, coins, KYBER_SYMBYTES);     // ! Kyber에서는 indcpa_keypair부분에서 random값을 생성했지만, ML-KEM에서는 이전에 coin값에 random값을 넣어놓고 그대로 사용함
                                            // A 행렬 생성 seed, noise seed의 seed임

    buf[KYBER_SYMBYTES] = KYBER_K;          // ! Kyber에서는 buf[0~31]까지만 채우고 G함수를 이용 but ML-KEM에서는 buf[32]에 Kyber_K값을 넣어주고
    
    hash_g(buf, buf, KYBER_SYMBYTES + 1);   // 32개의 값을 G함수에 넣는게 아니라 33개의 값을 G 함수에 넣어서 이용함
                                            // G 함수(SHA3_512)로 랜덤값을 Seed로 만들어줌 -> SHA3_512의 앞 32byte를 공개키의 seed값, 뒤 32byte를 noise의 seed값 으로 사용
                                            
                                            // 33번째 byte seed[32]는 module 차원으로, 세 가지 파라미터 세트 간의 도메인 분리를 보장하기 위해서 포함된 것임
                                            // 비밀키 대신 seed를 사용하는 구간에서, 해당 byte로의 확장을 통해서 원래 의도와 다른 parameter set으로 잘못 확장되더라도, 무관한 키가 구성되도록 보장하는것

    gen_a(a, publicseed);                   // Kyber와 마찬가지로 NTT도메인에 올라간 상태로 a행렬 생성

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);    // -3 ~ 3 범위의 비밀키를 생성
    }   // 비밀키 s 생성
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);   // -3 ~ 3 범위의 에러값 생성
    }   // 에러 다항식 e 생성

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&skpv);  // s를 NTT 변환
    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&e);     // e를 NTT 변환

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);  
        PQCLEAN_MLKEM512_CLEAN_poly_tomont(&pkpv.vec[i]);                                   
    }   // as = A * s

    PQCLEAN_MLKEM512_CLEAN_polyvec_add(&pkpv, &pkpv, &e);   // as + e
    PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(&pkpv);           // mod q

    pack_sk(sk, &skpv);                                     // sk encode -> 바이트 배열로 저장
    pack_pk(pk, &pkpv, publicseed);                         // pk encode -> pk : A*s + e (768)  |  A행렬을 생성하는 seed값 (32)
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES], const uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES], const uint8_t coins[KYBER_SYMBYTES]) 
{
    unsigned int i;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[KYBER_K], b;
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    
    PQCLEAN_MLKEM512_CLEAN_poly_frommsg(&k, m); // m의 값(message)을 k = m* 값(polynomial)로 변경, (Decompress_q(Decode_1(m), 1) 과정)
    gen_at(at, seed);                           // A 행렬 생성해주고

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(sp.vec + i, coins, nonce++);
    }   // r 행렬 생성

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    }   // e1 생성

    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(&epp, coins, nonce++); // e2 생성

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&sp); // r 행렬 NTT도메인으로 변경

    // matrix-vector multiplication
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    }   // A * r

    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp); // t * r

    PQCLEAN_MLKEM512_CLEAN_polyvec_invntt_tomont(&b);       // A * r 일반 다항식으로 변경
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&v);          // t * r 일반 다항식으로 변경

    PQCLEAN_MLKEM512_CLEAN_polyvec_add(&b, &b, &ep);        // A * r + e1
    PQCLEAN_MLKEM512_CLEAN_poly_add(&v, &v, &epp);          // t * r + e2
    PQCLEAN_MLKEM512_CLEAN_poly_add(&v, &v, &k);            // t * r + e2 + k*
    
    PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(&b); 
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&v);

    pack_ciphertext(c, &b, &v);     // compress, encode, c : ciphertext,  b : u,  v : v 
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) 
{
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext(&b, &v, c);       // u, v 복원
    unpack_sk(&skpv, sk);               // sk 복원

    PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&b);         // hat_{u}
    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);  // s * u
    PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM512_CLEAN_poly_sub(&mp, &v, &mp);  // v - us
    PQCLEAN_MLKEM512_CLEAN_poly_reduce(&mp);        

    PQCLEAN_MLKEM512_CLEAN_poly_tomsg(m, &mp);  // encode (m*값을 m로 변경)
}


// 실질적인 ML-KEM의 KEM-KEYPAIR 함수라고 생각하면 됨
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) 
{
    PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);                 // sk에 pk 연접
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);   // sk에 H(pk) 연접
    /* Value z for pseudo-random output on reject */
    memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + KYBER_SYMBYTES, KYBER_SYMBYTES); // sk에 random 값 z 연접
    return 0;
}
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) 
{
    uint8_t coins[2 * KYBER_SYMBYTES];          // ! random 값 저장하기 위한 coin값 추가
    randombytes(coins, 2 * KYBER_SYMBYTES);     // random 값 생성 d -> A 행렬 생성 seed, s 행렬 생성 seed 를 생성하는 seed, z -> implicit rejection을 위한 random 값
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);    // ! ML-KEM internal 함수 호출
    return 0;
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) 
{
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];

    memcpy(buf, coins, KYBER_SYMBYTES);

    // ! H(m)하는 ssk의 seed의 seed를 통해 ssk seed를 생성하는 과정이 사라짐
    // ! 즉, ssk의 seed는 random값 그대로임

    
    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES); // H(pk)를 생성
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);                    // ssk seed, H(pk)를 연접하여 ssk || r 생성

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES); // ciphertext 생성, buf : ssk seed || H(pk),  pk : t || a seed,  kr + 32 : r = G(H(pk))

    // ! ciphertext의 해시값을 생성하여 KDF를 이용해 ssk를 뽑아내는 과정 삭제

    memcpy(ss, kr, KYBER_SYMBYTES); // ss에 ssk 저장
    return 0;
}
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) 
{
    uint8_t coins[KYBER_SYMBYTES];
    randombytes(coins, KYBER_SYMBYTES); // ! SSK seed 값 생성
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}


int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) 
{
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];    // ! cmp에 하위 32byte가 추가로 생김 -> 이거 왜 생김 쓸모가 없는디
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;   


    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(buf, ct, sk);         // buf에 message값 복호화

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);   // H(pk)값을 가져오고 -> buf : m || H(pk)
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);    // m || H(pk)를 이용해서 K, r 을 만들어주고

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
    
    
    // 같으면 0, 다르면 1을 뱉는 함수
    fail = PQCLEAN_MLKEM512_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    /* Compute rejection key */
    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);  // sk의 마지막 32byte(random z 값), ciphertext를 이용해서 ss에 저장     J(z||c)

    // 여기까지에서 true key K는 kr의 상위 32byte, rejction key는 ss임 

    /* Copy true key to return buffer if fail is false */
    // fail이 0 -> kr을 ss에 저장, 1 -> 그대로
    PQCLEAN_MLKEM512_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));

    return 0;
}


int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_KAT(uint8_t *pk, uint8_t *sk, uint8_t *d, uint8_t* z) 
{
    uint8_t coins[2 * KYBER_SYMBYTES];          // random 값 저장하기 위한 coin값 추가
    //randombytes(coins, 2 * KYBER_SYMBYTES);     // random 값 생성 d -> A 행렬 생성 seed, s 행렬 생성 seed 를 생성하는 seed, z -> implicit rejection을 위한 random 값
    memcpy(coins, d, 32);
    memcpy(coins + 32, z, 32);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, coins);    // ML-KEM internal 함수 호출
    return 0;
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk, uint8_t *ssk_seed) 
{
    uint8_t coins[KYBER_SYMBYTES];
    //randombytes(coins, KYBER_SYMBYTES); // SSK seed 값 생성
    memcpy(coins, ssk_seed, KYBER_SYMBYTES);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec_KAT(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint8_t *invalid_ct, uint8_t *invalid_ss) 
{
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES + KYBER_SYMBYTES];    // cmp에 하위 32byte가 추가로 생김 -> 이거 왜 생김 쓸모가 없는디
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;   


    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(buf, ct, sk);         // buf에 message값 복호화

    /* Multitarget countermeasure for coins + contributory KEM */
    memcpy(buf + KYBER_SYMBYTES, sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES);   // H(pk)값을 가져오고 -> buf : m || H(pk)
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);    // m || H(pk)를 이용해서 K, r 을 만들어주고

    /* coins are in kr+KYBER_SYMBYTES */
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
    
    
    // 같으면 0, 다르면 1을 뱉는 함수
    fail = PQCLEAN_MLKEM512_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

    uint8_t ss_temp[32];
    /* Compute rejection key */
    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);  // sk의 마지막 32byte(random z 값), ciphertext를 이용해서 ss에 저장     J(z||c)

    // test invalid ct, ss
    rkprf(ss_temp, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, invalid_ct);  // sk의 마지막 32byte(random z 값), ciphertext를 이용해서 ss에 저장     J(z||c)
    if(memcmp(ss_temp, invalid_ss, 32)) return -1;
    // 여기까지에서 true key K는 kr의 상위 32byte, rejction key는 ss임 

    /* Copy true key to return buffer if fail is false */
    // fail이 0 -> kr을 ss에 저장, 1 -> 그대로
    PQCLEAN_MLKEM512_CLEAN_cmov(ss, kr, KYBER_SYMBYTES, (uint8_t) (1 - fail));

    return 0;
}


int TEST()
{
	int ret = 0;

	uint8_t* pk = (uint8_t*)malloc(PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);	//PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES -> 2 * 384 + 32
	uint8_t* sk = (uint8_t*)malloc(PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);	//PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES -> (2 * 384) + (2 * 384 + 32) + (2 * 32)
	uint8_t ct[KYBER_CIPHERTEXTBYTES];							//KYBER_CIPHERTEXTBYTES						   -> (2 * 320) + 128
	uint8_t ss[32];
	uint8_t ss2[32];

	PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);			// KEY »ý¼º + KEY ±³È¯
	// for (int i = 0; i < PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
	// 	printf("%02x ", pk[i]);
	// }
	// printf("\n");
	// for (int i = 0; i < PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES; i++) {
	// 	printf("%02x ", sk[i]);
	// }
	PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
	PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);


	for (int i = 0; i < 32; i++) {
		printf("%02x ", ss[i]);
	}
	printf("\n");
	for (int i = 0; i < 32; i++) { 
		printf("%02x ", ss2[i]);
	}
    free(pk);
    free(sk);

 
	return 0;
}

#include <stdbool.h>

static int hexnibble(int c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return 10 + (c - 'a');
    if ('A' <= c && c <= 'F') return 10 + (c - 'A');
    return -1;
}
static uint8_t hex2bin(const char* s, uint8_t *out, uint64_t outlen) {
    uint64_t L = strlen(s);
    // 공백/개행 제거
    while (L && (s[L - 1] == '\n' || s[L - 1] == '\r' || s[L - 1] == ' ' || s[L - 1] == '\t')) L--;
    if (L % 2) { outlen = 0; return -1; }
    if (!out) return -1;
    for (uint64_t i = 0; i < L / 2; i++) {
        int hi = hexnibble(s[2 * i]), lo = hexnibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { return -1; }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    outlen = L / 2;
    return 1;
}


static bool parse_line(char* line, char* key, char* out) {
    char* p = strstr(line, "=");
    if (!p) return false;
    *p = 0; p++;
    while (*line == ' ' || *line == '\t') line++;
    char* e = line + strlen(line) - 1;
    while (e >= line && (*e == ' ' || *e == '\t')) *e-- = 0;
    while (*p == ' ' || *p == '\t') p++;
    e = p + strlen(p) - 1;
    while (e >= p && (*e == '\n' || *e == '\r' || *e == ' ' || *e == '\t')) *e-- = 0;
    strcpy(key, line);
    strcpy(out, p);

    return true;
}

void get_kat_parameter(FILE *in, void *out, uint64_t outlen)
{
    uint8_t* in_buf  = (uint8_t*)malloc(sizeof(uint8_t) * outlen * 2 + 16);
    uint8_t* out_buf = (uint8_t*)malloc(sizeof(uint8_t) * outlen * 2 + 16);
    int8_t key[32];

    fgets(in_buf, outlen * 2 + 16, in);
    parse_line(in_buf, key, out_buf);
    if (outlen < 6)
    {
        uint64_t v = 0;
        v = strtoull(out_buf, NULL, 10);
        memcpy(out, &v, sizeof(out));
    }
    else
    {
        hex2bin(out_buf, out, outlen);
    }

    free(in_buf);
    free(out_buf);
}

int PRINT_X(uint8_t* in, uint64_t inlen)
{
    printf("\n");
    for(int i = 0;i<inlen;i++)
    {
        printf("%02x", in[i]);
    }
    printf("\n");
}

int TEST_KAT_MLKEM()
{
    int ret = 0;

    FILE* fp;

    fp = fopen("kat_MLKEM_512.rsp", "r");

    while(feof(fp) == 0)
    {
        uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES] = {0,};	//PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES -> 2 * 384 + 32
        uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES] = {0,};	//PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES -> (2 * 384) + (2 * 384 + 32) + (2 * 32)
        uint8_t ct[KYBER_CIPHERTEXTBYTES] = {0,};							//KYBER_CIPHERTEXTBYTES						   -> (2 * 320) + 128
        uint8_t ss[32] = {0,};
        uint8_t ss2[32] = {0,};

        uint64_t count = 0;
        uint8_t z_temp[32] = {0,};
        uint8_t d_temp[32] = {0,};
        uint8_t msg[32] = {0,};
        uint8_t pk_temp[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t sk_temp[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
        uint8_t ct_temp[KYBER_CIPHERTEXTBYTES] = {0,};
        uint8_t ss_temp[32] = {0,};
        uint8_t invalid_ct_temp[KYBER_CIPHERTEXTBYTES] = {0,};
        uint8_t invalid_ss_temp[32] = {0,};

        get_kat_parameter(fp, &count, 1);
        get_kat_parameter(fp, z_temp, 32);
        get_kat_parameter(fp, d_temp, 32);
        get_kat_parameter(fp, msg, 32);

        uint8_t temp[512];
        get_kat_parameter(fp, temp, 512);
        get_kat_parameter(fp, pk_temp, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
        get_kat_parameter(fp, sk_temp, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
        get_kat_parameter(fp, invalid_ct_temp, KYBER_CIPHERTEXTBYTES);
        get_kat_parameter(fp, invalid_ss_temp, 32);
        get_kat_parameter(fp, ct_temp, KYBER_CIPHERTEXTBYTES);
        get_kat_parameter(fp, ss_temp, 32);

        PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_KAT(pk, sk, d_temp, z_temp);
        if(memcmp(pk, pk_temp, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES)) return -1;
        if(memcmp(sk, sk_temp, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES)) return -1;

        PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_KAT(ct, ss, pk, msg);
        
        if(memcmp(ct, ct_temp, KYBER_CIPHERTEXTBYTES)) return -1;
        if(memcmp(ss, ss_temp, 32)) return -1;

        PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec_KAT(ss2, ct, sk, invalid_ct_temp, invalid_ss_temp);
        if(memcmp(ss2, ss_temp, 32)) return -1;
        
        
        //printf("%d is done\n", count);
    }

    printf("ML-KEM 512 KAT done\n");
 
	return 0;
}

int main()
{   
    TEST_KAT_MLKEM();

    return 0;
}