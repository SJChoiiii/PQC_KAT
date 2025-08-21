#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "params.h"
#include "fips202.h"
#include "symmetric.h"
//
#define MLEN 16
#define NTESTS 1

#include <windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */

static int randombytes_win32_randombytes(void *buf, const size_t n)
{
    HCRYPTPROV ctx;
    BOOL tmp;

    tmp = CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptGenRandom(ctx, (unsigned long)n, (BYTE *)buf);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptReleaseContext(ctx, 0);
    if (tmp == FALSE)
    {
        return -1;
    }

    return 0;
}


#define CTX_LEN 16

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))


#define DBENCH_START() // 아무 의미 없는 코드임
#define DBENCH_STOP(t)


static const int32_t zetas[MLDSA65_N] = {
    0,    25847, -2608894, -518909,   237124, -777960, -876248,   466468,
    1826347,  2353451, -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
    2725464,  1024112, -1079900,  3585928, -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672,  1757237, -19422,  4010497,   280005,
    2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968, -300467,  2348700, -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
    3412210, -983419,  2147896,  2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987,  1349076,  1852771, -1430430,
    -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342, -8578,  1653064, -3249728,  2389356, -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325, -177440,  1315589,  1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
    2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174, -43260, -522500,
    -655327, -3122442,  2031748,  3207046, -3556995, -525098, -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
    2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225, -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455, -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111, -975884,  1717735,   472078,
    -426683,  1723600, -1803090,  1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327,   183443, -976891,  1612842, -3545687,
    -554416,  3919660, -48306, -1362209,  3937738,  1400424, -846154,  1976782
};


/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_montgomery_reduce(int64_t a) {
    int32_t t;

    t = (int32_t)((uint64_t)a * (uint64_t)QINV);
    t = (a - (int64_t)t * Q) >> 32;
    return t;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_reduce32(int32_t a) {
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_caddq(int32_t a) {
    a += (a >> 31) & Q;
    return a;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ Q.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_freeze(int32_t a) {
    a = PQCLEAN_MLDSA65_CLEAN_reduce32(a);
    a = PQCLEAN_MLDSA65_CLEAN_caddq(a);
    return a;
}

int32_t PQCLEAN_MLDSA65_CLEAN_power2round(int32_t *a0, int32_t a)  {
    int32_t a1;

    a1 = (a + (1 << (D - 1)) - 1) >> D;
    *a0 = a - (a1 << D);
    return a1;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_decompose(int32_t *a0, int32_t a) {
    int32_t a1;

    a1  = (a + 127) >> 7;
    a1  = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;

    *a0  = a - a1 * 2 * GAMMA2;
    *a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;
    return a1;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits.
*
* Arguments:   - int32_t a0: low bits of input element
*              - int32_t a1: high bits of input element
*
* Returns 1 if overflow.
**************************************************/
unsigned int PQCLEAN_MLDSA65_CLEAN_make_hint(int32_t a0, int32_t a1) {
    if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0)) {
        return 1;
    }

    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - int32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
int32_t PQCLEAN_MLDSA65_CLEAN_use_hint(int32_t a, unsigned int hint) {      // !! MLDSA65 -> 65 변경 함수
    int32_t a0, a1;

    a1 = PQCLEAN_MLDSA65_CLEAN_decompose(&a0, a);
    if (hint == 0) {
        return a1;
    }

    if (a0 > 0) {
        return (a1 + 1) & 15;
    }
    return (a1 - 1) & 15;
}


#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

/*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into uint64_t in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
static uint64_t load64(const uint8_t *x) {
    uint64_t r = 0;
    for (size_t i = 0; i < 8; ++i) {
        r |= (uint64_t)x[i] << 8 * i;
    }

    return r;
}

/*************************************************
 * Name:        store64
 *
 * Description: Store a 64-bit integer to a byte array in little-endian order
 *
 * Arguments:   - uint8_t *x: pointer to the output byte array
 *              - uint64_t u: input 64-bit unsigned integer
 **************************************************/
static void store64(uint8_t *x, uint64_t u) {
    for (size_t i = 0; i < 8; ++i) {
        x[i] = (uint8_t) (u >> 8 * i);
    }
}

/* Keccak round constants */
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

/*************************************************
 * Name:        KeccakF1600_StatePermute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - uint64_t *state: pointer to input/output Keccak state
 **************************************************/
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

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_absorb(uint64_t *s, uint32_t r, const uint8_t *m,
                          size_t mlen, uint8_t p) {
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

/*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *h: pointer to output blocks
 *              - size_t nblocks: number of blocks to be
 *                                                squeezed (written to h)
 *              - uint64_t *s: pointer to input/output Keccak state
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_squeezeblocks(uint8_t *h, size_t nblocks,
                                 uint64_t *s, uint32_t r) {
    while (nblocks > 0) {
        KeccakF1600_StatePermute(s);
        for (size_t i = 0; i < (r >> 3); i++) {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}

/*************************************************
 * Name:        keccak_inc_init
 *
 * Description: Initializes the incremental Keccak state to zero.
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 **************************************************/
static void keccak_inc_init(uint64_t *s_inc) {
    size_t i;

    for (i = 0; i < 25; ++i) {
        s_inc[i] = 0;
    }
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_absorb
 *
 * Description: Incremental keccak absorb
 *              Preceded by keccak_inc_init, succeeded by keccak_inc_finalize
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 **************************************************/
static void keccak_inc_absorb(uint64_t *s_inc, uint32_t r, const uint8_t *m,
                              size_t mlen) {
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

/*************************************************
 * Name:        keccak_inc_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_inc_finalize(uint64_t *s_inc, uint32_t r, uint8_t p) {
    /* After keccak_inc_absorb, we are guaranteed that s_inc[25] < r,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[25] >> 3] ^= (uint64_t)p << (8 * (s_inc[25] & 0x07));
    s_inc[(r - 1) >> 3] ^= (uint64_t)128 << (8 * ((r - 1) & 0x07));
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - uint8_t *h: pointer to output bytes
 *              - size_t outlen: number of bytes to be squeezed
 *              - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_inc_squeeze(uint8_t *h, size_t outlen,
                               uint64_t *s_inc, uint32_t r) {
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

void shake128_inc_init(shake128incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(shake128incctx *state) {
    keccak_inc_finalize(state->ctx, SHAKE128_RATE, 0x1F);
}

void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, SHAKE128_RATE);
}

void shake128_inc_ctx_clone(shake128incctx *dest, const shake128incctx *src) {
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void shake128_inc_ctx_release(shake128incctx *state) {
    free(state->ctx);
}

void shake256_inc_init(shake256incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(shake256incctx *state) {
    keccak_inc_finalize(state->ctx, SHAKE256_RATE, 0x1F);
}

void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, SHAKE256_RATE);
}

void shake256_inc_ctx_clone(shake256incctx *dest, const shake256incctx *src) {
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void shake256_inc_ctx_release(shake256incctx *state) {
    free(state->ctx);
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - const uint8_t *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen) {
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE128_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                            (written to output)
 *              - shake128ctx *state: pointer to input/output Keccak state
 **************************************************/
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE128_RATE);
}

void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src) {
    dest->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKECTX_BYTES);
}

/** Release the allocated state. Call only once. */
void shake128_ctx_release(shake128ctx *state) {
    free(state->ctx);
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - shake256ctx *state: pointer to (uninitialized) output Keccak state
 *              - const uint8_t *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen) {
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE256_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - shake256ctx *state: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state) {
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE256_RATE);
}

void shake256_ctx_clone(shake256ctx *dest, const shake256ctx *src) {
    dest->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKECTX_BYTES);
}

/** Release the allocated state. Call only once. */
void shake256_ctx_release(shake256ctx *state) {
    free(state->ctx);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *output: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen) {
    size_t nblocks = outlen / SHAKE128_RATE;
    uint8_t t[SHAKE128_RATE];
    shake128ctx s;

    shake128_absorb(&s, input, inlen);
    shake128_squeezeblocks(output, nblocks, &s);

    output += nblocks * SHAKE128_RATE;
    outlen -= nblocks * SHAKE128_RATE;

    if (outlen) {
        shake128_squeezeblocks(t, 1, &s);
        for (size_t i = 0; i < outlen; ++i) {
            output[i] = t[i];
        }
    }
    shake128_ctx_release(&s);
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *output: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen) {
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

void sha3_256_inc_init(sha3_256incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_256_inc_ctx_clone(sha3_256incctx *dest, const sha3_256incctx *src) {
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_256_inc_ctx_release(sha3_256incctx *state) {
    free(state->ctx);
}

void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHA3_256_RATE, input, inlen);
}

void sha3_256_inc_finalize(uint8_t *output, sha3_256incctx *state) {
    uint8_t t[SHA3_256_RATE];
    keccak_inc_finalize(state->ctx, SHA3_256_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_256_RATE);

    sha3_256_inc_ctx_release(state);

    for (size_t i = 0; i < 32; i++) {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
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

void sha3_384_inc_init(sha3_384incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_384_inc_ctx_clone(sha3_384incctx *dest, const sha3_384incctx *src) {
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_384_inc_absorb(sha3_384incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHA3_384_RATE, input, inlen);
}

void sha3_384_inc_ctx_release(sha3_384incctx *state) {
    free(state->ctx);
}

void sha3_384_inc_finalize(uint8_t *output, sha3_384incctx *state) {
    uint8_t t[SHA3_384_RATE];
    keccak_inc_finalize(state->ctx, SHA3_384_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_384_RATE);

    sha3_384_inc_ctx_release(state);

    for (size_t i = 0; i < 48; i++) {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_384
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen) {
    uint64_t s[25];
    uint8_t t[SHA3_384_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_384_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_384_RATE);

    for (size_t i = 0; i < 48; i++) {
        output[i] = t[i];
    }
}

void sha3_512_inc_init(sha3_512incctx *state) {
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_512_inc_ctx_clone(sha3_512incctx *dest, const sha3_512incctx *src) {
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL) {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, SHA3_512_RATE, input, inlen);
}

void sha3_512_inc_ctx_release(sha3_512incctx *state) {
    free(state->ctx);
}

void sha3_512_inc_finalize(uint8_t *output, sha3_512incctx *state) {
    uint8_t t[SHA3_512_RATE];
    keccak_inc_finalize(state->ctx, SHA3_512_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_512_RATE);

    sha3_512_inc_ctx_release(state);

    for (size_t i = 0; i < 64; i++) {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
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

void PQCLEAN_MLDSA65_CLEAN_dilithium_shake128_stream_init(shake128incctx *state, const uint8_t seed[SEEDBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    shake128_inc_init(state);
    shake128_inc_absorb(state, seed, SEEDBYTES);
    shake128_inc_absorb(state, t, 2);
    shake128_inc_finalize(state);
}

void PQCLEAN_MLDSA65_CLEAN_dilithium_shake256_stream_init(shake256incctx *state, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    uint8_t t[2];
    t[0] = (uint8_t) nonce;
    t[1] = (uint8_t) (nonce >> 8);

    shake256_inc_init(state);
    shake256_inc_absorb(state, seed, CRHBYTES);
    shake256_inc_absorb(state, t, 2);
    shake256_inc_finalize(state);
}


void PQCLEAN_MLDSA65_CLEAN_ntt(int32_t a[MLDSA65_N]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < MLDSA65_N; start = j + len) {
            zeta = zetas[++k];
            for (j = start; j < start + len; ++j) {
                t = PQCLEAN_MLDSA65_CLEAN_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_invntt_tomont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions; input coefficients need to be smaller than
*              Q in absolute value. Output coefficient are smaller than Q in
*              absolute value.
*
* Arguments:   - uint32_t p[MLDSA65_N]: input/output coefficient array
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_invntt_tomont(int32_t a[MLDSA65_N]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978; // mont^2/256

    k = 256;
    for (len = 1; len < MLDSA65_N; len <<= 1) {
        for (start = 0; start < MLDSA65_N; start = j + len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = PQCLEAN_MLDSA65_CLEAN_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < MLDSA65_N; ++j) {
        a[j] = PQCLEAN_MLDSA65_CLEAN_montgomery_reduce((int64_t)f * a[j]);
    }
}



/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_reduce
*
* Description: Inplace reduction of all coefficients of polynomial to
*              representative in [-6283008,6283008].
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_reduce(poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        a->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_reduce32(a->coeffs[i]);
    }

    DBENCH_STOP(*tred);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_caddq
*
* Description: For all coefficients of in/out polynomial add Q if
*              coefficient is negative.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_caddq(poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        a->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_caddq(a->coeffs[i]);
    }

    DBENCH_STOP(*tred);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_add(poly *c, const poly *a, const poly *b)  {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }

    DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_sub
*
* Description: Subtract polynomials. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_sub(poly *c, const poly *a, const poly *b) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }

    DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{31-D} in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_shiftl(poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        a->coeffs[i] <<= D;
    }

    DBENCH_STOP(*tmul);
}



/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_ntt
*
* Description: Inplace forward NTT. Coefficients can grow by
*              8*Q in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_ntt(poly *a) {
    DBENCH_START();

    PQCLEAN_MLDSA65_CLEAN_ntt(a->coeffs);

    DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_invntt_tomont
*
* Description: Inplace inverse NTT and multiplication by 2^{32}.
*              Input coefficients need to be less than Q in absolute
*              value and output coefficients are again bounded by Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_invntt_tomont(poly *a) {
    DBENCH_START();

    PQCLEAN_MLDSA65_CLEAN_invntt_tomont(a->coeffs);

    DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              by 2^{-32}.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        c->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }

    DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_power2round(poly *a1, poly *a0, const poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        a1->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_power2round(&a0->coeffs[i], a->coeffs[i]);
    }

    DBENCH_STOP(*tround);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_decompose(poly *a1, poly *a0, const poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        a1->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_decompose(&a0->coeffs[i], a->coeffs[i]);
    }

    DBENCH_STOP(*tround);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
unsigned int PQCLEAN_MLDSA65_CLEAN_poly_make_hint(poly *h, const poly *a0, const poly *a1) {
    unsigned int i, s = 0;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        h->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }

    DBENCH_STOP(*tround);
    return s;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *b: pointer to output polynomial with corrected high bits
*              - const poly *a: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_use_hint(poly *b, const poly *a, const poly *h) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N; ++i) {
        b->coeffs[i] = PQCLEAN_MLDSA65_CLEAN_use_hint(a->coeffs[i], h->coeffs[i]);
    }

    DBENCH_STOP(*tround);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients were reduced by PQCLEAN_MLDSA65_CLEAN_reduce32().
*
* Arguments:   - const poly *a: pointer to polynomial
*              - int32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_poly_chknorm(const poly *a, int32_t B) {
    unsigned int i;
    int32_t t;
    DBENCH_START();

    if (B > (Q - 1) / 8) {
        return 1;
    }

    /* It is ok to leak which coefficient violates the bound since
       the probability for each coefficient is independent of secret
       data but we must not leak the sign of the centralized representative. */
    for (i = 0; i < MLDSA65_N; ++i) {
        /* Absolute value */
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

        if (t >= B) {
            DBENCH_STOP(*tsample);
            return 1;
        }
    }

    DBENCH_STOP(*tsample);
    return 0;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, Q-1] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;
    DBENCH_START();

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t  = buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < Q) {
            a[ctr++] = t;
        }
    }

    DBENCH_STOP(*tsample);
    return ctr;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling on the
*              output stream of SHAKE128(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
void PQCLEAN_MLDSA65_CLEAN_poly_uniform(poly *a,
                                        const uint8_t seed[SEEDBYTES],
                                        uint16_t nonce) {
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2];
    stream128_state state;

    stream128_init(&state, seed, nonce);
    stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

    ctr = rej_uniform(a->coeffs, MLDSA65_N, buf, buflen);

    while (ctr < MLDSA65_N) {
        off = buflen % 3;
        for (i = 0; i < off; ++i) {
            buf[i] = buf[buflen - off + i];
        }

        stream128_squeezeblocks(buf + off, 1, &state);
        buflen = STREAM128_BLOCKBYTES + off;
        ctr += rej_uniform(a->coeffs + ctr, MLDSA65_N - ctr, buf, buflen);
    }
    stream128_release(&state);
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen) {      // !! MLDSA65 -> 65 변경 함수
    unsigned int ctr, pos;
    uint32_t t0, t1;
    DBENCH_START();

    ctr = pos = 0;
    while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (t0 < 9) {
            a[ctr++] = 4 - t0;
        }
        if (t1 < 9 && ctr < len) {
            a[ctr++] = 4 - t1;
        }
    }

    DBENCH_STOP(*tsample);
    return ctr;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling on the
*              output stream from SHAKE256(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
void PQCLEAN_MLDSA65_CLEAN_poly_uniform_eta(poly *a,
        const uint8_t seed[CRHBYTES],
        uint16_t nonce) {
    unsigned int ctr;
    unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES];
    stream256_state state;

    stream256_init(&state, seed, nonce);
    stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

    ctr = rej_eta(a->coeffs, MLDSA65_N, buf, buflen);

    while (ctr < MLDSA65_N) {
        stream256_squeezeblocks(buf, 1, &state);
        ctr += rej_eta(a->coeffs + ctr, MLDSA65_N - ctr, buf, STREAM256_BLOCKBYTES);
    }
    stream256_release(&state);
}

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
*              of SHAKE256(seed|nonce)
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyz_unpack(poly *r, const uint8_t *a) {    // !! MLDSA65 -> 65 변경 함수
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 2; ++i) {
        r->coeffs[2 * i + 0]  = a[5 * i + 0];
        r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
        r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
        r->coeffs[2 * i + 0] &= 0xFFFFF;

        r->coeffs[2 * i + 1]  = a[5 * i + 2] >> 4;
        r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
        r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;
        /* r->coeffs[2*i+1] &= 0xFFFFF; */ /* No effect, since we're anyway at 20 bits */

        r->coeffs[2 * i + 0] = GAMMA1 - r->coeffs[2 * i + 0];
        r->coeffs[2 * i + 1] = GAMMA1 - r->coeffs[2 * i + 1];
    }

    DBENCH_STOP(*tpack);
}

void PQCLEAN_MLDSA65_CLEAN_poly_uniform_gamma1(poly *a,
        const uint8_t seed[CRHBYTES],
        uint16_t nonce) {
    uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];
    stream256_state state;

    stream256_init(&state, seed, nonce);
    stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
    stream256_release(&state);
    PQCLEAN_MLDSA65_CLEAN_polyz_unpack(a, buf);
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with TAU nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(seed).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing seed of length CTILDEBYTES
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[SHAKE256_RATE];
    shake256incctx state;

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, seed, CTILDEBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf, sizeof buf, &state);

    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << 8 * i;
    }
    pos = 8;

    for (i = 0; i < MLDSA65_N; ++i) {
        c->coeffs[i] = 0;
    }
    for (i = MLDSA65_N - TAU; i < MLDSA65_N; ++i) {
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_inc_squeeze(buf, sizeof buf, &state);
                pos = 0;
            }

            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
    shake256_inc_ctx_release(&state);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYETA_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyeta_pack(uint8_t *r, const poly *a) {        // !! MLDSA65 -> 65 변경 함수
    unsigned int i;
    uint8_t t[8];
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 2; ++i) {
        t[0] = (uint8_t) (ETA - a->coeffs[2 * i + 0]);
        t[1] = (uint8_t) (ETA - a->coeffs[2 * i + 1]);
        r[i] = t[0] | (t[1] << 4);
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyeta_unpack(poly *r, const uint8_t *a) {      // !! MLDSA65 -> 65 변경 함수
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 2; ++i) {
        r->coeffs[2 * i + 0] = a[i] & 0x0F;
        r->coeffs[2 * i + 1] = a[i] >> 4;
        r->coeffs[2 * i + 0] = ETA - r->coeffs[2 * i + 0];
        r->coeffs[2 * i + 1] = ETA - r->coeffs[2 * i + 1];
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyt1_pack(uint8_t *r, const poly *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 4; ++i) {
        r[5 * i + 0] = (uint8_t) (a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (uint8_t) ((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2));
        r[5 * i + 2] = (uint8_t) ((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4));
        r[5 * i + 3] = (uint8_t) ((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6));
        r[5 * i + 4] = (uint8_t) (a->coeffs[4 * i + 3] >> 2);
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyt1_unpack
*
* Description: Unpack polynomial t1 with 10-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyt1_unpack(poly *r, const uint8_t *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 4; ++i) {
        r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT0_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyt0_pack(uint8_t *r, const poly *a) {
    unsigned int i;
    uint32_t t[8];
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 8; ++i) {
        t[0] = (1 << (D - 1)) - a->coeffs[8 * i + 0];
        t[1] = (1 << (D - 1)) - a->coeffs[8 * i + 1];
        t[2] = (1 << (D - 1)) - a->coeffs[8 * i + 2];
        t[3] = (1 << (D - 1)) - a->coeffs[8 * i + 3];
        t[4] = (1 << (D - 1)) - a->coeffs[8 * i + 4];
        t[5] = (1 << (D - 1)) - a->coeffs[8 * i + 5];
        t[6] = (1 << (D - 1)) - a->coeffs[8 * i + 6];
        t[7] = (1 << (D - 1)) - a->coeffs[8 * i + 7];

        r[13 * i + 0]  =  (uint8_t) t[0];
        r[13 * i + 1]  =  (uint8_t) (t[0] >>  8);
        r[13 * i + 1] |=  (uint8_t) (t[1] <<  5);
        r[13 * i + 2]  =  (uint8_t) (t[1] >>  3);
        r[13 * i + 3]  =  (uint8_t) (t[1] >> 11);
        r[13 * i + 3] |=  (uint8_t) (t[2] <<  2);
        r[13 * i + 4]  =  (uint8_t) (t[2] >>  6);
        r[13 * i + 4] |=  (uint8_t) (t[3] <<  7);
        r[13 * i + 5]  =  (uint8_t) (t[3] >>  1);
        r[13 * i + 6]  =  (uint8_t) (t[3] >>  9);
        r[13 * i + 6] |=  (uint8_t) (t[4] <<  4);
        r[13 * i + 7]  =  (uint8_t) (t[4] >>  4);
        r[13 * i + 8]  =  (uint8_t) (t[4] >> 12);
        r[13 * i + 8] |=  (uint8_t) (t[5] <<  1);
        r[13 * i + 9]  =  (uint8_t) (t[5] >>  7);
        r[13 * i + 9] |=  (uint8_t) (t[6] <<  6);
        r[13 * i + 10]  =  (uint8_t) (t[6] >>  2);
        r[13 * i + 11]  =  (uint8_t) (t[6] >> 10);
        r[13 * i + 11] |=  (uint8_t) (t[7] <<  3);
        r[13 * i + 12]  =  (uint8_t) (t[7] >>  5);
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyt0_unpack(poly *r, const uint8_t *a) {
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 8; ++i) {
        r->coeffs[8 * i + 0]  = a[13 * i + 0];
        r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
        r->coeffs[8 * i + 0] &= 0x1FFF;

        r->coeffs[8 * i + 1]  = a[13 * i + 1] >> 5;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2]  = a[13 * i + 3] >> 2;
        r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3]  = a[13 * i + 4] >> 7;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4]  = a[13 * i + 6] >> 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5]  = a[13 * i + 8] >> 1;
        r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6]  = a[13 * i + 9] >> 6;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7]  = a[13 * i + 11] >> 3;
        r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
        r->coeffs[8 * i + 7] &= 0x1FFF;

        r->coeffs[8 * i + 0] = (1 << (D - 1)) - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = (1 << (D - 1)) - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = (1 << (D - 1)) - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = (1 << (D - 1)) - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = (1 << (D - 1)) - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = (1 << (D - 1)) - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = (1 << (D - 1)) - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = (1 << (D - 1)) - r->coeffs[8 * i + 7];
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyz_pack
*
* Description: Bit-pack polynomial with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYZ_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyz_pack(uint8_t *r, const poly *a) {      // !! MLDSA65 -> 65 변경 함수
    unsigned int i;
    uint32_t t[4];
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 2; ++i) {
        t[0] = GAMMA1 - a->coeffs[2 * i + 0];
        t[1] = GAMMA1 - a->coeffs[2 * i + 1];

        r[5 * i + 0]  = (uint8_t) (t[0]);
        r[5 * i + 1]  = (uint8_t) (t[0] >> 8);
        r[5 * i + 2]  = (uint8_t) (t[0] >> 16);
        r[5 * i + 2] |= (uint8_t) (t[1] << 4);
        r[5 * i + 3]  = (uint8_t) (t[1] >> 4);
        r[5 * i + 4]  = (uint8_t) (t[1] >> 12);
    }

    DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/


/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYW1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyw1_pack(uint8_t *r, const poly *a) {     // !! MLDSA65 -> 65 변경 함수
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < MLDSA65_N / 2; ++i) {
        r[i] = (uint8_t) (a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4));
    }

    DBENCH_STOP(*tpack);
}


/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*
* Arguments:   - polyvecl mat[MLDSA65_K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(polyvecl mat[MLDSA65_K], const uint8_t rho[SEEDBYTES]) {
    unsigned int i, j;

    for (i = 0; i < MLDSA65_K; ++i) {
        for (j = 0; j < MLDSA65_L; ++j) {
            PQCLEAN_MLDSA65_CLEAN_poly_uniform(&mat[i].vec[j], rho, (uint16_t) ((i << 8) + j));
        }
    }
}


/**************************************************************/
/************ Vectors of polynomials of length MLDSA65_L **************/
/**************************************************************/

void PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t) (MLDSA65_L * nonce + i));
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_reduce(&v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyvecl_add
*
* Description: Add vectors of polynomials of length MLDSA65_L.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length MLDSA65_L. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length MLDSA65_L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_acc_montgomery(poly *w,
        const polyvecl *u,
        const polyvecl *v) {
    unsigned int i;
    poly t;

    PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        PQCLEAN_MLDSA65_CLEAN_poly_add(w, w, &t);
    }
}
void PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[MLDSA65_K], const polyvecl *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length MLDSA65_L.
*              Assumes input polyvecl to be reduced by PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce().
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
    unsigned int i;

    for (i = 0; i < MLDSA65_L; ++i) {
        if (PQCLEAN_MLDSA65_CLEAN_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length MLDSA65_K **************/
/**************************************************************/

void PQCLEAN_MLDSA65_CLEAN_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length MLDSA65_K
*              to representatives in [-6283008,6283008].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_reduce(&v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length MLDSA65_K
*              add Q if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_caddq(&v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_add
*
* Description: Add vectors of polynomials of length MLDSA65_K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_sub
*
* Description: Subtract vectors of polynomials of length MLDSA65_K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length MLDSA65_K by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_shiftl(polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_shiftl(&v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length MLDSA65_K. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_ntt(&v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length MLDSA65_K. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}


/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length MLDSA65_K.
*              Assumes input polyveck to be reduced by PQCLEAN_MLDSA65_CLEAN_polyveck_reduce().
*
* Arguments:   - const polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(const polyveck *v, int32_t bound) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        if (PQCLEAN_MLDSA65_CLEAN_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }

    return 0;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length MLDSA65_K,
*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length MLDSA65_K,
*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(polyveck *h,
        const polyveck *v0,
        const polyveck *v1) {
    unsigned int i, s = 0;

    for (i = 0; i < MLDSA65_K; ++i) {
        s += PQCLEAN_MLDSA65_CLEAN_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_poly_use_hint(&w->vec[i], &v->vec[i], &h->vec[i]);
    }
}

void PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(uint8_t r[MLDSA65_K * POLYW1_PACKEDBYTES], const polyveck *w1) {
    unsigned int i;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}


/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_pack_pk(uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const polyveck *t1) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        pk[i] = rho[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_unpack_pk(uint8_t rho[SEEDBYTES],
                                     polyveck *t1,
                                     const uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES]) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        rho[i] = pk[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_pack_sk(uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const uint8_t tr[TRBYTES],
                                   const uint8_t key[SEEDBYTES],
                                   const polyveck *t0,
                                   const polyvecl *s1,
                                   const polyveck *s2) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        sk[i] = rho[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i) {
        sk[i] = key[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i) {
        sk[i] = tr[i];
    }
    sk += TRBYTES;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);
    }
    sk += MLDSA65_L * POLYETA_PACKEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
    }
    sk += MLDSA65_K * POLYETA_PACKEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_unpack_sk(uint8_t rho[SEEDBYTES],
                                     uint8_t tr[TRBYTES],
                                     uint8_t key[SEEDBYTES],
                                     polyveck *t0,
                                     polyvecl *s1,
                                     polyveck *s2,
                                     const uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES]) {
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i) {
        rho[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i) {
        key[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < TRBYTES; ++i) {
        tr[i] = sk[i];
    }
    sk += TRBYTES;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES);
    }
    sk += MLDSA65_L * POLYETA_PACKEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
    }
    sk += MLDSA65_K * POLYETA_PACKEDBYTES;

    for (i = 0; i < MLDSA65_K; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void PQCLEAN_MLDSA65_CLEAN_pack_sig(uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES],
                                    const uint8_t c[CTILDEBYTES],
                                    const polyvecl *z,
                                    const polyveck *h) {
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i) {
        sig[i] = c[i];
    }
    sig += CTILDEBYTES;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
    }
    sig += MLDSA65_L * POLYZ_PACKEDBYTES;

    /* Encode h */
    for (i = 0; i < OMEGA + MLDSA65_K; ++i) {
        sig[i] = 0;
    }

    k = 0;
    for (i = 0; i < MLDSA65_K; ++i) {
        for (j = 0; j < MLDSA65_N; ++j) {
            if (h->vec[i].coeffs[j] != 0) {
                sig[k++] = (uint8_t) j;
            }
        }

        sig[OMEGA + i] = (uint8_t) k;
    }
}

/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_unpack_sig(uint8_t c[CTILDEBYTES],
                                     polyvecl *z,
                                     polyveck *h,
                                     const uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES]) {
    unsigned int i, j, k;

    for (i = 0; i < CTILDEBYTES; ++i) {
        c[i] = sig[i];
    }
    sig += CTILDEBYTES;

    for (i = 0; i < MLDSA65_L; ++i) {
        PQCLEAN_MLDSA65_CLEAN_polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
    }
    sig += MLDSA65_L * POLYZ_PACKEDBYTES;

    /* Decode h */
    k = 0;
    for (i = 0; i < MLDSA65_K; ++i) {
        for (j = 0; j < MLDSA65_N; ++j) {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA) {
            return 1;
        }

        for (j = k; j < sig[OMEGA + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1]) {
                return 1;
            }
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA; ++j) {
        if (sig[j]) {
            return 1;
        }
    }

    return 0;
}


/*************************************************
* Name:        PQCLEAN_MLDSA65_CLEAN_ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Output vector is in bitreversed order.
*
* Arguments:   - uint32_t p[MLDSA65_N]: input/output coefficient array
**************************************************/






int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[MLDSA65_K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes_win32_randombytes(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = MLDSA65_K;
    seedbuf[SEEDBYTES + 1] = MLDSA65_L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_uniform_eta(&s2, rhoprime, MLDSA65_L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA65_CLEAN_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, TRBYTES, pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_MLDSA65_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}


int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_KAT(uint8_t *pk, uint8_t *sk, uint8_t *seed) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[MLDSA65_K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    //randombytes_win32_randombytes(seedbuf, SEEDBYTES);
    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = MLDSA65_K;
    seedbuf[SEEDBYTES + 1] = MLDSA65_L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    
    
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_uniform_eta(&s2, rhoprime, MLDSA65_L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA65_CLEAN_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, TRBYTES, pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_MLDSA65_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *ctx:   pointer to context string
*              - size_t ctxlen:  length of context string
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[MLDSA65_K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    if (ctxlen > 255) {
        return -1;
    }

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    //randombytes_win32_randombytes(rnd, RNDBYTES);
    for(int i = 0;i<RNDBYTES;i++)
    {
        rnd[i] = 0;
    }
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, MLDSA65_K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_MLDSA65_CLEAN_pack_sig(sig, sig, &z, &h);
    *siglen = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    return 0;
}

int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_KAT(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk,
        uint8_t *rng) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[MLDSA65_K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    if (ctxlen > 255) {
        return -1;
    }

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    //randombytes_win32_randombytes(rnd, RNDBYTES);
    memcpy(rnd, rng, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, MLDSA65_K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    PQCLEAN_MLDSA65_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_MLDSA65_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_MLDSA65_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_MLDSA65_CLEAN_pack_sig(sig, sig, &z, &h);
    *siglen = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    return 0;
}


/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx(uint8_t *sm,
        size_t *smlen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {
    int ret;
    size_t i;

    for (i = 0; i < mlen; ++i) {
        sm[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(sm, smlen, sm + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES, mlen, ctx, ctxlen, sk);
    *smlen += mlen;
    return ret;
}

int PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx_KAT(uint8_t *sm,
        size_t *smlen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk,
        uint8_t *rnd) {
    int ret;
    size_t i;

    for (i = 0; i < mlen; ++i) {
        sm[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_KAT(sm, smlen, sm + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES, mlen, ctx, ctxlen, sk, rnd);
    *smlen += mlen;
    return ret;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {
    unsigned int i;
    uint8_t buf[MLDSA65_K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl mat[MLDSA65_K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    if (ctxlen > 255 || siglen != PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) {
        return -1;
    }

    PQCLEAN_MLDSA65_CLEAN_unpack_pk(rho, &t1, pk);
    if (PQCLEAN_MLDSA65_CLEAN_unpack_sig(c, &z, &h, sig)) {
        return -1;
    }
    if (PQCLEAN_MLDSA65_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, TRBYTES, pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    PQCLEAN_MLDSA65_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_MLDSA65_CLEAN_poly_ntt(&cp);
    PQCLEAN_MLDSA65_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_MLDSA65_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_MLDSA65_CLEAN_polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, MLDSA65_K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    
    
    for (i = 0; i < CTILDEBYTES; ++i) {
        if (c[i] != c2[i]) {
            return -1;
        }
    }

    return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *ctx: pointer to context tring
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_open_ctx(uint8_t *m,
        size_t *mlen,
        const uint8_t *sm,
        size_t smlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {
    size_t i;

    if (smlen < PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) {
        goto badsig;
    }

    *mlen = smlen - PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(sm, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES, sm + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES, *mlen, ctx, ctxlen, pk)) {
        goto badsig;
    } else {
        /* All good, copy msg, return 0 */
        for (i = 0; i < *mlen; ++i) {
            m[i] = sm[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + i];
        }
        return 0;
    }

badsig:
    /* Signature verification failed */
    *mlen = 0;
    for (i = 0; i < smlen; ++i) {
        m[i] = 0;
    }

    return -1;
}





int TEST()
{
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t m[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];    // 실제         message
    uint8_t m2[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // verify에 있는 message
    uint8_t sm[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // sign에 있는  message
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ctx[CTX_LEN];

    for (i =0;i<CTX_LEN;i++)
    {
        ctx[i] = i;
    }


    randombytes_win32_randombytes(m, MLEN);
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx(sm, &smlen, m, MLEN, ctx, CTX_LEN, sk);
    ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_open_ctx(m2, &mlen, sm, smlen, ctx, CTX_LEN, pk);

    
    if (ret)
    {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }
    if (smlen != MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)
    {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }
    if (mlen != MLEN)
    {
        fprintf(stderr, "Message lengths wrong\n");
        return -1;
    }
    for (j = 0; j < MLEN; ++j)
    {
        if (m2[j] != m[j])
        {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }


    printf("CRYPTO_PUBLICKEYBYTES = %d\n", PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES = %d\n", PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);

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

void get_kat_parameter(FILE *in, uint8_t *out, uint64_t outlen)
{
    int8_t* in_buf  = (int8_t*)malloc(sizeof(int8_t) * outlen * 2 + 10);
    int8_t* out_buf = (int8_t*)malloc(sizeof(int8_t) * outlen * 2 + 10);
    int8_t key[20];

    fgets(in_buf, outlen * 2 + 10, in);
    parse_line(in_buf, key, out_buf);
    // if(strcmp(key, "count") == 0)
    //     printf("%s\n", out_buf);
    if (outlen < 3)
    {
        sscanf(out_buf, "%hhu", out);
    }
    else
    {
        hex2bin(out_buf, out, outlen * 2);
    }

    free(in_buf);
    free(out_buf);
}


int MLDSA_KAT_TEST_DET()
{
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t *m;  //[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES]; //= {0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E};    // 실제         message
    uint8_t *m2; //[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // verify에 있는 message
    uint8_t *sm;//[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // sign에 있는  message
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ctx[CTX_LEN];  //= {0x48, 0x0C, 0x65, 0x8C, 0x0C, 0xB3, 0xE0, 0x40, 0xBD, 0xE0, 0x84, 0x34, 0x5C, 0xEF, 0x0D, 0xF7};

    uint8_t count_temp;
    uint8_t xi[SEEDBYTES];
    uint8_t rng[RNDBYTES];
    uint8_t pk_temp[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_temp[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t mlen_temp = 16;
    uint8_t *msg;
    uint8_t *sm_temp;
    uint8_t smlen_temp;
    uint8_t ctx_temp[CTX_LEN];

    FILE* fp;
    fp = fopen("kat_MLDSA_65_det_pure.rsp", "r");
    while(feof(fp) == 0)
    {
        get_kat_parameter(fp, &count_temp, 1);
        get_kat_parameter(fp, xi, SEEDBYTES);
        
        char tempNULL[200];
        get_kat_parameter(fp, tempNULL, 200);
        
        get_kat_parameter(fp, pk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
        get_kat_parameter(fp, sk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
        msg = (uint8_t*)malloc(mlen_temp * (count_temp + 1));
        m = (uint8_t*)malloc(mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);
        m2 = (uint8_t*)malloc(mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);

        get_kat_parameter(fp, msg, mlen_temp * (count_temp + 1));

        char tempNULL2[200];
        get_kat_parameter(fp, tempNULL2, 200);

        sm_temp = (uint8_t*)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));
        sm = (uint8_t*)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));
        get_kat_parameter(fp, sm_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));

        char tempNULL3[200];
        get_kat_parameter(fp, tempNULL3, 200);

        get_kat_parameter(fp, ctx_temp, CTX_LEN);

        PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_KAT(pk, sk, xi);
        if(memcmp(pk, pk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0) return -1;
        if(memcmp(sk, sk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) return -1;

        memcpy(m, msg, mlen_temp * (count_temp + 1));

        PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx(sm, &smlen, m, mlen_temp * (count_temp + 1), ctx_temp, CTX_LEN, sk);
        if(memcmp(sm, sm_temp, smlen) != 0) return -1;

        // printf("sm is\n\n");
        // for(int i = 0;i<smlen;i++)
        // {
        //     printf("%02x", sm[i]);
        //     if(i == CTILDEBYTES - 1)
        //         printf("\n\n");
        //     if(i == CTILDEBYTES + MLDSA65_L*POLYZ_PACKEDBYTES -1)
        //         printf("\n\n");
        //     if(i == CTILDEBYTES + MLDSA65_L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES - 1)
        //         printf("\n\n");
        // }
        // printf("\n\n");
        // printf("sm temp is\n\n");
        // for(int i = 0;i<smlen;i++)
        // {
        //     printf("%02x", sm_temp[i]);
        //     if(i == CTILDEBYTES - 1)
        //         printf("\n\n");
        //     if(i == CTILDEBYTES + MLDSA65_L*POLYZ_PACKEDBYTES -1)
        //         printf("\n\n");
        //     if(i == CTILDEBYTES + MLDSA65_L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES - 1)
        //         printf("\n\n");
        // }
        // printf("\n\n");

        // for(int i = 0;i<smlen;i++)
        // {
        //     if(sm[i] != sm_temp[i])
        //     {
        //         printf("%d, %02X, %02X",i, sm[i], sm_temp[i]);
        //         break;
        //     }
        // }

        
        
        ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_open_ctx(m2, &mlen, sm, smlen, ctx_temp, CTX_LEN, pk);
        if(memcmp(m2, msg, mlen_temp * (count_temp + 1)) != 0) return -1;
        if (ret)
        {
            fprintf(stderr, "Verification failed\n");
            return -1;
        }
        if (smlen != mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)
        {
            fprintf(stderr, "Signed message lengths wrong\n");
            return -1;
        }
        if (mlen != mlen_temp * (count_temp + 1))
        {
            fprintf(stderr, "Message lengths wrong\n");
            return -1;
        }
        for (j = 0; j < mlen_temp * (count_temp + 1); ++j)
        {
            if (m2[j] != m[j])
            {
                fprintf(stderr, "Messages don't match\n");
                return -1;
            }
        }   

        free(msg);
        free(sm_temp);
        free(m);
        free(m2);
        //printf("%d is done\n", count_temp);
    }

    printf("KAT_TEST_DET DONE\n");
    fclose(fp);
    return 1;
}


int MLDSA_KAT_TEST_HEDGED()
{
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t *m;  //[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES]; //= {0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E};    // 실제         message
    uint8_t *m2; //[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // verify에 있는 message
    uint8_t *sm;//[MLEN + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];   // sign에 있는  message
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ctx[CTX_LEN];  //= {0x48, 0x0C, 0x65, 0x8C, 0x0C, 0xB3, 0xE0, 0x40, 0xBD, 0xE0, 0x84, 0x34, 0x5C, 0xEF, 0x0D, 0xF7};
    uint8_t rng[RNDBYTES];


    uint8_t count_temp;
    uint8_t xi[SEEDBYTES];
    uint8_t pk_temp[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_temp[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t mlen_temp = 16;
    uint8_t *msg;
    uint8_t *sm_temp;
    uint8_t smlen_temp;
    uint8_t ctx_temp[CTX_LEN];

    FILE* fp;
    fp = fopen("kat_MLDSA_65_hedged_pure.rsp", "r");
    while(feof(fp) == 0)
    {
        get_kat_parameter(fp, &count_temp, 1);
        get_kat_parameter(fp, xi, SEEDBYTES);
        get_kat_parameter(fp, rng, RNDBYTES);
        char tempNULL[100];
        get_kat_parameter(fp, tempNULL, 100);
        
        get_kat_parameter(fp, pk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
        get_kat_parameter(fp, sk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
        msg = (uint8_t*)malloc(mlen_temp * (count_temp + 1));
        m = (uint8_t*)malloc(mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);
        m2 = (uint8_t*)malloc(mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);

        get_kat_parameter(fp, msg, mlen_temp * (count_temp + 1));

        char tempNULL2[11];
        get_kat_parameter(fp, tempNULL2, 11);

        sm_temp = (uint8_t*)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));
        sm = (uint8_t*)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));
        get_kat_parameter(fp, sm_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + mlen_temp * (count_temp + 1));

        char tempNULL3[15];
        get_kat_parameter(fp, tempNULL3, 15);

        get_kat_parameter(fp, ctx_temp, CTX_LEN);

        PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_KAT(pk, sk, xi);
        if(memcmp(pk, pk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0) return -1;
        if(memcmp(sk, sk_temp, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) return -1;

        memcpy(m, msg, mlen_temp * (count_temp + 1));
        PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx_KAT(sm, &smlen, m, mlen_temp * (count_temp + 1), ctx_temp, CTX_LEN, sk, rng);
        //printf("count : %d", count_temp);

        if(memcmp(sm, sm_temp, smlen) != 0) return -1;
        
        ret = PQCLEAN_MLDSA65_CLEAN_crypto_sign_open_ctx(m2, &mlen, sm, smlen, ctx_temp, CTX_LEN, pk);
        if(memcmp(m2, msg, mlen_temp * (count_temp + 1)) != 0) return -1;
        if (ret)
        {
            fprintf(stderr, "Verification failed\n");
            return -1;
        }
        if (smlen != mlen_temp * (count_temp + 1) + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)
        {
            fprintf(stderr, "Signed message lengths wrong\n");
            return -1;
        }
        if (mlen != mlen_temp * (count_temp + 1))
        {
            fprintf(stderr, "Message lengths wrong\n");
            return -1;
        }
        for (j = 0; j < mlen_temp * (count_temp + 1); ++j)
        {
            if (m2[j] != m[j])
            { 
                fprintf(stderr, "Messages don't match\n");
                return -1;
            }
        }   

        free(msg);
        free(sm_temp);
        free(m);
        free(m2);
        printf("%d is done\n", count_temp);
    }

    printf("KAT_TEST_HEDGED DONE\n");
    fclose(fp);
    return 1;
}

int main()
{
    //TEST();
    MLDSA_KAT_TEST_DET();

    MLDSA_KAT_TEST_HEDGED();

    return 0;
}