/**
 * Implementation of the Lyra2 Password Hashing Scheme (PHS).
 *
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h>

#include "Lyra2.h"
#include "Sponge.h"

/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. The number of columns of the memory matrix is set to nCols = N_COLS.
 * This version supports salts and passwords whose combined length is smaller than the size of the memory matrix,
 * (i.e., (nRows x nCols x b) bits, where "b" is the underlying sponge's bitrate). In this implementation, the "params" 
 * is composed by all integer parameters (treated as type "unsigned int") in the order they are provided, plus the value 
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 * In case of parallel version, there are two more "params": total of threads and thread number (nPARALLEL || threadNumber).
 *
 * @param out The derived key to be output by the algorithm
 * @param outlen Desired key length
 * @param in User password
 * @param inlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param t_cost Parameter to determine the processing time (T)
 * @param m_cost Memory cost parameter (defines the number of rows of the memory matrix, R)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost) {
    return LYRA2(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, N_COLS);
}

#if (nPARALLEL == 1)
/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "params" is composed by all 
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value 
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
int LYRA2(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols) {
    //============================= Basic variables ============================//
    int64_t gap = 1;            //Modifier to the step, assuming the values 1 or -1
    uint64_t step = 1;          //Visitation step (used during Setup to dictate the sequence in which rows are read)
    uint64_t window = 2;        //Visitation window (used to define which rows can be revisited during Setup)
    uint64_t sqrt = 2;          //Square of window (i.e., square(window)), when a window is a square number;
                                //otherwise, sqrt = 2*square(window/2) 
    
    uint64_t row0 = 3;          //row0: sequentially written during Setup; randomly picked during Wandering
    uint64_t prev0 = 2;         //prev0: stores the previous value of row0
    uint64_t row1 = 1;          //row1: revisited during Setup, and then read [and written]; randomly picked during Wandering
    uint64_t prev1 = 0;         //prev1: stores the previous value of row1

    uint64_t i;                 //auxiliary iteration counter
    //==========================================================================/
    
    //========== Initializing the Memory Matrix and pointers to it =============//
    //Tries to allocate enough space for the whole memory matrix
    i = (uint64_t) ((uint64_t) nRows * (uint64_t) ROW_LEN_BYTES);
    uint64_t *wholeMatrix = (uint64_t *)malloc(i);
    if (wholeMatrix == NULL) {
	return -1;
    }
    //Allocates pointers to each row of the matrix
    uint64_t **memMatrix = (uint64_t **)malloc(nRows * sizeof (uint64_t*));
    if (memMatrix == NULL) {
	return -1;
    }
    //Places the pointers in the correct positions
    uint64_t *ptrWord = wholeMatrix;
    for (i = 0; i < nRows; i++) {
	memMatrix[i] = ptrWord;
	ptrWord += ROW_LEN_INT64;
    }
    
    //==========================================================================/
    
    //============= Padding (password + salt + params) with 10*1 ===============//

    //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
    //but this ensures that the password copied locally will be overwritten as soon as possible

    //First, we clean enough blocks for the password, salt, params and padding
    //Change the ''6'' if different amounts of parameters were passed 
    uint64_t nBlocksInput = ((saltlen + pwdlen + 6 * sizeof (int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;
    byte *ptrByte = (byte*) wholeMatrix;
    memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES);

    //Prepends the password
    memcpy(ptrByte, pwd, pwdlen);
    ptrByte += pwdlen;

    //Concatenates the salt
    memcpy(ptrByte, salt, saltlen);
    ptrByte += saltlen;

    //Concatenates the params: every integer passed as parameter, in the order they are provided by the interface
    memcpy(ptrByte, &kLen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &pwdlen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &saltlen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &timeCost, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &nRows, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &nCols, sizeof (int));
    ptrByte += sizeof (int);

    //Now comes the padding
    *ptrByte = 0x80;                                            //first byte of padding: right after the password
    ptrByte = (byte*) wholeMatrix;                              //resets the pointer to the start of the memory matrix
    ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1;  //sets the pointer to the correct position: end of incomplete block
    *ptrByte ^= 0x01;                                           //last byte of padding: at the end of the last incomplete block
    
    //==========================================================================/

    //======================= Initializing the Sponge State ====================//
    //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
    uint64_t *state = (uint64_t *)malloc(16 * sizeof (uint64_t));
    if (state == NULL) {
	return -1;
    }
    initState(state);
    
    //==========================================================================/
    
    //============= Absorbing the input data with the sponge ===============//
    
    //Absorbing salt, password and params: this is the only place in which the block length is hard-coded to 512 bits, for compatibility with Blake2b and BlaMka
    ptrWord = wholeMatrix;
    for (i = 0; i < nBlocksInput; i++) {
	absorbBlockBlake2Safe(state, ptrWord);          //absorbs each block of pad(pwd || salt || params)
	ptrWord += BLOCK_LEN_BLAKE2_SAFE_INT64;         //goes to next block of pad(pwd || salt || params)
    }
    
    //================================================================================/
    
    //================================ Setup Phase ==================================//
    //==Initializes a (nRows x nCols) memory matrix, it's cells having b bits each)==//

    //Initializes M[0]
    reducedSqueezeRow0(state, memMatrix[0]);    //The locally copied password is most likely overwritten here
    //Initializes M[1]
    reducedDuplexRow1and2(state, memMatrix[0], memMatrix[1]);
    //Initializes M[2]
    reducedDuplexRow1and2(state, memMatrix[1], memMatrix[2]);
    
    //Filling Loop
    for(row0 = 3 ; row0 < nRows; row0++){
        //Performs a reduced-round duplexing operation over "M[row1][col] [+] M[prev0][col] [+] M[prev1][col]", filling M[row0] and updating M[row1]
	//M[row0][N_COLS-1-col] = M[prev0][col] XOR rand;
        //M[row1][col] = M[row1][col] XOR rot(rand)                    rot(): right rotation by 'omega' bits (e.g., 1 or more words)
	reducedDuplexRowFilling(state, memMatrix[row1], memMatrix[prev0], memMatrix[prev1], memMatrix[row0]);

        //Updates the "prev" indices: the rows more recently updated
        prev0 = row0;
        prev1 = row1;
        
        //updates the value of row1: deterministically picked, with a variable step
        row1 = (row1 + step) & (window - 1);
	
	//Checks if all rows in the window where visited.
	if (row1 == 0) {
	    window *= 2;                        //doubles the size of the re-visitation window
	    step = sqrt + gap;                  //changes the step: approximately doubles its value
	    gap = -gap;                         //inverts the modifier to the step 
            if (gap == -1){
                sqrt *= 2;                      //Doubles sqrt every other iteration
            }
	}
    }
    
    //============================ Wandering Phase =============================//
    //=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
    
    //Visitation Loop
    for (i = 0 ; i < timeCost*nRows ; i++) {            
        //Selects a pseudorandom indices row0 and row1
        //------------------------------------------------------------------------------------------
        /*(USE THIS IF nRows IS A POWER OF 2)*/
        //row0 = ((uint64_t)state[0]) & (nRows-1);	
        //row1 = ((uint64_t)state[2]) & (nRows-1);
        /*(USE THIS FOR THE "GENERIC" CASE)*/
        row0 = ((uint64_t)state[0]) % nRows;            //row0 = lsw(rand) mod nRows
        row1 = ((uint64_t)state[2]) % nRows;            //row1 = lsw(rot(rand)) mod nRows 
                                                        //we rotate 2 words for compatibility with the SSE implementation

        //Performs a reduced-round duplexing operation over "M[row0][col] [+] M[row1][col] [+] M[prev0][col0] [+] M[prev1][col1], updating both M[row0] and M[row1]
        //M[row0][col] = M[row0][col] XOR rand; 
        //M[row1][col] = M[row1][col] XOR rot(rand)                     rot(): right rotation by 'omega' bits (e.g., 1 or more words)
        reducedDuplexRowWandering(state, memMatrix[row0], memMatrix[row1], memMatrix[prev0], memMatrix[prev1]);

        //update prev's: they now point to the last rows ever updated
        prev0 = row0;
        prev1 = row1;   
    }
    
    //==========================================================================/

    //============================ Wrap-up Phase ===============================//
    //========================= Output computation =============================//
    //Absorbs one last block of the memory matrix with the full-round sponge
    absorbColumn(state, memMatrix[row0]);
    
    //Squeezes the key with the full-round sponge
    squeeze(state, (unsigned char *)K, kLen);
    
    //==========================================================================/

    //========================= Freeing the memory =============================//
    free(memMatrix);
    free(wholeMatrix);

    //Wiping out the sponge's internal state before freeing it
    memset(state, 0, 16 * sizeof (uint64_t));
    free(state);
    //==========================================================================/

    return 0;
}
#endif
