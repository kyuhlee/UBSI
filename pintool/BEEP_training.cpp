/*BEGIN_LEGAL 
		Intel Open Source License 

		Copyright (c) 2002-2011 Intel Corporation. All rights reserved.

		Redistribution and use in source and binary forms, with or without
		modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/* ===================================================================== */
/*
			@ORIGINAL_AUTHOR: Robert Muth
			*/

/* ===================================================================== */
/*! @file
	*  This file contains an ISA-portable PIN tool for tracing instructions
	*/

#include "pin.H"
//#include "intervalTree/interval.H"
#include <iostream>
#include <sys/syscall.h>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#define hash_map map

//#define TRACE_MEM
#define ONLY_MAIN_IMAGE

#define NDEBUG

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif


#define trace(M, _a...) do { \
		PIN_GetLock(&lock, 0); \
		fprintf(outfile, M, ## _a); \
		fflush(outfile); \
		PIN_ReleaseLock(&lock); \
} while (0)

#define LE 1
#define LX 2
/*#define trace(M, _a...) do { \
		if(thread_outfile == NULL) printf("%s.%d is not exist!!!!\n", filename_prefix, PIN_ThreadId()); \
		fprintf(thread_outfile, M, ## _a); \
		fflush(thread_outfile); \
} while (0)
*/

#define MAX_THREAD 1024
#define MAX_CALLSTACK 1536*6
#define MAX_BBLPATH 5120*2

#define START_FNC "main"
#define MALLOC "malloc"
#define CALLOC "calloc"
#define REALLOC "realloc"
#define FREE "free"
#define MEMCPY "memcpy"
#define MEMCPY2 "__memcpy_ssse3_back"
#define MEMCCPY "memccpy"
#define MEMMOVE "memmove"
#define STRCPY "strcpy"
#define STRNCPY "strncpy"

//#define MIN_MEM_ACCESS sizeof(int)
#define MIN_MEM_ACCESS 4096

#define TD 1 //TRACE_DESC
#define TF 2 //TRACE_FILE
#define TI 4 //TRACE_IPC
#define TN 8 //TRACE_NETWORK
#define TP 16 //TRACE_PROCESS
#define TS 32//TRACE_SIGNAL
#define TM 64 //TRACE_MEMORY
#define NF 128 //SYSCALL_NEVER_FAILS
#define LG 256 // BEEP Logging
#define P1 512 // Path is stored in arg1
#define P2 1024 // Path is stored in arg2
#define MA 8 //MAX_ARGS

ADDRINT TARGET_memcpy, TARGET_memcpy2, TARGET_strcpy, TARGET_strncpy, TARGET_memmove;
PIN_LOCK lock;
//ITNode *ITRoot = NULL;
UINT64 malloc_id = 1;
//pthread_mutexattr_t attr;

VOID MemcpyBefore(THREADID tid, ADDRINT a1, ADDRINT a2, ADDRINT a3);
VOID MemcpyAfter(THREADID tid, ADDRINT ip, ADDRINT ret);
struct Bbl {
		ADDRINT start;
		ADDRINT end;
		ADDRINT tail;
		UINT64 timestamp; // in number of instrutions per thread
};
typedef vector<Bbl> BblPath;

struct CallStackFrame {
		ADDRINT sp;
		BblPath path;
		UINT32 pathLen;
};

struct Thread {
		CallStackFrame callStack[MAX_CALLSTACK]; // call stack
		UINT32 callStackDepth; // call stack depth
		UINT64 instrCount; // number of instructions executed by this thread
};

Thread threadTable[MAX_THREAD];

typedef hash_map<ADDRINT, UINT32> LoopIdTable;

LoopIdTable loopIdTable;

typedef struct loop {
		ADDRINT entry;
		ADDRINT exit;
		ADDRINT imgBase;
		int depth;
		int loopId;
} struct_loop;

typedef struct sysent {
		unsigned nargs;
		int	sys_flags;
		int	sys_num;
		const char *sys_name;
} struct_sysent;

const struct_sysent sysent[] = {
#include "syscallent.h"
};

typedef struct {
		int type; // 1. Malloc, 2. Free, 3. Realloc
		int id;  
		ADDRINT addr;
		ADDRINT size;
		ADDRINT addrSrc;
} malloc_log;

std::vector<malloc_log> mallocLog;

ADDRINT MIN_HEAP_ADDRESS = 0; // The smallest memory address that has dynamically allocated. If an instruction access any memory smaller than this, ignore it.
ADDRINT MAX_HEAP_ADDRESS = 0;

/*  */
/* Global Variables */
/* ===================================================================== */

char *outFileName;
FILE *outfile, *outfile2, *outfile3;

//__thread FILE *thread_outfile;
//char filename_prefix[256];
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

ADDRINT syscall_t[MAX_THREAD][7];
ADDRINT malloc_t[MAX_THREAD];
ADDRINT realloc_t[MAX_THREAD][2];
ADDRINT calloc_t[MAX_THREAD];
ADDRINT memcpy_t[MAX_THREAD][4];
int memId = 1;

bool startPrint = false;
//bool startPrint = true;

INT32 Usage()
{
		cerr << "This tool produces a BEEP trace." << endl << endl;
		cerr << KNOB_BASE::StringKnobSummary() << endl;
		return -1;
}

struct lastTrace {
		bool valid;
		unsigned long timestamp;
		int tid;
		long ip;
		int loopId;
};

lastTrace lastLE;

void dump_last_le()
{
		if(lastLE.valid) {
				PIN_GetLock(&lock, 0); 
				fprintf(outfile,"%lu: [%d] LE ip %lx id %d\n", lastLE.timestamp, lastLE.tid, lastLE.ip, lastLE.loopId);
				fflush(outfile); 
				PIN_ReleaseLock(&lock); 
		}
		lastLE.valid = false;
}

void loop_trace(int type, unsigned long timestamp, int tid, long ip, int loopId)
{	
		if(type == LE) {
				dump_last_le();
				lastLE.timestamp = timestamp;
				lastLE.tid = tid;
				lastLE.ip = ip;
				lastLE.loopId = loopId;
				lastLE.valid = true;
		}
				
		if(type == LX) {
				if(lastLE.valid && lastLE.tid == tid && lastLE.loopId == loopId) {
								lastLE.valid = false;
								return;
				}
				trace("%lu: [%d] LX ip %lx id %d\n", timestamp, tid, ip, loopId);
		}
}

string invalid = "invalid_rtn";

/* ===================================================================== */
const string *Target2String(ADDRINT target)
{
		string name = RTN_FindNameByAddress(target);
		name = PIN_UndecorateSymbolName(name,UNDECORATION_NAME_ONLY );
		if (name == "")
				return &invalid;
		else
				return new string(name);
}

bool IsAddressInMainExecutable(ADDRINT addr)
{
		PIN_LockClient();
		RTN rtn = RTN_FindByAddress(addr);
		PIN_UnlockClient();
		if (rtn == RTN_Invalid())
				return false;

		SEC sec = RTN_Sec(rtn);
		if (sec == SEC_Invalid())
				return false;

		IMG img = SEC_Img(sec);
		if (img == IMG_Invalid())
				return false;
		if(IMG_IsMainExecutable(img)) return true;
		
		if(IMG_Name(img).find("libxul") != string::npos) return true; // for firefox
		return false;
}

ADDRINT getLastIpInExecutable(Thread *thread)
{
		for(int i = thread->callStackDepth-1; i >= 0; i--)
		{
				CallStackFrame *frame = &thread->callStack[i];
				ADDRINT addr = frame->path[frame->pathLen-1].end;
				//printf("bbl = %lx\n", frame->path[frame->pathLen-1].end);
				if(IsAddressInMainExecutable(addr)) return addr;
		}
		return 0;
}
/* ===================================================================== */

/* Pops stack frames of a call stack so that the top of the stack is in line
	* with the current stack pointer. */
void AdjustCallStack(Thread *thread, ADDRINT sp)
{
		while (thread->callStackDepth > 1) {
				CallStackFrame *frame = &thread->callStack[thread->callStackDepth-1];
				if (frame->sp > sp) {
						break;
				}
				thread->callStackDepth--;
		}
}

/* Search for a basic block in the path in reverse order. */
UINT32 FindBblReverse(CallStackFrame *frame, ADDRINT end)
{
		for (UINT32 i = 0; i < frame->pathLen; i++) {
				UINT32 pos = frame->pathLen - i - 1;
				Bbl *bbl = &frame->path[pos];
				if (bbl->end == end) {
						return pos;
				}
		}
		return (UINT32)-1;
}

/* Returns a basic block after allocating and inserting it to the call stack
	* frame at a specified position. */
Bbl *InsertBbl(CallStackFrame *frame, ADDRINT pos)
{	
		for (UINT32 i = frame->pathLen; i > pos; i--) {
				frame->path[i] = frame->path[i-1];
		}
		frame->pathLen++;
		return &frame->path[pos];
}

/* ===================================================================== */

VOID memWrite(THREADID tid, ADDRINT target, UINT32 size, ADDRINT ip)
{
		if(!startPrint) return;
		if(size < MIN_MEM_ACCESS) return;
		if(target > MAX_HEAP_ADDRESS) return;
		if(target < MIN_HEAP_ADDRESS) return;

		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		UINT64 timestamp = threadTable[tid].instrCount;

		trace("%lu: [%d] WR ip %lx id 0 addr %lx size %d write\n", timestamp, tid, ip, target, size);

		/*Interval t = {target, target+size, 0, true};
				Interval *res = IT_overlapSearch(ITRoot, t);

				if(res != NULL) {
				trace( "%lu: [%d] WR ip %lx id %ld addr %lx size %d \n", timestamp, tid, ip, res->id, target, size);
				}
				*/
}

VOID memRead(THREADID tid, ADDRINT target, UINT32 size, ADDRINT ip)
{
		if(!startPrint) return;
		if(size < MIN_MEM_ACCESS) return;
		if(target > MAX_HEAP_ADDRESS) return;
		if(target < MIN_HEAP_ADDRESS) return;

		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		UINT64 timestamp = threadTable[tid].instrCount;

		trace("%lu: [%d] RD ip %lx id 0 addr %lx size %d read\n", timestamp, tid, ip, target, size);
		/*
					Interval t = {target, target+size, 0, true};
					Interval *res = IT_overlapSearch(ITRoot, t);

					if(res != NULL) {
					trace("%lu: [%d] RD ip %lx, id %ld, addr %lx, size %d \n", timestamp, tid, ip, res->id, target, size);
					}
					*/
}

VOID loopEntry(THREADID tid, UINT32 loopId, ADDRINT ip, UINT64 timestamp)
{
		if(startPrint == false) return;
		trace("%lu: [%d] LE ip %lx id %d\n", timestamp, tid, ip, loopId);
		//loop_trace(LE, timestamp, tid, ip, loopId);
		//trace("[%d] LE id %d\n", tid, loopId);
}

VOID loopExit(THREADID tid, UINT32 loopId, ADDRINT ip, UINT64 timestamp)
{
		if(startPrint == false) return;
		trace("%lu: [%d] LX ip %lx id %d\n", timestamp, tid, ip, loopId);
		//loop_trace(LX, timestamp, tid, ip, loopId);
		//trace("[%d] LX id %d\n",tid, loopId);
}

/* ===================================================================== */

/* Called before a direct or indirect function call. */
void CallBefore(THREADID tid, ADDRINT sp)
{
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		Thread *thread = &threadTable[tid];

		AdjustCallStack(thread, sp);

		ASSERT(thread->callStackDepth < MAX_CALLSTACK, "Increase MAX_CALLSTACK");
		CallStackFrame *frame = &thread->callStack[thread->callStackDepth++];
		frame->sp = sp;
		frame->pathLen = 0;
}

/* Called before a direct function call. */
void DirectCallBefore(THREADID tid, ADDRINT sp)
{
		CallBefore(tid, sp);
}

/* Called before an indirect function call. */
void IndirCallBefore(THREADID tid, ADDRINT to, BOOL taken,
				ADDRINT sp)
{
		if (!taken) return;
		CallBefore(tid, sp);
}

/* Called before the execution of a basic block. */
void BblBefore(THREADID tid, ADDRINT start, ADDRINT end, ADDRINT tail,
				ADDRINT sp, UINT32 instrCount)
{
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		Thread *thread = &threadTable[tid];

		AdjustCallStack(thread, sp);

		CallStackFrame *frame = &thread->callStack[thread->callStackDepth-1];

		UINT32 pos = FindBblReverse(frame, end);

		// Does the frame contain this basic block yet?
		if (pos == (UINT32)-1) {
				// No, then just add the basic block to the path in the frame.
				Bbl *bbl = &frame->path[frame->pathLen++];
				bbl->start = start;
				bbl->end = end;
				bbl->tail = tail;
				bbl->timestamp = thread->instrCount;

				thread->instrCount += instrCount;
				return;
		}

		/* OK, this basic block is a loop entry. */
		Bbl *entry = &frame->path[pos];

		UINT64 entryTime = entry->timestamp;

		// Split the basic block if start address is different
		if (entry->start < start) {
				++pos;

				Bbl *bbl = InsertBbl(frame, pos);
				bbl->start = start;
				bbl->end = end;
				bbl->tail = tail;
				bbl->timestamp = thread->instrCount;

				entry->end = start;
				// XXX: we don't know the tail address at this point
				entry->tail = entry->end-4; // assume tail is 4 bytes for now

				entry = bbl;
		} else if (start < entry->start) {
				entry->start = start;
		}

		Bbl *back = &frame->path[frame->pathLen-1];

		if (entry->end != back->end) {
				UINT64 backTime = back->timestamp;

#ifdef ONLY_MAIN_IMAGE
				if (IsAddressInMainExecutable(entry->start))
#endif
				{
						UINT32 loopId = 0;
						string filename;
						INT32 line;
						//PIN_GetLock(&lock, 0);
						LoopIdTable::iterator x = loopIdTable.find(entry->end);
						if (x == loopIdTable.end()) {
								loopIdTable[entry->end] = loopId = loopIdTable.size();
								PIN_LockClient();
								PIN_GetSourceLocation(entry->start, NULL, &line, &filename);
								PIN_UnlockClient();
								fprintf(outfile2, "LoopId %d, addr %lx, file %s, line %d\n", loopId, entry->start, filename.c_str(), line);
								fflush(outfile2);
						} else {
								loopId = loopIdTable[entry->end];
						}
					//PIN_ReleaseLock(&lock);

						loopEntry(tid, loopId, entry->start, entryTime);
						loopExit(tid, loopId, back->tail, backTime);
				}
		}

		// Remove the path in the frame executed in previous iteration of the
		// loop, except the loop entry.
		frame->pathLen = pos+1;

		entry->timestamp = thread->instrCount;

		thread->instrCount += instrCount;
}

/* Called before a trace. */
void Trace(TRACE trace, void *v)
{
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
				INS tail = BBL_InsTail(bbl);

				if (INS_IsSyscall(tail)) {}
				else if (INS_IsSysret(tail)) {}
				else if (INS_IsRet(tail)) {}
				else if (INS_IsCall(tail))
				{
						if (INS_IsDirectBranchOrCall(tail))
						{
								INS_InsertPredicatedCall(tail, IPOINT_BEFORE,
												(AFUNPTR)DirectCallBefore, IARG_THREAD_ID,
												IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
						}
						else
						{
								INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)IndirCallBefore,
												IARG_THREAD_ID, IARG_BRANCH_TARGET_ADDR,
												IARG_BRANCH_TAKEN, IARG_REG_VALUE, REG_STACK_PTR,
												IARG_END);
						}
				}
				else
				{
						// Sometimes code is not in an image.
						RTN rtn = TRACE_Rtn(trace);
						// Also track jumps into shared libraries.
						if (RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) &&
										".plt" == SEC_Name(RTN_Sec(rtn)))
						{
								INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)IndirCallBefore,
												IARG_THREAD_ID, IARG_BRANCH_TARGET_ADDR,
												IARG_BRANCH_TAKEN, IARG_REG_VALUE, REG_STACK_PTR,
												IARG_END);
						}
				}

				BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BblBefore,
								IARG_THREAD_ID, IARG_ADDRINT, BBL_Address(bbl),
								IARG_ADDRINT, BBL_Address(bbl)+BBL_Size(bbl), IARG_ADDRINT,
								INS_Address(tail), IARG_REG_VALUE, REG_STACK_PTR, 
								IARG_UINT32, BBL_NumIns(bbl), IARG_END);
		}
}

VOID Instruction(INS ins, VOID *v)
{
		//return;
#ifdef TRACE_MEM
#ifdef ONLY_MAIN_IMAGE
  if (!IsAddressInMainExecutable(INS_Address(ins))) return;
#endif

		if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)) return;
		if(INS_IsMemoryRead(ins) && INS_MemoryReadSize(ins) >= MIN_MEM_ACCESS) {
				INS_InsertCall(
								ins, IPOINT_BEFORE, (AFUNPTR) memRead,
								IARG_THREAD_ID,
								IARG_MEMORYREAD_EA,
								IARG_MEMORYREAD_SIZE,
								IARG_INST_PTR,
								IARG_END);
		}

		if(INS_HasMemoryRead2(ins)) {
				INS_InsertCall(
								ins, IPOINT_BEFORE, (AFUNPTR) memRead,
								IARG_THREAD_ID,
								IARG_MEMORYREAD2_EA,
								IARG_MEMORYREAD_SIZE,
								IARG_INST_PTR,
								IARG_END);
		}


		if(INS_IsMemoryWrite(ins) && INS_MemoryWriteSize(ins) >= MIN_MEM_ACCESS) {
				INS_InsertCall(
								ins, IPOINT_BEFORE, (AFUNPTR) memWrite,
								IARG_THREAD_ID,
								IARG_MEMORYWRITE_EA,
								IARG_MEMORYWRITE_SIZE,
								IARG_INST_PTR,
								IARG_END);
		}
#endif
		return;

}

VOID MallocBefore(THREADID tid, ADDRINT size)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		malloc_t[tid] = size;
}

VOID MallocAfter(THREADID tid, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret == 0) return;

		UINT64 timestamp = threadTable[tid].instrCount;

		trace("%lu: [%d] MA ip 0 id %d addr %lx size %ld \n", timestamp, tid, memId++, ret, malloc_t[tid]);

		//malloc_log l = {1, memId, ret, malloc_t[tid], 0};
		//PIN_GetLock(&lock, 0);
		//mallocLog.push_back(l);
		//PIN_ReleaseLock(&lock);
		//Interval i = {ret, ret+malloc_t[tid], memId++, true};
		//ITRoot = IT_insert(ITRoot, i);
		if(MIN_HEAP_ADDRESS == 0 || MIN_HEAP_ADDRESS > ret) MIN_HEAP_ADDRESS = ret;
		if(MAX_HEAP_ADDRESS < (ret+malloc_t[tid])) MAX_HEAP_ADDRESS = ret + malloc_t[tid];
}

VOID FreeBefore(THREADID tid, ADDRINT ptr)
{
		if(!startPrint) return;
		if(ptr == 0) return;

		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		UINT64 timestamp = threadTable[tid].instrCount;

		//malloc_log l = {2, 0, ptr, 0, 0};
		//PIN_GetLock(&lock, 0);
		//mallocLog.push_back(l);
		//PIN_ReleaseLock(&lock);
		trace("%lu: [%d] FR ip 0 id 0 addr %lx size 0\n", timestamp, tid, ptr);
		//IT_erase(ITRoot, ptr);
}

VOID CallocBefore(THREADID tid, ADDRINT a1, ADDRINT a2)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		calloc_t[tid] = a1*a2;
}

VOID CallocAfter(THREADID tid, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret == 0) return;

		UINT64 timestamp = threadTable[tid].instrCount;

		//malloc_log l = {1, memId, ret, calloc_t[tid], 0};
		//PIN_GetLock(&lock, 0);
		//mallocLog.push_back(l);
		//PIN_ReleaseLock(&lock);
		trace("%lu: [%d] MA ip 0 id %d addr %lx size %ld \n", timestamp, tid, memId++, ret, calloc_t[tid]);
		//Interval i = {ret, ret+calloc_t[tid], memId++, true};
		//ITRoot = IT_insert(ITRoot, i);
		//
		if(MIN_HEAP_ADDRESS == 0 || MIN_HEAP_ADDRESS > ret) MIN_HEAP_ADDRESS = ret;
		if(MAX_HEAP_ADDRESS < (ret+calloc_t[tid])) MAX_HEAP_ADDRESS = ret + calloc_t[tid];
}

VOID ReallocBefore(THREADID tid, ADDRINT a1, ADDRINT a2)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		realloc_t[tid][0] = a1;
		realloc_t[tid][1] = a2;
}

VOID ReallocAfter(THREADID tid, ADDRINT ret)
{
		if(!startPrint) return;
		if(realloc_t[tid][0] == 0 && realloc_t[tid][0] == 0) return;
		if(ret == 0) return;

		UINT64 timestamp = threadTable[tid].instrCount;

		//malloc_log l = {3, memId, ret, realloc_t[tid][1], realloc_t[tid][0]};
		//PIN_GetLock(&lock, 0);
		//mallocLog.push_back(l);
		//PIN_ReleaseLock(&lock);
		trace("%lu: [%d] RA ip 0 id %d addr %lx size %ld addr_src %lx \n", timestamp, tid, memId++, ret, realloc_t[tid][1], realloc_t[tid][0]);
		//IT_erase(ITRoot, realloc_t[tid][0]);
		//Interval i = {ret, ret+realloc_t[tid][1], memId++, true};
		//ITRoot = IT_insert(ITRoot, i);
		if(MIN_HEAP_ADDRESS == 0 || MIN_HEAP_ADDRESS > ret) MIN_HEAP_ADDRESS = ret;
		if(MAX_HEAP_ADDRESS < (ret+realloc_t[tid][1])) MAX_HEAP_ADDRESS = (ret+realloc_t[tid][1]);
}

VOID MemcpyPrint(THREADID tid, ADDRINT ip, ADDRINT dest, ADDRINT src, UINT32 size, const char *name)
{
		if(!startPrint) return;
		if(size < MIN_MEM_ACCESS) return;
		if(dest > MAX_HEAP_ADDRESS) return;
		if(dest < MIN_HEAP_ADDRESS) return;
		if(!IsAddressInMainExecutable(ip)) ip = getLastIpInExecutable(&threadTable[tid]);
		if(ip == 0) return;

		UINT64 timestamp = threadTable[tid].instrCount;

		trace("%lu: [%d] RD ip %lx id 0 addr %lx size %d %s\n", timestamp, tid, ip, src, size, name);
		trace("%lu: [%d] WR ip %lx id 0 addr %lx size %d %s\n", timestamp, tid, ip, dest, size, name);

		/*
					Interval t = {src, src + size, 0, true};
					Interval *res = IT_overlapSearch(ITRoot, t);

					if(res != NULL) 
					trace("%lu: [%d] RD ip %lx, id %ld, %s dest %lx, sec %lx, size %ld \n", timestamp, tid, ip, res->id, name,  dest, src, size);

					Interval t1 = {dest, dest + size, 0, true};
					res = IT_overlapSearch(ITRoot, t1);

					if(res != NULL) 
					trace("%lu: [%d] WR ip %lx, id %ld, %s dest %lx, sec %lx, size %d \n", timestamp, tid, ip, res->id, name, dest, src, size);
					*/
}

VOID MemcpyBefore(THREADID tid, ADDRINT a1, ADDRINT a2, ADDRINT a3)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		memcpy_t[tid][0] = a1;
		memcpy_t[tid][1] = a2;
		memcpy_t[tid][2] = a3;
}

VOID MemcpyAfter(THREADID tid, ADDRINT ip, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret > 0) MemcpyPrint(tid, ip, memcpy_t[tid][0], memcpy_t[tid][1], memcpy_t[tid][2], "memcpy");
}

VOID MemmoveAfter(THREADID tid, ADDRINT ip, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret > 0) MemcpyPrint(tid, ip, memcpy_t[tid][0], memcpy_t[tid][1], memcpy_t[tid][2], "memmove");
}

VOID StrcpyBefore(THREADID tid, ADDRINT a1, ADDRINT a2)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		memcpy_t[tid][0] = a1;
		memcpy_t[tid][1] = a2;
		memcpy_t[tid][2] = strlen((char*)a1);
}

VOID StrcpyAfter(THREADID tid, ADDRINT ip, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret > 0) MemcpyPrint(tid, ip, memcpy_t[tid][0], memcpy_t[tid][1], MIN_MEM_ACCESS, "strcpy");
}

VOID StrncpyBefore(THREADID tid, ADDRINT a1, ADDRINT a2, ADDRINT a3)
{
		if(!startPrint) return;
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		memcpy_t[tid][0] = a1;
		memcpy_t[tid][1] = a2;
		memcpy_t[tid][2] = a3;
}

VOID StrncpyAfter(THREADID tid, ADDRINT ip, ADDRINT ret)
{
		if(!startPrint) return;
		if(ret > 0) MemcpyPrint(tid, ip, memcpy_t[tid][0], memcpy_t[tid][1], memcpy_t[tid][2], "strncpy");
}

VOID MainBefore()
{
		startPrint = true;
		printf("PIN!! START LOGGING!!\n");
}

/* ===================================================================== */
VOID Image(IMG img, VOID *v)
{
		//string filename;
		//INT32 line;

		//ADDRINT img_addr = IMG_LowAddress(img);
		//string img_name = IMG_Name(img);
		fprintf(outfile3, "Image : %s, entry %lx, lowAddr: %lx, highAddr: %lx\n", IMG_Name(img).c_str(), IMG_Entry(img), IMG_LowAddress(img), IMG_HighAddress(img));
		RTN mainRtn = RTN_FindByName(img, START_FNC);
		if(RTN_Valid(mainRtn))
		{
				RTN_Open(mainRtn);
				RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)MainBefore, IARG_END);
				RTN_Close(mainRtn);
		}
#ifdef TRACE_MEM
		RTN mallocRtn = RTN_FindByName(img, MALLOC);
		if (RTN_Valid(mallocRtn))
		{
				printf("MALLOC found\n");
				RTN_Open(mallocRtn);
				RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_END);
				RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_THREAD_ID, 
								IARG_G_RESULT0, IARG_END);
				RTN_Close(mallocRtn);
		}

		RTN callocRtn = RTN_FindByName(img, CALLOC);
		if (RTN_Valid(callocRtn))
		{
				RTN_Open(callocRtn);
				RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_END);
				RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)CallocAfter, IARG_THREAD_ID, 
								IARG_G_RESULT0, IARG_END);
				RTN_Close(callocRtn);
		}

		RTN reallocRtn = RTN_FindByName(img, REALLOC);
		if (RTN_Valid(reallocRtn))
		{
				RTN_Open(reallocRtn);
				RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_END);
				RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)ReallocAfter, IARG_THREAD_ID, 
								IARG_G_RESULT0, IARG_END);
				RTN_Close(reallocRtn);
		}

		RTN freeRtn = RTN_FindByName(img, FREE);
		if (RTN_Valid(freeRtn))
		{
				RTN_Open(freeRtn);
				RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_THREAD_ID, 
								IARG_G_ARG0_CALLEE, IARG_END);
				RTN_Close(freeRtn);
		}
/*
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
				for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
				{
						if(strstr(RTN_Name(rtn).c_str(), STRNCPY))
						{
								if (RTN_Valid(rtn))
								{
										RTN_Open(rtn);
										RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)StrncpyBefore,
														IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_END);
										RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)StrcpyAfter, IARG_THREAD_ID, IARG_INST_PTR,
														IARG_G_RESULT0, IARG_END);
										PIN_LockClient();
										PIN_GetSourceLocation(RTN_Address(rtn), NULL, &line, &filename);
										PIN_UnlockClient();
										fprintf(outfile3, "STRNCPY addr %lx, file %s, line %d\n", RTN_Address(rtn), filename.c_str(), line);
										fflush(outfile3);

										RTN_Close(rtn);
								}
						} else if(strstr(RTN_Name(rtn).c_str(), STRCPY)) {
								if (RTN_Valid(rtn))
								{
										RTN_Open(rtn);
										RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)StrcpyBefore,
														IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_END);
										RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)StrcpyAfter, IARG_THREAD_ID, IARG_INST_PTR,
														IARG_G_RESULT0, IARG_END);

										PIN_LockClient();
										PIN_GetSourceLocation(RTN_Address(rtn), NULL, &line, &filename);
										PIN_UnlockClient();
										fprintf(outfile3, "STRCPY addr %lx, file %s, line %d\n", RTN_Address(rtn), filename.c_str(), line);
										fflush(outfile3);

										RTN_Close(rtn);
								}
						} else	if(strstr(RTN_Name(rtn).c_str(), MEMCPY)) {
								if (RTN_Valid(rtn))
								{
										RTN_Open(rtn);

										RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
														IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_G_ARG2_CALLEE, IARG_END);
										RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MemcpyAfter, IARG_THREAD_ID, IARG_INST_PTR,
														IARG_G_RESULT0, 
														IARG_PTR, img_name.c_str(), IARG_ADDRINT, img_addr,
														IARG_END);
							
										PIN_LockClient();
										PIN_GetSourceLocation(RTN_Address(rtn), NULL, &line, &filename);
										PIN_UnlockClient();
										fprintf(outfile3, "MEMCPY addr %lx, file %s, line %d\n", RTN_Address(rtn), filename.c_str(), line);
										printf("%s found addr %lx, file %s, line %d\n",RTN_Name(rtn).c_str(), RTN_Address(rtn), filename.c_str(), line);
										fflush(outfile3);
										RTN_Close(rtn);
								}
						} 

				}
		}
*/

		RTN memcpyRtn = RTN_FindByName(img, MEMCPY);
		if (RTN_Valid(memcpyRtn))
		{
				printf("MEMCPY found\n");
				RTN_Open(memcpyRtn);
				TARGET_memcpy = RTN_Address(memcpyRtn);
				printf("memcpy addr %lx\n", TARGET_memcpy);
				RTN_InsertCall(memcpyRtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_G_ARG2_CALLEE, IARG_END);
				RTN_InsertCall(memcpyRtn, IPOINT_AFTER, (AFUNPTR)MemcpyAfter, IARG_THREAD_ID, IARG_INST_PTR,
								IARG_G_RESULT0, IARG_END);
				RTN_Close(memcpyRtn);
		}

		RTN memcpy2Rtn = RTN_FindByName(img, MEMCPY2);
		if (RTN_Valid(memcpy2Rtn))
		{
				printf("MEMCPY2 found\n");
				RTN_Open(memcpy2Rtn);
				TARGET_memcpy2 = RTN_Address(memcpy2Rtn);
				printf("memcpy2 addr %lx\n", TARGET_memcpy2);
				RTN_InsertCall(memcpy2Rtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_G_ARG2_CALLEE, IARG_END);
				RTN_InsertCall(memcpy2Rtn, IPOINT_AFTER, (AFUNPTR)MemcpyAfter, IARG_THREAD_ID, IARG_INST_PTR,
								IARG_G_RESULT0, IARG_END);
				
				RTN_Close(memcpy2Rtn);
		}

		RTN memmoveRtn = RTN_FindByName(img, MEMMOVE);
		if (RTN_Valid(memmoveRtn))
		{
				printf("MEMMOVE found\n");
				RTN_Open(memmoveRtn);
				RTN_InsertCall(memmoveRtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
								IARG_THREAD_ID, IARG_G_ARG0_CALLEE, IARG_G_ARG1_CALLEE, IARG_G_ARG2_CALLEE, IARG_END);
				RTN_InsertCall(memmoveRtn, IPOINT_AFTER, (AFUNPTR)MemmoveAfter, IARG_THREAD_ID, IARG_INST_PTR,
								IARG_G_RESULT0, IARG_END);
				RTN_Close(memmoveRtn);
		}

#endif
}
/* ===================================================================== */
VOID traceFileOpen(char *fname)
{
		char name[256];
		struct stat st = {0};

		if (stat("./BEEP_out", &st) == -1) {
				mkdir("./BEEP_out", 0700);
		}
		char *ptr = strrchr(fname, '/');
		if(ptr == NULL) ptr=fname;

		sprintf(name, "BEEP_out/%s.pinout.%d", ptr, PIN_GetPid());
		outfile = fopen(name, "w");
	//	thread_outfile = fopen(name, "w");
		if(outfile == NULL)
		{
				fprintf(stderr, "Cannot create output file \"%s\", errno %d.\n", name, errno);
		}

		sprintf(name, "BEEP_out/%s.pinout.%d.loop", ptr, PIN_GetPid());
		outfile2 = fopen(name, "w");
		if(outfile2 == NULL)
		{
				fprintf(stderr, "Cannot create output file \"%s\", errno %d.\n", name, errno);
		}

		sprintf(name, "BEEP_out/%s.pinout.%d.mem", ptr, PIN_GetPid());
		outfile3 = fopen(name, "w");
		if(outfile3 == NULL)
		{
				fprintf(stderr, "Cannot create output file \"%s\", errno %d.\n", name, errno);
		}
}

/* Called when a thread starts. */
void ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, void *v)
{
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		Thread *thread = &threadTable[tid];

		for (UINT32 i = 0; i < MAX_CALLSTACK; i++) {
				CallStackFrame *frame = &thread->callStack[i];
				frame->path.reserve(MAX_BBLPATH);
		}

		CallStackFrame *frame = &thread->callStack[0];
		frame->sp = (ADDRINT)-1; // must be larger than any stack pointer
		thread->callStackDepth = 1;

//		char name[256];
//		sprintf(name, "%s.%d", filename_prefix, PIN_ThreadId());
//		thread_outfile = fopen(name, "w");
}

/* Called when a thread terminates. */
void ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, void *v)
{
		ASSERT(tid < MAX_THREAD, "Increase MAX_THREAD");
		Thread *thread = &threadTable[tid];

		for (UINT32 i = 0; i < MAX_CALLSTACK; i++) {
				CallStackFrame *frame = &thread->callStack[i];
				frame->path.clear();
				frame->path.~vector<Bbl>();

		}
//		fclose(thread_outfile);
}

VOID Fini(INT32 code, VOID *v)
{
		fclose(outfile);
		fclose(outfile2);
		fclose(outfile3);
#ifndef NDEBUG
		IT_inorder(ITRoot);
#endif
}

int unitNum[MAX_THREAD];

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
		syscall_t[threadIndex][0] = PIN_GetSyscallNumber(ctxt, std);
		syscall_t[threadIndex][1] = PIN_GetSyscallArgument(ctxt, std, 0);
		syscall_t[threadIndex][2] = PIN_GetSyscallArgument(ctxt, std, 1);
		syscall_t[threadIndex][3] = PIN_GetSyscallArgument(ctxt, std, 2);
		syscall_t[threadIndex][4] = PIN_GetSyscallArgument(ctxt, std, 3);
		syscall_t[threadIndex][5] = PIN_GetSyscallArgument(ctxt, std, 4);
}

VOID SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
		if(!startPrint) return;

		int sysno = syscall_t[tid][0];
		int ret = PIN_GetSyscallReturn(ctxt, std);

		if(ret < 0) return;
		if((sysent[sysno].sys_flags & LG) == 0) return;

		UINT64 timestamp = threadTable[tid].instrCount;

		trace("%lu: [%d] SC ip 0 id %d (%s) ret %d\n", timestamp, tid, sysno, sysent[sysno].sys_name, ret);
}

VOID injectMallocLog(THREADID tid) 
{
		UINT64 timestamp = threadTable[tid].instrCount;

		std::vector<malloc_log>::iterator it;
		for( it = mallocLog.begin(); it != mallocLog.end(); it++)
		{
				if(it->type == 1) {
						trace("%lu: [0] MA ip 0 id %d addr %lx size %ld #from the parent\n", timestamp, it->id, it->addr, it->size);
				} else if(it->type == 2) {
						trace("%lu: [0] FR ip 0 id %d addr %lx size %ld #from the parent\n", timestamp, it->id, it->addr, it->size);
				} else if(it->type == 3) {
						trace("%lu: [0] RA ip 0 id %d addr %lx size %ld addr_src %lx #from the parent\n", timestamp, it->id, it->addr, it->size, it->addrSrc);
				}
		}
}

VOID AfterForkInChild(THREADID tid, const CONTEXT* ctxt, VOID * arg)
{
		traceFileOpen(outFileName);
		//injectMallocLog(tid);
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{

		PIN_InitSymbols();

		if( PIN_Init(argc,argv) )
		{
				return Usage();
		}


		if(argc < 5) return Usage();
		outFileName = argv[4];
		traceFileOpen(outFileName);

		//PIN_InitLock(&lock);
		IMG_AddInstrumentFunction(Image, 0);
		PIN_AddSyscallEntryFunction(SyscallEntry, 0);
		PIN_AddSyscallExitFunction(SyscallExit, 0);
		TRACE_AddInstrumentFunction(Trace, 0);
		INS_AddInstrumentFunction(Instruction, 0);

		PIN_AddThreadStartFunction(ThreadStart, 0);
		PIN_AddThreadFiniFunction(ThreadFini, 0);

		PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);

		PIN_AddFiniFunction(Fini, 0);

		// Never returns

		PIN_StartProgram();

		return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
