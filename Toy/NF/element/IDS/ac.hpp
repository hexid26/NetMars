#pragma once
// #define _G4C_AC_TEST_
#ifdef _G4C_AC_TEST_
#include <stdio.h>
#include <stdlib.h>
#endif

#include <stddef.h>

#include <errno.h>
#include "g4c.h"
#include "g4c_ac.h"

#include <cstdio>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <iostream>
#include <algorithm>

using namespace std;

class ACState
{
public:
	int id;
	ACState *prev;
	map<char, int> go;
	set<int> output;
	int failure;

	int transition[AC_ALPHABET_SIZE];

	ACState() : id(0), prev(0), failure(-1) {}
	ACState(int sid) : id(sid), prev(0), failure(-1) {}
	ACState(int sid, ACState *sprev) : id(sid), prev(sprev), failure(-1) {}
	~ACState() {}
};

class ACMachine
{
public:
	vector<ACState *> states;
	char **patterns;
	int npatterns;

	ACMachine() {}
	~ACMachine()
	{
		for (int i = 0; i < states.size(); i++)
			delete states[i];
		states.clear();
	}
};

extern "C" void
ac_build_goto(char *kws[], int n, ACMachine *acm);

extern "C" void
ac_build_failure(ACMachine *acm);

extern "C" void
ac_build_transition(ACMachine *acm);

extern "C"
{
#include <stdlib.h>
#include <string.h>
}

extern "C" int
g4c_cpu_acm_match(g4c_acm_t *acm, uint8_t *data, int len);

// extern "C" g4c_acm_t*
// g4c_create_matcher(char **ptns, int nptns, int withdev, int stream)
// {
//     ACMachine *cppacm = new ACMachine();
//     if (!cppacm) {
// 	fprintf(stderr, "Out of memory for C++ ACM\n");
// 	return 0;
//     }

//     ac_build_goto(ptns, nptns, cppacm);
//     ac_build_failure(cppacm);
//     ac_build_transition(cppacm);

//     size_t trsz = cppacm->states.size()*AC_ALPHABET_SIZE*sizeof(int);
//     trsz = g4c_round_up(trsz, G4C_PAGE_SIZE);

//     size_t outsz = cppacm->states.size()*sizeof(int);
//     outsz = g4c_round_up(outsz, G4C_PAGE_SIZE);

//     size_t totalsz = G4C_PAGE_SIZE + trsz + outsz;
//     g4c_acm_t *acm = (g4c_acm_t*)g4c_alloc_page_lock_mem(totalsz);
//     void *dmem = 0;
//     if (withdev) {
// 	dmem = g4c_alloc_dev_mem(totalsz);
//     }

//     if (!acm || (withdev && !dmem)) {
// 	fprintf(stderr, "Out of mem for acm GPU memory or device mem "
// 		"%p, %p, %lu\n", acm, dmem, totalsz);
// 	return 0;
//     }

//     acm->mem = (void*)acm;
//     acm->devmem = dmem;
//     acm->memsz = totalsz;
//     acm->nstates = (int)cppacm->states.size();
//     acm->transitions = (int*)g4c_ptr_add(acm->mem, G4C_PAGE_SIZE);
//     acm->outputs = (int*)g4c_ptr_add(acm->transitions, trsz);
//     if (withdev) {
// 	acm->dtransitions = (int*)g4c_ptr_add(acm->devmem, G4C_PAGE_SIZE);
// 	acm->doutputs = (int*)g4c_ptr_add(acm->dtransitions, trsz);
//     }

//     for (int i=0; i<acm->nstates; i++) {
// 	ACState *cpps = cppacm->states[i];
// 	memcpy(g4c_acm_htransitions(acm, i),
// 	       cpps->transition,
// 	       sizeof(int)*AC_ALPHABET_SIZE);
// 	if (cpps->output.size()) {
// 	    set<int>::iterator minout =
// 		min_element(cpps->output.begin(), cpps->output.end());
// 	    *g4c_acm_houtput(acm, i) = (*minout) + 1;
// 	} else {
// 	    *g4c_acm_houtput(acm, i) = 0;
// 	}
//     }

//     if (withdev) {
// 	g4c_h2d_async(acm->mem, acm->devmem, acm->memsz, stream);
// 	g4c_stream_sync(stream);
//     }

//     return acm;
// }

extern "C" int
ac_build_machine(ac_machine_t *acm, char **patterns,
				 int npatterns, unsigned int memflags);

extern "C" void
ac_release_machine(ac_machine_t *acm);

extern "C" int
ac_match(char *str, int len, unsigned int *res, int once, ac_machine_t *acm);
#ifdef _G4C_AC_TEST_

static void
dump_state(ACState *s, char *kws[]);

static void
dump_c_state(ac_state_t *s, ac_machine_t *acm);

extern "C" void
dump_c_acm(ac_machine_t *acm);

#endif
