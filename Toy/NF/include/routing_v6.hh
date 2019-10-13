#include <cstdint>
#include <net.hh>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "hash_table.hh"

class Lock
{
public:
    Lock()
    {
        int ret;
        //ret = pthread_mutex_init(&mutex_, NULL);
        assert(ret == 0);
    }

    void acquire()
    {
        //pthread_mutex_lock(&mutex_);
    }

    void release()
    {
        //pthread_mutex_unlock(&mutex_);
    }

    pthread_mutex_t mutex_;
};

class RoutingTableV6
{
public:
    RoutingTableV6() : m_IsBuilt(false)
    {
        for (int i = 0; i < 128; i++)
        {
            // Currently all tables have the same DEFAULT_TABLE_SIZE;
            m_Tables[i] = new HashTable128();
        }
    }
    virtual ~RoutingTableV6()
    {
        for (int i = 0; i < 128; i++)
            delete m_Tables[i];
    }
    int from_random(int seed, int count);
    int from_file(const char *filename);
    void add(uint128_t addr, int len, uint16_t dest);
    int update(uint128_t addr, int len, uint16_t dest);
    int remove(uint128_t addr, int len);
    int build();
    uint16_t lookup(uint128_t *ip);
    RoutingTableV6 *clone();
    void copy_to(RoutingTableV6 *new_table); // added function in modular-nba

    HashTable128 *m_Tables[128];
    bool m_IsBuilt;

private:
    Lock build_lock_;
};

uint128_t masks(uint128_t aa, int len)
{
    len = 128 - len;
    uint128_t a = aa;
    assert(len >= 0 && len <= 128);

    if (len < 64)
    {
        a.u64[0] = ((a.u64[0] >> len) << len);
    }
    else if (len < 128)
    {
        a.u64[1] = ((a.u64[1] >> (len - 64)) << (len - 64));
        a.u64[0] = 0;
    }
    else
    {
        a.u64[0] = 0;
        a.u64[1] = 0;
    }
    return a;
};
