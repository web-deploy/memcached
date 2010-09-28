#ifndef SFLOW_MC_H
#define SFLOW_MC_H 1

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/wait.h>

#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> /* for PRIu64 etc. */
#include <pthread.h>

#include "sflow_api.h"
#define SFMC_VERSION "0.9"
#define SFMC_DEFAULT_CONFIGFILE "/etc/hsflowd.auto"
#define SFMC_MAX_TICKS 60
#define SFMC_SEPARATORS " \t\r\n="
#define SFMC_QUOTES "'\" \t\r\n"
/* SFMC_MAX LINE LEN must be enough to hold the whole list of targets */
#define SFMC_MAX_LINELEN 1024
#define SFMC_MAX_COLLECTORS 10

typedef struct _SFMCCollector {
  struct sockaddr sa;
  SFLAddress addr;
  uint16_t port;
  uint16_t priority;
} SFMCCollector;

typedef struct _SFMCConfig {
  int error;
  uint32_t sampling_n;
  uint32_t polling_secs;
  SFLAddress agentIP;
  uint32_t num_collectors;
  SFMCCollector collectors[SFMC_MAX_COLLECTORS];
} SFMCConfig;

typedef struct _SFMC {
  pthread_mutex_t *mutex;
  int enabled;
  /* config */
  char *configFile;
  time_t configFile_modTime;
  SFMCConfig *config;
  uint32_t configTests;
  /* sFlow agent */
  SFLAgent *agent;
  /* UDP send sockets */
  int socket4;
  int socket6;
} SFMC;

#define SFLOW_SAMPLE_TEST(c) (unlikely((--c->thread->sflow_skip)==0))
void sflow_sample(SFMC *sm, struct conn *c, SFLMemcache_prot prot, SFLMemcache_cmd cmd, char *key, size_t keylen, uint32_t nkeys, size_t value_bytes, uint32_t duration_uS, uint32_t status);
#define SFLOW_DURATION_UNKNOWN 0
#define SFLOW_TOKENS_UNKNOWN 0
void sflow_init(SFMC *sm);
void sflow_tick(SFMC *sm);
void sflow_processVarValueOption(SFMC *sm, char *optarg);
SFLMemcache_operation_status sflow_map_status(enum store_item_type ret);
SFLMemcache_cmd sflow_map_nread(int cmd);

#endif /* SFLOW_MC_H */

