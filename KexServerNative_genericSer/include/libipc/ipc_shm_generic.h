/*
 * ipc_control.h
 *
 *  Created on: 22 Apr 2020
 *      Author: yiwen
 */

#ifndef __IPC_SHM_GENERIC_H__
#define __IPC_SHM_GENERIC_H__

#include<stdio.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<sys/types.h>
#include<string.h>
#include<errno.h>
#include<stdlib.h>
#include<unistd.h>
#include<inttypes.h>
#include <string.h>
#include <pthread.h>

#define SHM_BUF_SIZE					1024

struct IPC_shm {

#define 		IPC_SHM_STATE_INIT  0x00
#define 		IPC_SHM_STATE_REDY 	0x01
#define 		IPC_SHM_STATE_BUSY 	0x02
#define 		IPC_SHM_STATE_FREE 	0x03
	volatile int state;
	volatile size_t length;
	unsigned char data[SHM_BUF_SIZE];

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

int IPC_shm_init(struct IPC_shm **shm, int shm_addr, int server);

int IPC_shm_free(struct IPC_shm *shm);

int IPC_shm_read(struct IPC_shm *shm, unsigned char *data, size_t *olen);

int IPC_shm_write(struct IPC_shm *shm, unsigned char *data, size_t len);

#endif /* __IPC_SHM_GENERIC_H__ */
