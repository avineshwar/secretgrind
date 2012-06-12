/*
 * taintgrind.h
 *
 *  Created on: Jun 12, 2012
 *      Author: khilan
 */

#ifndef TAINTGRIND_H_
#define TAINTGRIND_H_

#include "valgrind.h"

typedef enum {
	VG_USERREQ__TAINTGRIND_ENTERSANDBOX,
	VG_USERREQ__TAINTGRIND_EXITSANDBOX,
	VG_USERREQ__TAINTGRIND_SHAREDFD,
	VG_USERREQ__TAINTGRIND_SHAREDVAR
} Vg_TaintGrindClientRequest;

#define TNT_SANDBOX(fncall) \
	{ \
		VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__TAINTGRIND_ENTERSANDBOX, 0, 0, 0, 0, 0); \
		fncall; \
		VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__TAINTGRIND_EXITSANDBOX, 0, 0, 0, 0, 0); \
	}

#define TNT_SHAREDFD(fd) \
		VALGRIND_DO_CLIENT_REQUEST_EXPR(fd, VG_USERREQ__TAINTGRIND_SHAREDFD, fd, 0, 0, 0, 0)

#define TNT_SHAREDVAR(var) \
			VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__TAINTGRIND_SHAREDVAR, #var, 0, 0, 0, 0)

#endif /* TAINTGRIND_H_ */
