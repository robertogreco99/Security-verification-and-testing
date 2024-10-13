// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
/*	$File: localtime_r.c,v 1.1 2015/01/09 19:28:32 christos Exp $	*/

#include "file.h"
#ifndef	lint
FILE_RCSID("@(#)$File: localtime_r.c,v 1.1 2015/01/09 19:28:32 christos Exp $")
#endif	/* lint */
#include <time.h>
#include <string.h>

/* asctime_r is not thread-safe anyway */
struct tm *
localtime_r(const time_t *t, struct tm *tm)
{
	struct tm *tmp = localtime(t);
	if (tmp == NULL)
		return NULL;
	memcpy(tm, tmp, sizeof(*tm));
	return tmp;
}
