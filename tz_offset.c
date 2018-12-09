#include <time.h>

#include "tz_offset.h"

/* timezone is a system global variable.
 * See tzset(3) or timezone(3).
 */
int32_t tz_offset(void)
{
    return -timezone;
}
