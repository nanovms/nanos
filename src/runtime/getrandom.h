#pragma once

#define MAX_ENTROPY_POOL            4096
#define GRND_NONBLOCK               1
#define GRND_RANDOM                 2
#define MAX_RANDOM_ENTROPY_COUNT    256

u64 do_getrandom(buffer b, u64 flags);
