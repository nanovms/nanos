#pragma once

boolean init_hpet(heap misc, heap virtual_pagesized, heap pages);
void hpet_timer(time period, thunk t);
void hpet_periodic_timer(time rate, thunk t);

