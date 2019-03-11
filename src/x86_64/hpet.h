
boolean init_hpet(heap misc, heap virtual_pagesized, heap pages);
void hpet_timer(timestamp period, thunk t);
void hpet_runloop_timer(timestamp period);
void hpet_periodic_timer(timestamp rate, thunk t);

