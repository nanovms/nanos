//#define ENABLE_MSG_DEBUG
#include <runtime.h>
#include <table.h>
#define EMPTY ((void *)0)

static inline key int_key_function(void *x) {
  return *((key*)(x));
}

static inline boolean int_equal_function(void *x, void *y) {
  int x_int = *(int*)(x);
  int y_int = *(int*)(y);
  return x_int == y_int;
}

static inline boolean string_equal_function(void *x, void *y) {
  char *x_str = (char*)(x);
  char *y_str = (char*)(y);
  return strcmp(x_str, y_str) == 0;
}

void deallocate_table(table t) {
  while(table_elements(t)) {
    for(int i = 0; i<t->buckets; i++){
      entry j = t->entries[i];
      if(j != INVALID_ADDRESS) {
        key nextdel = j->k;
        table_set(t, &nextdel, EMPTY);
      }
    }
  }
  heap h = t->h;
  deallocate(h, t->entries, t->buckets * sizeof(void *));
  deallocate(h, t, sizeof(struct table)); 
}

void check_int(table t) {
  // empty table
  assert(table_elements(t) == 0);
  // add 4 elements
  int key[] = {0, 1, 2, 3};
  int value[] = {4, 5, 6, 7};
  for(int i = 0; i < 4; ++i) {
    table_set(t, &key[i], &value[i]);
  }
  assert(table_elements(t) == 4);
  // add new element in same key
  value[0] = 10;
  table_set(t, &key[0], &value[0]);
  // same size?
  assert(table_elements(t) == 4);
  // check values
  for(int i = 0; i < 4; ++i) {
    void *v = table_find(t, &key[i]);
    int val = *((int*)v);
    assert(val == value[i]);
  }
  //delete values
  for(int i = 0; i < 4; ++i) {
    table_set(t, &key[i], EMPTY);
  }
  // empty table again
  assert(table_elements(t) == 0);
}

void check_string(table t) {
  // empty table
  assert(table_elements(t) == 0);
  // add 4 elements
  int key[] = {0, 1, 2, 3};
  char *value[] = {"one", "two", "three", "four"};
  for(int i = 0; i < 4; ++i) {
    table_set(t, &key[i], value[i]);
  }
  assert(table_elements(t) == 4);
  // add new element in same key
  char newval[] = "five";
  table_set(t, &key[0], newval);
  // same size?
  assert(table_elements(t) == 4);
  // check values
  char *v = (char*)table_find(t, &key[0]);
  assert(strcmp(v, value[0])!=0);
  assert(strcmp(v, newval)==0);
  for(int i = 1; i < 4; ++i) {
    v = (char*)table_find(t, &key[i]);
    assert(strcmp(value[i], v)==0);
  }
  //delete values
  for(int i = 0; i < 4; ++i) {
    table_set(t, &key[i], EMPTY);
  }
  // empty table again
  assert(table_elements(t) == 0);
}

int main() {
  heap h = init_process_runtime();
  msg_debug("test with default functions (pointers)\n");
  table t = allocate_table(h, identity_key, pointer_equal);
  check_int(t);
  deallocate_table(t);
  t = EMPTY;

  msg_debug("test with int values functions\n");
  t = allocate_table(h, int_key_function, int_equal_function);
  check_int(t);
  deallocate_table(t);
  t = EMPTY;

  msg_debug("test with string values functions\n");
  t = allocate_table(h, int_key_function, string_equal_function);
  check_string(t);
  deallocate_table(t);
  t = EMPTY;
  
  exit(0);
}
