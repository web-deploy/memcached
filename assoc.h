/* associative array */
void assoc_init(const int hashpower_init);
item *assoc_find(const char *key, const size_t nkey);
int assoc_insert(item *item);
void assoc_delete(const char *key, const size_t nkey);
void do_assoc_move_next_bucket(void);
int start_assoc_maintenance_thread(void);
void stop_assoc_maintenance_thread(void);
#ifdef ENABLE_SFLOW
typedef int (itemCB)(item *, int bkt, void *magic);
int htWalk(itemCB *cbFn, int startBkt, int n, void *magic);
#endif
