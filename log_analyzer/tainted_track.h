
bool detect_root_access();
void insert_tainted_pid(INT pid);
void insert_tainted_inode(string str, INT pid, INT inode);
bool find_tainted_open(bool isWrite);
bool tainted_write_open();
void insert_tainted_inode(string str, INT pid, INT inode);
bool find_tainted_clone();
void insert_graph_socketread(INT pid, INT unitid);
void clean_temp_list(bool isFork);
void insert_graph_socketread(INT pid, INT unitid);
void insert_temp_socketread();
bool is_tainted_pid(INT pid);
bool is_tainted_proc_list(INT pid, INT unitid);
