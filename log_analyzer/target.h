typedef struct {
		string command;
		set<string> filewrite;
		set<string> fileread;
		set<string> socketread;
		set<string> socketwrite;
		INT parent;
		bool child;
		INT numChild;
} TargetProcess;

extern map<INT, TargetProcess> targetProcess;
extern map<string, set<INT> > fileWrite;
extern map<string, set<INT> > fileRead;
extern map<string, set<INT> > localSocket;

bool isLibOrConf(string name, INT pid);
bool isReadOnly(string name, INT pid);
bool isWriteOnly(string name, INT pid);
void insert_target_process(INT spid, string exe, string comm);

