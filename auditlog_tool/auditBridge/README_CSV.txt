* Delimiter: ";" 

* Order of fields: 
evt.num; evt.datetime; evt.type; evt.res; evt.args; thread.tid; thread.unitid;
proc.pid; proc.ppid; proc.name; proc.exepath; user.uid; user.euid; user.gid;
fd[0].num; fd[0].type; fd[0].filename; fd[0].name; fd[0].inode; fd[0].ip;
fd[0].port; fd[1].num; fd[1].type; fd[1].filename; fd[1].name; fd[1].inode;
fd[1].ip; fd[1].port; proc.cwd; proc.args; proc.name; proc.inode; dep.tid;
dep.unitid;


* Common fields:
- evt.num
- evt.datetime
- evt.type; syscall name and number or UBSI events (UBSI_ENTRY, UBSI_EXIT, UBSI_DEP)
- evt.res; syscall return value
- evt.args; up to 4 args (arg[0] - arg[3])
- thread.tid; tid with thread creation time
- thread.unitid; UBSI unitid (loop time, loopId, loopCounter)
- proc.id; main thread id
- proc.ppid
- proc.name
- proc.exepath
- user.uid
- user.euid
- user.gid

* File descriptor:
; for regular files
- fd[0].num
- fd[0].type
- fd[0].filename
- fd[0].name
- fd[0].inode
; for socket
- fd[0].ip
- fd[0].port
- proc.cwd; current working directory

* SYS_execve:
- proc.args; commandline arguments
- proc.name; binary file name to be executed
- proc.inode; inode for the binary

* UBSI_DEP:
; tid and unitid of the unit that the current unit has dependence
- dep.tid
- dep.unitid

UBSI_ENTRY and UBSI_EXIT:
since we have unitid for each event, we don't need to consider
UBSI_ENTRY and UBSI_EXIT events. (but I just keep them in the log)

