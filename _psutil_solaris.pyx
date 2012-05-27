# -*- coding: ASCII -*-

# ^ The above encoding must be preserved for due to the use of
# embedded strings in this code.

# Be sure to read some of the comments at the end of this file.

__author__ = 'Justin Venus <justin.venus@gmail.com>'
__doc__ = """
Solaris 10+ psutil backend interface implementation.

These interfaces were written in cython.  One of the advantages
to this approach is ease of integration with the native C API's
and python.  Another advantage is that types do not have to match
the specification exactly as the real header files are used for
compilation.  The last advantage is we only have to update this
one file and emit new C sources to fulfill our API obligations.
"""

from libc.stdio cimport (
    FILE, fread, fclose, ferror, feof, fopen, const_char, fflush)

################################################################################
# it is just easier to define these and copy the structure
# definitions directly from the header files.
################################################################################
ctypedef int int32_t
ctypedef int gid_t
ctypedef int uid_t
ctypedef int pid_t
ctypedef int ino_t
ctypedef int dev_t
ctypedef long time_t
ctypedef long suseconds_t
ctypedef unsigned char uchar_t
ctypedef unsigned int uint32_t
ctypedef signed long long int int64_t
ctypedef unsigned long long int uint64_t
ctypedef unsigned long long u_longlong_t
ctypedef unsigned long ulong_t
ctypedef ulong_t major_t
ctypedef ulong_t minor_t
ctypedef long long longlong_t
ctypedef unsigned int uint_t
ctypedef int intptr_t
ctypedef unsigned int uintptr_t
ctypedef longlong_t offset_t
################################################################################

DEF XMAP=1
DEF MAP=2

cdef extern from "sys/time.h":
    ctypedef long long hrtime_t

cdef extern from "sys/mnttab.h":
    enum: MNTTAB #location of mnttab on this system
    ctypedef struct struct_mnttab "struct mnttab":
        char    *mnt_special
        char    *mnt_mountp
        char    *mnt_fstype
        char    *mnt_mntopts
        char    *mnt_time
    int getmntent(FILE *, struct_mnttab *)

cdef extern from "sys/sysinfo.h":
    enum: CPU_USER   # user
    enum: CPU_WAIT   # iowait
    enum: CPU_KERNEL # sys
    enum: CPU_IDLE   # idle
    enum: CPU_STATES # swap

    enum: W_IO
    enum: W_SWAP
    enum: W_PIO
    enum: W_STATES

    enum: __cpu_stat_lock # private used further in this def

    ctypedef struct cpu_sysinfo_t:
        uint_t  cpu[CPU_STATES] # CPU utilization                     
        uint_t  wait[W_STATES]  # CPU wait time breakdown              * 
        uint_t  bread           # physical block reads                 
        uint_t  bwrite          # physical block writes (sync+async)   
        uint_t  lread           # logical block reads                  
        uint_t  lwrite          # logical block writes                 
        uint_t  phread          # raw I/O reads                        
        uint_t  phwrite         # raw I/O writes                       
        uint_t  pswitch         # context switches                     
        uint_t  trap            # traps                                
        uint_t  intr            # device interrupts                    
        uint_t  syscall         # system calls                         
        uint_t  sysread         # read() + readv() system calls        
        uint_t  syswrite        # write() + writev() system calls      
        uint_t  sysfork         # forks                                
        uint_t  sysvfork        # vforks                               
        uint_t  sysexec         # execs                                
        uint_t  readch          # bytes read by rdwr()                 
        uint_t  writech         # bytes written by rdwr()              
        uint_t  rcvint          # XXX: UNUSED                          
        uint_t  xmtint          # XXX: UNUSED                          
        uint_t  mdmint          # XXX: UNUSED                          
        uint_t  rawch           # terminal input characters            
        uint_t  canch           # chars handled in canonical mode      
        uint_t  outch           # terminal output characters           
        uint_t  msg             # msg count (msgrcv()+msgsnd() calls)  
        uint_t  sema            # semaphore ops count (semop() calls)  
        uint_t  namei           # pathname lookups                     
        uint_t  ufsiget         # ufs_iget() calls                     
        uint_t  ufsdirblk       # directory blocks read                
        uint_t  ufsipage        # inodes taken with attached pages     
        uint_t  ufsinopage      # inodes taked with no attached pages  
        uint_t  inodeovf        # inode table overflows                
        uint_t  fileovf         # file table overflows                 
        uint_t  procovf         # proc table overflows                 
        uint_t  intrthread      # interrupts as threads (below clock)  
        uint_t  intrblk         # intrs blkd/prempted/released (swtch) 
        uint_t  idlethread      # times idle thread scheduled          
        uint_t  inv_swtch       # involuntary context switches         
        uint_t  nthreads        # thread_create()s                     
        uint_t  cpumigrate      # cpu migrations by threads            
        uint_t  xcalls          # xcalls to other cpus                 
        uint_t  mutex_adenters  # failed mutex enters (adaptive)       
        uint_t  rw_rdfails      # rw reader failures                   
        uint_t  rw_wrfails      # rw writer failures                   
        uint_t  modload         # times loadable module loaded         
        uint_t  modunload       # times loadable module unloaded       
        uint_t  bawrite         # physical block writes (async)        
# Following are gathered only under #ifdef STATISTICS in source        
        uint_t  rw_enters       # tries to acquire rw lock             
        uint_t  win_uo_cnt      # reg window user overflows            
        uint_t  win_uu_cnt      # reg window user underflows           
        uint_t  win_so_cnt      # reg window system overflows          
        uint_t  win_su_cnt      # reg window system underflows         
        uint_t  win_suo_cnt     # reg window system user overflows

    ctypedef struct cpu_syswait_t:
        int     iowait          # procs waiting for block I/O
        int     swap            # XXX: UNUSED
        int     physio          # XXX: UNUSED

    ctypedef struct vminfo_t:   # (update freq) update action          
        uint64_t freemem        # (1 sec) += freemem in pages          
        uint64_t swap_resv      # (1 sec) += reserved swap in pages    
        uint64_t swap_alloc     # (1 sec) += allocated swap in pages   
        uint64_t swap_avail     # (1 sec) += unreserved swap in pages  
        uint64_t swap_free      # (1 sec) += unallocated swap in pages 
        uint64_t updates        # (1 sec) ++                           

    ctypedef struct cpu_vminfo_t:
        uint_t  pgrec           # page reclaims (includes pageout)     
        uint_t  pgfrec          # page reclaims from free list         
        uint_t  pgin            # pageins                              
        uint_t  pgpgin          # pages paged in                       
        uint_t  pgout           # pageouts                             
        uint_t  pgpgout         # pages paged out                      
        uint_t  swapin          # swapins                              
        uint_t  pgswapin        # pages swapped in                     
        uint_t  swapout         # swapouts                             
        uint_t  pgswapout       # pages swapped out                    
        uint_t  zfod            # pages zero filled on demand          
        uint_t  dfree           # pages freed by daemon or auto        
        uint_t  scan            # pages examined by pageout daemon     
        uint_t  rev             # revolutions of the page daemon hand  
        uint_t  hat_fault       # minor page faults via hat_fault()    
        uint_t  as_fault        # minor page faults via as_fault()     
        uint_t  maj_fault       # major page faults                    
        uint_t  cow_fault       # copy-on-write faults                 
        uint_t  prot_fault      # protection faults                    
        uint_t  softlock        # faults due to software locking req   
        uint_t  kernel_asflt    # as_fault()s in kernel addr space     
        uint_t  pgrrun          # times pager scheduled                
        uint_t  execpgin        # executable pages paged in            
        uint_t  execpgout       # executable pages paged out           
        uint_t  execfree        # executable pages freed               
        uint_t  anonpgin        # anon pages paged in                  
        uint_t  anonpgout       # anon pages paged out                 
        uint_t  anonfree        # anon pages freed                     
        uint_t  fspgin          # fs pages paged in                    
        uint_t  fspgout         # fs pages paged out                   
        uint_t  fsfree          # fs pages free                        

    ctypedef struct cpu_stat_t:
        unsigned int    __cpu_stat_lock[2]  # 32-bit kstat compat.
        cpu_sysinfo_t   cpu_sysinfo 
        cpu_syswait_t   cpu_syswait 
        cpu_vminfo_t    cpu_vminfo 

cdef extern from "sys/mkdev.h":
    cdef major_t major(dev_t)
    cdef minor_t minor(dev_t)

cdef extern from "kstat.h":
    enum: KSTAT_STRLEN
    enum: KSTAT_TYPE_IO
    enum: KSTAT_TYPE_NAMED
    enum: KSTAT_TYPE_RAW
    # needed to lookup which union member to use in kstat_named_t
    enum: KSTAT_DATA_CHAR   # <kstat_named_t *>.value.c
    enum: KSTAT_DATA_INT32  # <kstat_named_t *>.value.i32
    enum: KSTAT_DATA_UINT32 # <kstat_named_t *>.value.ui32
    enum: KSTAT_DATA_INT64  # <kstat_named_t *>.value.i64
    enum: KSTAT_DATA_UINT64 # <kstat_named_t *>.value.ui64

    ctypedef struct kstat_t:
        #
        # Fields relevant to both kernel and user
        #
        hrtime_t        ks_crtime       # creation time (from gethrtime()) 
        kstat_t         *ks_next        # kstat chain linkage 
        int             ks_kid          # unique kstat ID 
        char            ks_module[KSTAT_STRLEN]  # provider module name 
        unsigned char   ks_resv         # reserved, currently just padding 
        int             ks_instance     # provider module's instance 
        char            ks_name[KSTAT_STRLEN]  # kstat name 
        unsigned char   ks_type         # kstat data type 
        char            ks_class[KSTAT_STRLEN]  # kstat class 
        unsigned char   ks_flags        # kstat flags 
        void            *ks_data        # kstat type-specific data 
        unsigned int    ks_ndata        # # of type-specific data records 
        size_t          ks_data_size    # total size of kstat data section 
        hrtime_t        ks_snaptime     # time of last data shapshot
        #
        # Fields relevant to kernel only
        #
        void            *_pri1
        void            *_pri2
        void            *_pri3
        void            *_pri4

    ctypedef struct kstat_ctl_t:
        int kc_chain_id   # current kstat chain ID
        kstat_t *kc_chain # pointer to kstat chain
        int kc_kd         # /dev/kstat descriptor
        void **kc_private # Private DONOT USE!!!!

    ctypedef union kstat_named_union:  
        char c[16]                  # enough for 128-bit ints
        int32_t i32
        uint32_t ui32
        int64_t i64
        uint64_t ui64
        # These structure members are obsolete
        int32_t l
        uint32_t ul
        int64_t ll
        uint64_t ull

    ctypedef struct kstat_named_t:
        char name[KSTAT_STRLEN]         # name of counter
        uchar_t data_type               # data type
        kstat_named_union value

    ctypedef struct kstat_io_t:
        u_longlong_t    nread           # number of bytes read 
        u_longlong_t    nwritten        # number of bytes written 
        uint_t          reads           # number of read operations 
        uint_t          writes          # number of write operations 
# you can ignore these
        hrtime_t wtime          # cumulative wait (pre-service) time 
        hrtime_t wlentime       # cumulative wait length*time product 
        hrtime_t wlastupdate    # last time wait queue changed 
        hrtime_t rtime          # cumulative run (service) time 
        hrtime_t rlentime       # cumulative run length*time product 
        hrtime_t rlastupdate    # last time run queue changed 
        uint_t  wcnt            # count of elements in wait state 
        uint_t  rcnt            # count of elements in run state 

    cdef kstat_ctl_t *kstat_open()
    cdef int kstat_close(kstat_ctl_t *)
    cdef int kstat_read(kstat_ctl_t *, kstat_t *, void *)
    cdef void *kstat_data_lookup(kstat_t *, char *)

cdef extern from "unistd.h":
    enum: _SC_NPROCESSORS_ONLN # (volatile) number of procs online
    enum: _SC_AVPHYS_PAGES     # (volatile) memory pages not currently used
    enum: _SC_PAGE_SIZE        # system memory page size
    enum: _SC_PHYS_PAGES       # Total number of pages of physical memory in system
    long sysconf(int)
    size_t pread(int, void *, size_t, long)

cdef extern from "sys/time_impl.h":
    ctypedef struct timestruc_t:
        long tv_sec
        long tv_nsec

cdef extern from "sys/time.h":
    ctypedef struct struct_timeval "struct timeval":
        time_t          tv_sec         # seconds
        suseconds_t     tv_usec        # and microseconds

#for system users
cdef extern from "utmpx.h":
    enum: _UTMP_ID_LEN
    # The following symbolic constants  are  defined  as  possible
    # values for the ut_type member of the utmpx structure:

    enum: EMPTY         # No valid user accounting information.
#NOTE psutil Namespace API Conflict
#    enum: BOOT_TIME     # Identifies time of system boot.
    enum: OLD_TIME      # Identifies time when system clock changed.
    enum: NEW_TIME      # Identifies time after system clock changed.
    enum: USER_PROCESS  # Identifies a process.
    enum: INIT_PROCESS  # Identifies a process spawned by the init process.
    enum: LOGIN_PROCESS # Identifies the session leader of a logged-in user.
    enum: DEAD_PROCESS  # Identifies a session leader who has exited.
    ctypedef struct struct_exit_status "struct exit_status":
        pass

    ctypedef struct struct_utmpx "struct utmpx":
        char    ut_user[32]            # user login name
        char    ut_id[_UTMP_ID_LEN]    # inittab id
        char    ut_line[32]            # device name (console, lnxx)
        pid_t   ut_pid                 # process id
        short   ut_type                # type of entry
        #incomplete definition don't use
        struct_exit_status ut_exit     # process termination/exit status
        struct_timeval ut_tv           # time entry was made
        int     ut_session             # session ID, used for windowing
        int     pad[5]                 # reserved for future use
        short   ut_syslen              # significant length of ut_host
        char    ut_host[257]           # remote host name

    #man -s 3c for full descriptions
    struct_utmpx *getutxent() # opens utmpx if not already open and returns next entry
    void endutxent() # closes utmpx

cdef extern from "string.h":
    cdef void *memmove(void *, void *, int)
    cdef void *memset(void *, int, size_t)
    cdef int strcmp(char *, char *)

cdef extern from "sys/resource.h":
    enum: PRIO_PROCESS
    cdef int setpriority(int, int, int)

cdef extern from "errno.h":
    enum: EINVAL # Invalid
    enum: ENOENT # NoSuchProcess
    enum: ESRCH  # NoSuchProcess
    enum: EPERM  # AccessDenied
    enum: EACCES # AccessDenied
    cdef extern int errno
    cdef extern char *strerror(int)

cdef extern from "stdio.h":
    cdef extern void *realloc(void *, int)
    cdef extern void *malloc(int)
    cdef extern void free(void *)
    cdef extern int close(int)

cdef extern from "Python.h":
    ctypedef struct PyObject
    ctypedef struct PyThreadState
    cdef extern PyThreadState *PyEval_SaveThread()
    cdef extern void PyEval_RestoreThread(PyThreadState*)

cdef extern from "sys/regset.h":
    ctypedef struct fpregset_t:
        pass # only needed for definitions below

cdef extern from "sys/ucontext.h":
    ctypedef struct stack_t:
        pass # only needed for definition below

cdef extern from "signal.h":
    ctypedef struct struct_sigaction "struct sigaction":
        pass # only needed for definition below
    # admittedly ^this is a goofy definition

################################################################################
# NOTE We cannot directly include "sys/procfs.h" for definitions because of
# a conflict with "pyconfig.h".  Basically what happens is pyconfig.h defines
# _FILE_OFFSET_BITS as 64 which is incompatible with a definition that is
# included in "sys/procfs_old.h" and this causes a linking error. So we just
# provide the definitions that we need ourselves. 
################################################################################

DEF PRCLSZ=8    # maximum size of scheduling class name
DEF PRFNSZ=16   # Maximum size of execed filename
DEF PRARGSZ=80  # number of chars of arguments
DEF PRNODEV=-1  # no controlling terminal
DEF PRSYSARGS=8 # maximum number of syscall arguments
#hack sizeof(timestruc_t)
DEF _SIZE_TSTRUC=8
#hack sizeof(int)
DEF _SIZE_INT=4
DEF PRFILLER=11 - 2 * _SIZE_TSTRUC / _SIZE_INT
DEF PRMAPSZ=64
# Protection and attribute flags
DEF MA_READ=0x04         # readable by the traced process
DEF MA_WRITE=0x02        # writable by the traced process
DEF MA_EXEC=0x01         # executable by the traced process
DEF MA_SHARED=0x08       # changes are shared by mapped object
DEF MA_ANON=0x40         # anonymous memory (e.g. /dev/zero)
DEF MA_ISM=0x80          # intimate shared mem (shared MMU resources)
DEF MA_NORESERVE=0x100   # mapped with MAP_NORESERVE
DEF MA_SHM=0x200         # System V shared memory
DEF MA_RESERVED1=0x400   # reserved for future use
DEF MA_OSM=0x800         # Optimized Shared Memory

#
# Process credentials.  PCSCRED and /proc/<pid>/cred
#
ctypedef struct prcred_t:
    uid_t   pr_euid        # effective user id
    uid_t   pr_ruid        # real user id
    uid_t   pr_suid        # saved user id (from exec)
    gid_t   pr_egid        # effective group id
    gid_t   pr_rgid        # real group id
    gid_t   pr_sgid        # saved group id (from exec)
    int     pr_ngroups     # number of supplementary groups
    gid_t   pr_groups[1]   # array of supplementary groups

#
# Memory-map interface.  /proc/<pid>/map /proc/<pid>/rmap
#
ctypedef struct prmap_t:
    uintptr_t pr_vaddr     # virtual address of mapping
    size_t  pr_size        # size of mapping in bytes
    char    pr_mapname[PRMAPSZ]    # name in /proc/<pid>/object
    offset_t pr_offset     # offset into mapped object, if any
    int     pr_mflags      # protection and attribute flags (see above)
    int     pr_pagesize    # pagesize (bytes) for this mapping
    int     pr_shmid       # SysV shmid, -1 if not SysV shared memory
    int     pr_filler[1]   # filler for future expansion

#
# HAT memory-map interface.  /proc/<pid>/xmap
#
ctypedef struct prxmap_t:
    uintptr_t pr_vaddr      # virtual address of mapping
    size_t  pr_size         # size of mapping in bytes
    char    pr_mapname[PRMAPSZ]    # name in /proc/<pid>/object
    offset_t pr_offset      # offset into mapped object, if any
    int     pr_mflags       # protection and attribute flags (see above)
    int     pr_pagesize     # pagesize (bytes) for this mapping
    int     pr_shmid        # SysV shmid, -1 if not SysV shared memory
    int     pr_dev  # st_dev from stat64() of mapped object, or PRNODEV
    uint64_t pr_ino # st_ino from stat64() of mapped object, if any
    size_t  pr_rss          # pages of resident memory
    size_t  pr_anon         # pages of resident anonymous memory
    size_t  pr_locked       # pages of locked memory
    size_t  pr_pad          # currently unused
    uint64_t pr_hatpagesize # pagesize of the hat mapping
    void    *pr_filler      # DONOT USE incomplete definition

#
# lwp status file.  /proc/<pid>/lwp/<lwpid>/lwpstatus
#
ctypedef struct lwpstatus_t:
    int     pr_flags        # flags (see below) 
    int     pr_lwpid        # specific lwp identifier 
    short   pr_why          # reason for lwp stop, if stopped 
    short   pr_what         # more detailed reason 
    short   pr_cursig       # current signal, if any 
    short   pr_pad1 
    int     pr_info         # info associated with signal or fault 
    int     pr_lwppend      # set of signals pending to the lwp 
    int     pr_lwphold      # set of signals blocked by the lwp 
# NOTE incomplete def for pr_action
    struct_sigaction pr_action      # signal action for current signal 
# NOTE incomplete def for pr_altstack
    stack_t pr_altstack     # alternate signal stack info 
    unsigned int pr_oldcontext      # address of previous ucontext 
    short   pr_syscall      # system call number (if in syscall) 
    short   pr_nsysarg      # number of arguments to this syscall 
    int     pr_errno        # errno for failed syscall, 0 if successful 
    long    pr_sysarg[PRSYSARGS]    # arguments to this syscall 
    long    pr_rval1        # primary syscall return value 
    long    pr_rval2        # second syscall return value, if any 
    char    pr_clname[PRCLSZ]       # scheduling class name 
    timestruc_t pr_tstamp   # real-time time stamp of stop 
    timestruc_t pr_utime    # lwp user cpu time 
    timestruc_t pr_stime    # lwp system cpu time 
    int     pr_filler[PRFILLER] 
    int     pr_errpriv      # missing privilege 
    unsigned int pr_ustack  # address of stack boundary data (stack_t) 
    unsigned long pr_instr  # current instruction 
# NOTE incomplete def for next two items
    fpregset_t pr_reg       # general registers 
    fpregset_t pr_fpreg     # floating-point registers 

#
# process status file.  /proc/<pid>/status
#
ctypedef struct pstatus_t:
    int     pr_flags        # flags (see below) 
    int     pr_nlwp         # number of active lwps in the process 
    int     pr_pid          # process id 
    int     pr_ppid         # parent process id 
    int     pr_pgid         # process group id 
    int     pr_sid          # session id 
    int     pr_aslwpid      # historical  now always zero 
    int     pr_agentid      # lwp id of the /proc agent lwp, if any 
    int     pr_sigpend      # set of process pending signals 
    unsigned int pr_brkbase # address of the process heap 
    size_t  pr_brksize      # size of the process heap, in bytes 
    unsigned int pr_stkbase # address of the process stack 
    size_t  pr_stksize      # size of the process stack, in bytes 
    timestruc_t pr_utime    # process user cpu time 
    timestruc_t pr_stime    # process system cpu time 
    timestruc_t pr_cutime   # sum of children's user times 
    timestruc_t pr_cstime   # sum of children's system times 
    int     pr_sigtrace     # set of traced signals 
    int     pr_flttrace     # set of traced faults 
    int     pr_sysentry     # set of system calls traced on entry 
    int     pr_sysexit      # set of system calls traced on exit 
    char    pr_dmodel       # data model of the process (see below) 
    char    pr_pad[3] 
    int     pr_taskid       # task id 
    int     pr_projid       # project id 
    int     pr_nzomb        # number of zombie lwps in the process 
    int     pr_zoneid       # zone id 
    int     pr_filler[15]   # reserved for future use 
#NOTE lwpstatus is not supported in this library
    lwpstatus_t pr_lwp      # status of the representative lwp 

#
# process status file.  /proc/<pid>/lwp/<lwpid>/lwpsinfo
#
ctypedef struct lwpsinfo_t:
    int     pr_flag          # lwp flags (DEPRECATED; do not use) 
    int     pr_lwpid         # lwp id 
    unsigned int pr_addr     # internal address of lwp 
    unsigned int pr_wchan    # wait addr for sleeping lwp 
    char    pr_stype         # synchronization event type 
    char    pr_state         # numeric lwp state 
    char    pr_sname         # printable character for pr_state 
    char    pr_nice          # nice for cpu usage 
    short   pr_syscall       # system call number (if in syscall) 
    char    pr_oldpri        # pre-SVR4, low value is high priority 
    char    pr_cpu           # pre-SVR4, cpu usage for scheduling 
    int     pr_pri           # priority, high value is high priority 
                    # The following percent number is a 16-bit binary 
                    # fraction [0 .. 1] with the binary point to the 
                    # right of the high-order bit (1.0 == 0x8000) 
    unsigned short pr_pctcpu # % of recent cpu time used by this lwp 
    unsigned short pr_pad 
    timestruc_t pr_start     # lwp start time, from the epoch 
    timestruc_t pr_time      # usr+sys cpu time for this lwp 
    char    pr_clname[PRCLSZ]       # scheduling class name 
    char    pr_name[PRFNSZ]         # name of system lwp 
    int     pr_onpro         # processor which last ran this lwp 
    int     pr_bindpro       # processor to which lwp is bound 
    int     pr_bindpset      # processor set to which lwp is bound 
    int     pr_lgrp          # lwp home lgroup 
    int     pr_filler[4]     # reserved for future use 

#
# process status file.  /proc/<pid>/psinfo
#
ctypedef struct psinfo_t:
    int     pr_flag         # process flags (DEPRECATED; do not use) 
    int     pr_nlwp         # number of active lwps in the process 
    unsigned int pr_pid     # unique process id 
    unsigned int pr_ppid    # process id of parent 
    unsigned int pr_pgid    # pid of process group leader 
    unsigned int pr_sid     # session id 
    unsigned int pr_uid     # real user id 
    unsigned int pr_euid    # effective user id 
    unsigned int pr_gid     # real group id 
    unsigned int pr_egid    # effective group id 
    unsigned int pr_addr    # address of process 
    size_t  pr_size         # size of process image in Kbytes 
    size_t  pr_rssize       # resident set size in Kbytes 
    size_t  pr_pad1
    unsigned long pr_ttydev # controlling tty device (or PRNODEV) 
                    # The following percent numbers are 16-bit binary 
                    # fractions [0 .. 1] with the binary point to the 
                    # right of the high-order bit (1.0 == 0x8000) 
    unsigned short pr_pctcpu     # % of recent cpu time used by all lwps 
    unsigned short pr_pctmem     # % of system memory used by process 
    timestruc_t pr_start    # process start time, from the epoch 
    timestruc_t pr_time     # usr+sys cpu time for this process 
    timestruc_t pr_ctime    # usr+sys cpu time for reaped children 
    char    pr_fname[PRFNSZ]       # name of execed file 
    char    pr_psargs[PRARGSZ]     # initial characters of arg list 
    int     pr_wstat        # if zombie, the wait() status 
    int     pr_argc         # initial argument count 
    unsigned int pr_argv    # address of initial argument vector 
    unsigned int pr_envp    # address of initial environment vector 
    char    pr_dmodel       # data model of the process 
    char    pr_pad2[3]
    int     pr_taskid       # task id 
    int     pr_projid       # project id 
    int     pr_nzomb        # number of zombie lwps in the process 
    int     pr_poolid       # pool id 
    int     pr_zoneid       # zone id 
    int     pr_contract     # process contract 
    int     pr_filler[1]    # reserved for future use 
    lwpsinfo_t pr_lwp       # information for representative lwp 

#</workaround definitions>

import os   # os is fast enough and convienent
import sys  # used by a decorator to pull the exception off the stack
import time # time is implemented in C so it's fast enough
# psutil helper libraries
import _psutil_posix
from psutil._common import *
from psutil import _psposix
from psutil.error import AccessDenied, NoSuchProcess

################################################################################
# internal utility functions
################################################################################
INVALID_ADDRESS=<uintptr_t>-1
cdef uintptr_t P2ALIGN(uintptr_t x, uintptr_t align):
    """power of 2 alignment"""
    return x & -(align)

cdef bint addr_in_range(uintptr_t start, uintptr_t end, size_t size):
    """check address ranges for sanity"""
    if start != INVALID_ADDRESS or end != INVALID_ADDRESS:
        if start != INVALID_ADDRESS and end < P2ALIGN(start, size):
            return False
        if end != INVALID_ADDRESS and start > P2ALIGN(end + size, size):
            return False
    return True # address is in range

cdef object toaddr(uintptr_t start, uintptr_t end):
    """make a printable address range"""
    #strip off long character if it ends up tacked on.
    return '%s-%s' % (hex(start)[2:].strip('L'), hex(end)[2:].strip('L'))

cdef object timestruc2epoch(timestruc_t *t):
    """make a timestruct_t equivalent to time.time()"""
    n = t.tv_nsec
    n *= 0.000000001
    n += t.tv_sec
    return n

cdef object timeval2epoch(struct_timeval t):
    """make a struct timeval equivalent to time.time()"""
    n = t.tv_usec
    n *= 0.000000001
    n += t.tv_sec
    return n

cdef const_char *make_resource(int pid, char *r):
    """represent a proc resource file as a const char*"""
    cdef char *foo
    x = "/proc/%d/%s" % (pid, r)
    foo = x # tmp variable needed for coersion
    return <const_char *>foo

cdef int snapshot(const_char *f, void *data, size_t size) nogil:
    """reads a proc file into a structure pointer. on success returns 0
       on failure returns a positive value corresponding to errno.
    """
    cdef FILE *fp
    cdef int error = 0

    fp = fopen(f, "rb")
    error = errno

    if fp is NULL:
       if not error: # might occur in a thread
           error = EINVAL #most logical explanation
       return error

    error = 0
    while not feof(fp):
        fread(data, size, 1, fp)
        if ferror(fp) and not feof(fp):
            error = ferror(fp)
            break

    fflush(fp)
    fclose(fp)
    return error

cdef object _io_tuple(kstat_io_t *k):
    """converts kstat_io_t to a tuple"""
    return (k.reads, k.writes, k.nread, k.nwritten, k.rtime, k.wtime)

cdef object _kstat_named(kstat_named_t *k):
    """pulls the right union value out of the kstat_named_t pointer"""
    if k.data_type == KSTAT_DATA_CHAR:
        return k.value.c
    elif k.data_type == KSTAT_DATA_INT32:
        return k.value.i32
    elif k.data_type == KSTAT_DATA_UINT32:
        return k.value.ui32
    elif k.data_type == KSTAT_DATA_INT64:
        return k.value.i64
    elif k.data_type == KSTAT_DATA_UINT64:
        return k.value.ui64
    raise ValueError('could not decode kstat_named_t')

################################################################################
# Solaris Implementation
################################################################################

def _wrap_error(func):
    """Call func into a try/except clause and translate ENOENT,
    EACCES and EPERM in NoSuchProcess or AccessDenied exceptions.
    """
    def decorator(self, *args, **kwargs):
        """this is a decorator, but you knew that"""
        try:
            return func(self, *args, **kwargs)
        except (IOError, OSError, EnvironmentError):
            # best of my knowledge this gettattr is overkill
            error = getattr(sys.exc_info()[1], 'errno', -1)
            if error in (ENOENT, ESRCH):
                raise NoSuchProcess(self.pid, self._process_name)
            if error in (EPERM, EACCES):
                raise AccessDenied(self.pid, self._process_name)
            raise
    return decorator

#TODO wrap all exceptions
cdef class Process:
    """Solaris process implementation."""

    # By default, extention types do not support having weak references made to 
    # them.  So we are enabling it by default, in the event it may be needed.
    cdef object __weakref__
    cdef object __pname__
    cdef object _tstamp
    cdef object _cmdline
    cdef object _name
    cdef object _exe
    cdef object _start
    cdef object _env
    cdef long _inode
    cdef int _pid
    cdef pstatus_t *status
    cdef psinfo_t *process
    cdef const_char *cwd
    cdef const_char *fd
    cdef const_char *lwpd

    property _process_name:
        """used by the psutil implementation"""
        def __get__(self):
            return self.__pname__
        def __set__(self, value):
            self.__pname__ = value
        def __del__(self):
            return

    property pid:
        """process id"""
        def __get__(self):
            return self._pid
        def __set__(self, value):
            return #ignored
        def __del__(self):
            return

    def __cinit__(self):
        self.process = NULL
        self.status = NULL
        self._tstamp = 0
        self._env = {}

    def __dealloc__(self):
        if self.process is not NULL:
            free(self.process)
        if self.status is not NULL:
            free(self.status)

    def __init__(self, int pid):
        self._pid = pid
        self._inode = os.stat('/proc/%d' % (pid,)).st_ino
        # setup static resources
        self.fd = make_resource(pid, 'fd')
        self.lwpd = make_resource(pid, 'lwp')
        # pre cache some static data
        self._update_info()
        try:
            self._exe = os.readlink('/proc/%d/path/a.out' % (pid,))
        except:
            self._exe = self.process.pr_fname
        self._name = self._exe.split(os.path.sep)[-1]
        self._cmdline = self.process.pr_psargs.split(' ')
        self._start = timestruc2epoch(&self.process.pr_start)

    def is_running(self):
        """track whether this process is still valid"""
        try:
            assert self._inode == os.stat('/proc/%d' % (self._pid,)).st_ino
            assert pid_exists(self._pid)
        except:
            raise NoSuchProcess(self.pid, self._process_name)

    def _update_info(self):
        """updates psinfo_t pointer"""
        cdef int error = 0
        cdef size_t size
        cdef PyThreadState *_save
        cdef psinfo_t pstmp
        self.is_running()
        x = time.time()

        if self.process is not NULL and (x - self._tstamp) <= 1.0:
            return # let the structure be cached for a second

        size = os.stat('/proc/%d/psinfo' % (self._pid,)).st_size 
        _save = PyEval_SaveThread()
        # NOTE snapshot is gil free
        error = snapshot(
            make_resource(self._pid, 'psinfo'), &pstmp, size)
        PyEval_RestoreThread(_save)

        if error:
            if error in (EPERM, EACCES):
                raise AccessDenied(self.pid, self._process_name)
            elif error in (ENOENT, ESRCH):
                raise NoSuchProcess(self.pid, self._process_name)
            raise IOError(error, strerror(error))

        if self.process is not NULL:
            self.process = <psinfo_t *>realloc(
                <void *>self.process, size)
        else:
            self.process = <psinfo_t *>malloc(size)

        if self.process is NULL:
            raise MemoryError()

        self._tstamp = x # update timestamp

        # not sure if the stuctures overlap, so be safe
        self.process = <psinfo_t *>memmove(
            <void *>self.process, &pstmp, size)

    def _update_status(self):
        """updates pstatus_t pointer"""
        cdef int error = 0
        cdef size_t size
        cdef PyThreadState *_save
        cdef pstatus_t pstmp
        self.is_running()
        x = time.time()

        if self.status is not NULL and (x - self._tstamp) <= 1.0:
            return # let the structure be cached for a second

        size = os.stat('/proc/%d/status' % (self._pid,)).st_size 
        _save = PyEval_SaveThread()
        # NOTE snapshot is gil free
        error = snapshot(
            make_resource(self._pid, 'status'), &pstmp, size)
        PyEval_RestoreThread(_save)

        if error:
            if error in (EPERM, EACCES):
                raise AccessDenied(self.pid, self._process_name)
            elif error in (ENOENT, ESRCH):
                raise NoSuchProcess(self.pid, self._process_name)
            raise IOError(error, strerror(error))

        if self.status is not NULL:
            self.status = <pstatus_t *>realloc(
                <void *>self.status, size)
        else:
            self.status = <pstatus_t *>malloc(size)

        if self.status is NULL:
            raise MemoryError()

        self._tstamp = x # update timestamp

        # not sure if the stuctures overlap, so be safe
        self.status = <pstatus_t *>memmove(
            <void *>self.status, &pstmp, size)

    @_wrap_error
    def get_process_ppid(self):
        """returns the process parent id as an int"""
        self._update_info()
        return int(self.process.pr_ppid)

    def get_process_name(self):
        """returns the process name"""
        self.is_running()
        return self._name

    def get_process_exe(self):
        """returns the process executable"""
        self.is_running()
        return self._exe

################################################################################
#TODO we could to this the same way get_process_environ
# potentially getting around the 80 char limit in the
# structure assuming of course we have full read access.
################################################################################
    def get_process_cmdline(self):
        """returns the process cmdline"""
        self.is_running()
        return self._cmdline

    @_wrap_error
    def get_process_status(self):
        """returns the process status"""
        self._update_info()
        return self.process.pr_lwp.pr_sname

    @_wrap_error
    def get_process_nice(self):
        """returns the process nice value"""
        self._update_info()
        return self.process.pr_lwp.pr_nice

    @_wrap_error
    def set_process_nice(self, int value):
        """sets the nice priority of a process"""
        self.is_running()
        cdef int result = setpriority(
            PRIO_PROCESS, self._pid, value
        )
        if result == -1:
            if errno in (EPERM, EACCES):
                raise AccessDenied(self.pid, self._process_name)
            elif errno in (ENOENT, ESRCH):
                raise NoSuchProcess(self.pid, self._process_name)
            raise OSError(errno, strerror(errno))
        # clear the cache check
        self._tstamp = 0
        return result

    cdef prcred_t *_prcred(self):
        """If you use this then you are responsible for freeing memory.
        NULL is returned if you don't have access. Access is only allowed
        by the euid accessing of this process or root."""
        cdef prcred_t *prc
        cdef int error = 0
        cdef PyThreadState *_save
        
        cred = '/proc/%d/cred' % (self._pid,)
        if not os.path.exists(cred):
            return NULL
        if not os.access(cred, os.R_OK):
            return NULL
        # WARNING we are allocating memory
        prc = <prcred_t *>malloc(sizeof(prcred_t))
        if prc is NULL:
            return NULL
        _save = PyEval_SaveThread()
        # NOTE snapshot is gil free
        error = snapshot(
            make_resource(self._pid, 'cred'), prc, sizeof(prcred_t)
        )
        PyEval_RestoreThread(_save)

        if error:
            # free memory on error if applicable
            if prc is not NULL: free(prc)
            return NULL
        # return the allocated pointer
        return prc

    @_wrap_error
    def get_process_uids(self):
        """process uids as a namedtuple"""
        cdef prcred_t *prc
        prc = self._prcred()
        # NOTE this is the only way to get the saved state
        if prc is not NULL:
            result = ntuple_uids(
                int(prc.pr_ruid), int(prc.pr_euid), int(prc.pr_suid))
            free(prc) # DONOT FORGET to manage memory
            return result
        # next best option
        self._update_info()
        return ntuple_uids(
            int(self.process.pr_uid), int(self.process.pr_euid), 0)

    @_wrap_error
    def get_process_gids(self):
        """process gids as a namedtuple"""
        cdef prcred_t *prc
        prc = self._prcred()
        # NOTE this is the only way to get the saved state
        if prc is not NULL:
            result = ntuple_gids(
                int(prc.pr_rgid), int(prc.pr_egid), int(prc.pr_sgid))
            free(prc) # DONOT FORGET to manage memory
            return result
        # next best option
        self._update_info()
        return ntuple_gids(
            int(self.process.pr_gid), int(self.process.pr_egid), 0)

    @_wrap_error
    def get_process_terminal(self):
        """return process controlling terminal or None"""
        self._update_info()
        # no controlling terminal declared, be done
        if self.process.pr_ttydev == PRNODEV: return
        # the link from the std file descriptors should point
        # to the controlling terminal, we give up if this fails.
        for x in (0,1,2,255):
            try:
                return os.readlink(
                    '/proc/%d/path/%d' % (self._pid,x)
                )
            except: pass

    def get_process_create_time(self):
        """process create time"""
        self.is_running()
        return self._start

    @_wrap_error
    def get_process_environ(self):
        """returns a dictionary of environment variables"""
        cdef long offset
        # maximum buffer size, should handle crazy TERMCAP
        cdef long maxsize = 4096
        # maximum environment variables to attempt to retrieve
        cdef char *env[400]
        cdef char *buf
        cdef int i, fd
        cdef size_t result
        # let's see if the process is still valid
        self._update_info()
        asfile = '/proc/%d/as' % (self._pid,)
        # we can only get the initial env, so cache it
        if not self._env:
            buf = <char *>malloc(sizeof(char *) * maxsize)
            if buf is NULL:
                raise MemoryError()
            x = open(asfile)
            fd = x.fileno()
            # get the environment vector offset
            pread(fd, env, 400, self.process.pr_envp)
            for i from 0 <= i < 400:
                result = 0
                if env[i] is not NULL:
                    # reset the buffer to all NULL values
                    memset(<void *>buf, '\0', maxsize)
                    # read env vector information, leave a NULL terminator
                    result = pread(fd, <void *>buf, maxsize - 1, <long>env[i])
                if result > 0 and buf is not NULL:
                    pbuf = buf.split('=')
                    key = pbuf.pop(0)
                    pbuf = '='.join(pbuf)
                    try: # we don't really care about the decode error
                        assert pbuf and key
                        if pbuf.decode('ascii') and key.decode('ascii'):
                            self._env.update({key: pbuf})
                    except: pass # more than likely a UnicodeDecodeError
            free(buf) # don't forget this
            x.close() # or this
        # return the dictionary
        return self._env

    @_wrap_error
    def get_process_cwd(self):
        """process current working directory"""
        self.is_running()
        return os.readlink('/proc/%d/path/cwd' % (self._pid,))

    @_wrap_error
    def get_process_num_threads(self):
        """process thread count"""
        self._update_info()
        return self.process.pr_nlwp

################################################################################
#NOTE we could use POSIX AIO and Event Completion Port Framework.
# If a case existed where we had a ton of threads to inspect
# sequentially and the reads caused a substatial performance
# penality, we could schedule the reads with the kernel via AIO
# and collect the results in one system call. This would require
# a lot of code and would only be a benifit if we needed to inspect
# more that 100 threads (guess).
################################################################################
    @_wrap_error
    def get_process_threads(self):
        """returns the process threads as a namedtuple"""
        cdef PyThreadState *_save
        cdef lwpstatus_t status
        cdef int error
        self.is_running()
        returnlist = []
        lwps = os.listdir('/proc/%d/lwp' % (self._pid,))
        lwps = [ int(x) for x in lwps if x.isdigit() ]
      
        # sequentially inspect the thread status 
        for lwp in lwps:
            s = 'lwp/%d/lwpstatus' % (lwp,)
            _save = PyEval_SaveThread()
            # NOTE snapshot is gil free
            error = snapshot(
                make_resource(self._pid, s),
                <void *>&status,
                sizeof(lwpstatus_t)
            )
            PyEval_RestoreThread(_save)
            if error:
                raise IOError(error, strerror(error))
            utime = timestruc2epoch(&status.pr_utime)
            stime = timestruc2epoch(&status.pr_stime)
            ntuple = ntuple_thread(lwp, utime, stime)
            returnlist.append(ntuple)
        return returnlist

    @_wrap_error
    def get_cpu_times(self):
        """returns the cpu times as a namedtuple"""
        self.is_running() # avoid unnecessary lookups
        try: # only the euid and root can read the status
            self._update_status()
            utime = timestruc2epoch(&self.status.pr_utime) 
            stime = timestruc2epoch(&self.status.pr_stime) 
            return ntuple_cputimes(utime, stime)
        except: pass #try again
        # this allows psutil.test() to function

        # now we will approximate the usage based on percentages known
        self._update_info()
        # get the total times
        times = get_system_cpu_times()
        user = times.user
        sys = times.system
        # percent modifier of recent cpu activity for all lwps of this pid
        pct = float(self.process.pr_pctcpu)/float(0x8000)
        return ntuple_cputimes(user*pct, sys*pct)

    @_wrap_error
    def get_memory_info(self):
        """returns memory usage as a namedtuple"""
        self._update_info()
        # memory is in KB on solaris
        return ntuple_meminfo(
            int(self.process.pr_rssize) * 1024,
            int(self.process.pr_size) * 1024
        )

################################################################################
# Start Memory Mapping Code
#
# Needs verification that it is working correctly.
# 
# NOTE: The following is for reference only.
# http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/cmd/ptools/pmap
################################################################################
    _mmap_base_fields = ['path', 'rss', 'size', 'offset', 'anonymous', 
                         'locked', 'swap']
    nt_mmap_grouped = namedtuple('mmap', ' '.join(_mmap_base_fields))
    nt_mmap_ext = namedtuple('mmap', 'addr perms ' + ' '.join(_mmap_base_fields))

    cdef object _get_mem_name(self, prxmap_t *p):
        """name the memory map"""
        cdef int _p = self._pid
        cdef dev_t dev
        cdef ino_t ino
        vaddr_sz = p.pr_vaddr + p.pr_size
        brk_base_sz = self.status.pr_brkbase + self.status.pr_brksize
        # attempt to get the name of the resource
        if not (p.pr_mflags & MA_ANON) or vaddr_sz <= self.status.pr_brkbase \
                or p.pr_vaddr >= brk_base_sz:
            try: return os.readlink('/proc/%d/path/%s' % (_p, p.pr_mapname))
            except: pass
            # fallback to the object information
            try:
                x = os.stat('/proc/%d/object/%s' % (_p, p.pr_mapname))
                dev = x.st_dev
                ino = x.st_ino
                return "dev:%d,%d ino:%d" % (major(dev), minor(dev), ino)
            except: pass
        # attempt to get the shared memory names
        if p.pr_mflags & MA_ISM or p.pr_mflags & MA_SHM:
            ismdism = p.pr_mflags & MA_NORESERVE and 'ism' or 'dism'
            if p.pr_shmid == -1:
                return '[%s shmid=null]' % (ismdism,)
            return '[%s shmid=0x%x]' % (ismdism, p.pr_shmid)
        # add the stack base and size
        stk_base_sz = self.status.pr_stkbase + self.status.pr_stksize
        if vaddr_sz > self.status.pr_stkbase and p.pr_vaddr < stk_base_sz:
            return '[stack]'
        elif p.pr_mflags & MA_ANON and vaddr_sz > self.status.pr_brkbase \
                and p.pr_vaddr < brk_base_sz:
            return '[heap]'
#TODO '[%s tid=%d]' #requires examining stackspace
        return '[anon]'

    cdef object _get_perms(self, prxmap_t *p):
        """create the permission string 'rwxsR'"""
        result = ""
        result += p.pr_mflags & MA_READ and 'r' or '-'
        result += p.pr_mflags & MA_WRITE and 'w' or '-'
        result += p.pr_mflags & MA_EXEC and 'x' or '-'
        result += p.pr_mflags & MA_SHARED and 's' or '-'
        result += p.pr_mflags & MA_NORESERVE and 'R' or '-'
        result += p.pr_mflags & MA_RESERVED1 and '*' or '-'
        return result

    cdef ulong_t _get_swap(self, prxmap_t *p):
        """used to calculate where swap is being used"""
        if p.pr_mflags & MA_SHARED|MA_NORESERVE and p.pr_pagesize:
            # swap reserved for entire non-ism SHM
            return p.pr_size / p.pr_pagesize
        elif p.pr_mflags & MA_NORESERVE:
            # swap reserved on fault for each anon page
            return p.pr_anon
        elif p.pr_mflags & MA_WRITE and p.pr_pagesize:
            # swap reserved for entire writable segment
            return p.pr_size / p.pr_pagesize
        return 0

    @_wrap_error
    def get_memory_maps(self):
        """returns the memory maps as a namedtuple"""
        # may raise an access error
        cdef prxmap_t *xmap, *p
        cdef size_t size, nread
        cdef int nmap, fd
        self._update_status()

        m = '/proc/%d/xmap' % (self._pid,)
        size = os.stat(m).st_size
        x = open(m, 'rb')
        fd = x.fileno()
        xmap = <prxmap_t *>malloc(size)

        if xmap is NULL:
            x.close()
            raise MemoryError()

        nread = pread(fd, xmap, size, 0)
        # close file
        x.close()
        if nread < 0:
            free(xmap)
            raise IOError(errno, strerror(errno))

        nmap = nread / sizeof(prxmap_t)

        p = xmap
        returnlist = []
        # interate through the map
        while nmap:
            nmap -= 1
            if p is NULL:
                p += 1
                continue
            # make sure the address is within range
            pr_addr_sz = p.pr_vaddr + p.pr_size
            if not addr_in_range(p.pr_vaddr, pr_addr_sz, p.pr_pagesize):
                p += 1
                continue
            
            returnlist.append(tuple([
                toaddr(p.pr_vaddr, pr_addr_sz),
                self._get_perms(p),
                self._get_mem_name(p),
                p.pr_rss * p.pr_pagesize,
                p.pr_size,
                p.pr_offset,
                p.pr_anon * p.pr_pagesize,
                p.pr_locked * p.pr_pagesize,
                self._get_swap(p),
            ]))
            # increment pointer
            p += 1

        free(xmap)
        return returnlist
################################################################################
# End Memory Mapping Code
################################################################################

    @_wrap_error
    def get_open_files(self):
        """returns a namedtuple of open files"""
        self.is_running()
        retlist = []
        # use fd for filedescriptor list
        base = '/proc/%d/fd' % (self._pid,)
        # use path to decode links
        path = '/proc/%d/path' % (self._pid,)
        for link in os.listdir(base):
            retlist.append(
                ntuple_openfile(
                    os.readlink(
                        "%s/%s" % (path, link)
                    ),
                    int(link)
                )
            )
        return retlist

# TODO i think this would require the use of DTRACE
    def get_connections(self, kind):
        """returns a namedtuple of connections"""
        raise AccessDenied(self.pid, self._process_name)

################################################################################
# API Requirements
################################################################################
def get_pid_list():
    """Returns a list of PIDs currently running on the system."""
    return sorted([ int(i) for i in os.listdir('/proc') ])

def pid_exists(int pid):
    """Check For the existence of a unix pid."""
    return os.path.exists('/proc/%d' % (pid,))

def _cpu_times():
    """generator to yield cpu stats"""
    cdef kstat_ctl_t *kc
    cdef kstat_t *ksp
    cdef cpu_stat_t cs

    kc = kstat_open()
    if kc is NULL:
        # gracefully handle this error
        raise StopIteration()
    nice = softirq = 0.0
    # pre load the kstat chain
    ksp = kc.kc_chain
    while ksp is not NULL:
        try:
            assert strcmp(ksp.ks_module, "cpu_stat") == 0
            assert kstat_read(kc, ksp, &cs) != -1
            yield (\
                float(cs.cpu_sysinfo.cpu[CPU_USER]),\
                nice,\
                float(cs.cpu_sysinfo.cpu[CPU_KERNEL]),\
                float(cs.cpu_sysinfo.cpu[CPU_IDLE]),\
                float(cs.cpu_sysinfo.cpu[CPU_WAIT]),\
                float(cs.cpu_sysinfo.cpu[CPU_STATES]),\
                softirq)
        except AssertionError: pass
        ksp = ksp.ks_next
    kstat_close(kc)

def get_system_per_cpu_times():
    """Return a list of namedtuple representing the CPU times
    for every CPU available on the system.
    """
    return [ ntuple_sys_cputimes(*x) for x in _cpu_times() ]

def get_system_cpu_times():
    """Return a named tuple representing the following CPU times:
    user, nice, system, idle, iowait, irq, softirq.  Some stats are
    set to Zero value, because Solaris doesn't provide them.
    """
    return ntuple_sys_cputimes(*[sum(x) for x in zip(*_cpu_times())])

def phymem_usage():
    """Return physical memory usage statistics as a namedutple including
    total, used, free and percent usage.
    """
    # we could have done this with kstat, but imho this is good enough
    total = sysconf(_SC_PHYS_PAGES) # it is possible to exceed 32bit int
    total *= sysconf(_SC_PAGE_SIZE)
    free = sysconf(_SC_AVPHYS_PAGES) # it is possible to exceed 32bit int
    free *= sysconf(_SC_PAGE_SIZE)
    used = total - free
    percent = usage_percent(used, total, _round=1)
    return ntuple_sysmeminfo(int(total), int(used), int(free), percent)

def virtmem_usage():
    """Return virtual memory usage statistics as a namedutple including
    total, used, free and percent usage.
    """
    cdef kstat_ctl_t *kc
    cdef kstat_t *ksp
    cdef vminfo_t vm

    free = 0
    used = 0

    kc = kstat_open()
    if kc is NULL: return
    # pre load the kstat chain
    ksp = kc.kc_chain
    while ksp is not NULL:
        try:
            assert ksp.ks_type == KSTAT_TYPE_RAW
            assert strcmp(ksp.ks_class, "vm") == 0
            assert kstat_read(kc, ksp, &vm) != -1
            free += vm.swap_free
            used += (vm.swap_alloc + vm.swap_resv)
        except AssertionError: pass
        ksp = ksp.ks_next

    kstat_close(kc)
    total = free + used
    percent = usage_percent(used, total, _round=1)
    return ntuple_sysmeminfo(total, used, free, percent) 

def disk_partitions(all=False):
    """Return mounted disk partitions as a list of nameduples"""
    cdef FILE *fp
    cdef struct_mnttab mt
    fp = fopen(<const_char *>MNTTAB, "rb")
    if fp is NULL:
        if errno:
            raise IOError(errno, strerr(errno))
        raise MemoryError()
    
    retlist = [] 
    while getmntent(fp, &mt) == 0:
        device = mt.mnt_special
        mountpoint = mt.mnt_mountp
        fstype = mt.mnt_fstype
        opts = mt.mnt_mntopts
        if device == '-':
            device = ''
        if not all:
            if not device: continue 
        ntuple = ntuple_partition(device, mountpoint, fstype, opts)
        retlist.append(ntuple)
    fclose(fp)
    return retlist

get_disk_usage = _psposix.get_disk_usage

def network_io_counters():
    """Return network I/O statistics for every network interface
    installed on the system as a dict of raw tuples.
    """
    cdef kstat_ctl_t *kc
    cdef kstat_t *ksp
    cdef kstat_named_t *knp

    kc = kstat_open()
    if kc is NULL: return
    returndict = {}
    # pre load the kstat chain
    ksp = kc.kc_chain
    while ksp is not NULL:
        try:
            assert ksp.ks_type == KSTAT_TYPE_NAMED
            assert strcmp(ksp.ks_class, "net") == 0
            assert kstat_read(kc, ksp, NULL) != -1
            # real devices end with the instance number
            assert str(ksp.ks_name).endswith(str(ksp.ks_instance))
            # read rx
            knp = <kstat_named_t *>kstat_data_lookup(ksp, "rbytes")
            assert knp is not NULL
            # finish reading rx
            bytes_recv = _kstat_named(knp)
            # read tx
            knp = <kstat_named_t *>kstat_data_lookup(ksp, "obytes")
            assert knp is not NULL
            # finish reading tx
            bytes_sent = _kstat_named(knp)
            # read packets received
            knp = <kstat_named_t *>kstat_data_lookup(ksp, "ipackets")
            assert knp is not NULL
            # finish reading packets received
            packets_recv = _kstat_named(knp)
            # read packets sent
            knp = <kstat_named_t *>kstat_data_lookup(ksp, "opackets")
            assert knp is not NULL
            # finish reading packets sent
            packets_sent = _kstat_named(knp)
            x = (bytes_sent, bytes_recv, packets_sent, packets_recv)
            returndict[ksp.ks_name] = x
        except AssertionError: pass 
        # advance the pointer to the next item
        ksp = ksp.ks_next

    kstat_close(kc)
    return returndict

def disk_io_counters():
    """Return disk I/O statistics for every disk installed on the
    system as a dict of raw tuples.
    """
    cdef kstat_ctl_t *kc
    cdef kstat_t *ksp
    cdef kstat_io_t kio

    kc = kstat_open()
    if kc is NULL: return
    returndict = {}
    # pre load the kstat chain
    ksp = kc.kc_chain
    while ksp is not NULL:
        try:
            assert ksp.ks_type == KSTAT_TYPE_IO
            assert strcmp(ksp.ks_class, "disk") == 0
            assert kstat_read(kc, ksp, &kio) != -1
            returndict[ksp.ks_name] = _io_tuple(&kio)
        except AssertionError: pass
        ksp = ksp.ks_next

    kstat_close(kc)
    return returndict

def get_system_users():
    """Return currently connected users as a list of namedtuples."""
    cdef struct_utmpx *tmp
    #preload utmpx
    tmp = getutxent()
    if tmp is NULL:
        raise IOError(errno, strerror(errno))
    retlist = []
    while tmp is not NULL:
        try:
            #pull out the useful data
            assert strcmp(tmp.ut_user, 'LOGIN') != 0
            _user = tmp.ut_user
            #ignore startup and shutdown records
            assert _user
            _time = timeval2epoch(tmp.ut_tv)
            _host = tmp.ut_host
            if not _host or _host.startswith(':'):
                _host = 'localhost'
            _tty = tmp.ut_line
            abstty = os.path.join('/dev', _tty)
            if os.path.exists(abstty):
                _tty = abstty
            nt = ntuple_user(_user, _tty, _host, _time)
            retlist.append(nt)
        except AssertionError: pass
        #pull next entry
        tmp = getutxent()
    #close this db session
    endutxent()
    return retlist

cdef object _get_boottime():
    """cycle through utmpx to look for the boot time"""
    cdef struct_utmpx *tmp
    tmp = getutxent()
    if tmp is NULL:
        # fallback and ask pid 0 directly
        return Process(0).get_process_create_time()
    boottime = 0
    while tmp is not NULL:
        try:
            assert tmp.ut_type == 2 #define BOOT_TIME
            boottime = timeval2epoch(tmp.ut_tv)
            break # now that we have the boottime we break out
        except AssertionError: pass
        #pull next entry
        tmp = getutxent()
    #close this db session
    endutxent()
    return boottime

# API obligations
BOOT_TIME = _get_boottime()
NUM_CPUS = sysconf(_SC_NPROCESSORS_ONLN)

__extra__all__ = []


################################################################################
# Comments
################################################################################
# Process.get_connections:
#   Getting the connections that a process has may not be possible without
#   using dtrace.  Unfortunately the dtrace CAPI is not stable or completely
#   documented at this time and the dtrace utility can only be used by root
#   or another privledged user id.  For the time being this method will raise
#   an AccessError by default until an appropriate solution can be implemented.
#
################################################################################
# Ideas for Future Solaris Specific Enhancements
################################################################################
#
# http://getthegood.com/TechNotes/Papers/ProcStatistics.html
#
################################################################################
