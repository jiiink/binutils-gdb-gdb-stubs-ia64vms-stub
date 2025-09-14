/* GDB stub for Itanium OpenVMS
   Copyright (C) 2012-2025 Free Software Foundation, Inc.

   Contributed by Tristan Gingold, AdaCore.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* On VMS, the debugger (in our case the stub) is loaded in the process and
   executed (via SYS$IMGSTA) before the main entry point of the executable.
   In UNIX parlance, this is like using LD_PRELOAD and debug via installing
   SIGTRAP, SIGSEGV... handlers.

   This is currently a partial implementation.  In particular, modifying
   registers is currently not implemented, as well as inferior procedure
   calls.

   This is written in very low-level C, in order not to use the C runtime,
   because it may have weird consequences on the program being debugged.
*/

#if __INITIAL_POINTER_SIZE != 64
#error "Must be compiled with 64 bit pointers"
#endif

#define __NEW_STARLET 1
#include <descrip.h>
#include <iledef.h>
#include <efndef.h>
#include <in.h>
#include <inet.h>
#include <iodef.h>
#include <ssdef.h>
#include <starlet.h>
#include <stsdef.h>
#include <tcpip$inetdef.h>

#include <lib$routines.h>
#include <ots$routines.h>
#include <str$routines.h>
#include <libdef.h>
#include <clidef.h>
#include <iosbdef.h>
#include <dvidef.h>
#include <lnmdef.h>
#include <builtins.h>
#include <prtdef.h>
#include <psldef.h>
#include <chfdef.h>

#include <lib_c/imcbdef.h>
#include <lib_c/ldrimgdef.h>
#include <lib_c/intstkdef.h>
#include <lib_c/psrdef.h>
#include <lib_c/ifddef.h>
#include <lib_c/eihddef.h>

#include <stdarg.h>
#include <pthread_debug.h>

#define VMS_PAGE_SIZE 0x2000
#define VMS_PAGE_MASK (VMS_PAGE_SIZE - 1)

/* Declared in lib$ots.  */
extern void ots$fill (void *addr, size_t len, unsigned char b);
extern void ots$move (void *dst, size_t len, const void *src);
extern int ots$strcmp_eql (const void *str1, size_t str1len,
			   const void *str2, size_t str2len);

/* Stub port number.  */
static unsigned int serv_port = 1234;

/* DBGEXT structure.  Not declared in any header.  */
struct dbgext_control_block
{
  unsigned short dbgext$w_function_code;
#define DBGEXT$K_NEXT_TASK	      3
#define DBGEXT$K_STOP_ALL_OTHER_TASKS 31
#define DBGEXT$K_GET_REGS 33
  unsigned short dbgext$w_facility_id;
#define CMA$_FACILITY 64
  unsigned int dbgext$l_status;
  unsigned int dbgext$l_flags;
  unsigned int dbgext$l_print_routine;
  unsigned int dbgext$l_evnt_code;
  unsigned int dbgext$l_evnt_name;
  unsigned int dbgext$l_evnt_entry;
  unsigned int dbgext$l_task_value;
  unsigned int dbgext$l_task_number;
  unsigned int dbgext$l_ada_flags;
  unsigned int dbgext$l_stop_value;
#define dbgext$l_priority   dbgext$l_stop_value;
#define dbgext$l_symb_addr  dbgext$l_stop_value;
#define dbgext$l_time_slice dbgext$l_stop_value;
  unsigned int dbgext$l_active_registers;
};

#pragma pointer_size save
#pragma pointer_size 32

/* Pthread handler.  */
static int (*dbgext_func) (struct dbgext_control_block *blk);

#pragma pointer_size restore

/* Set to 1 if thread-aware.  */
static int has_threads;

/* Current thread.  */
static pthread_t selected_thread;
static pthreadDebugId_t selected_id;

/* Internal debugging flags.  */
struct debug_flag
{
  /* Name of the flag (as a string descriptor).  */
  const struct dsc$descriptor_s name;
  /* Value.  */
  int val;
};

/* Macro to define a debugging flag.  */
#define DEBUG_FLAG_ENTRY(str) \
  { { sizeof (str) - 1, DSC$K_DTYPE_T, DSC$K_CLASS_S, str }, 0}

static struct debug_flag debug_flags[] =
{
  /* Disp packets exchanged with gdb.  */
  DEBUG_FLAG_ENTRY("packets"),
#define trace_pkt (debug_flags[0].val)
  /* Display entry point informations.  */
  DEBUG_FLAG_ENTRY("entry"),
#define trace_entry (debug_flags[1].val)
  /* Be verbose about exceptions.  */
  DEBUG_FLAG_ENTRY("excp"),
#define trace_excp (debug_flags[2].val)
  /* Be verbose about unwinding.  */
  DEBUG_FLAG_ENTRY("unwind"),
#define trace_unwind (debug_flags[3].val)
  /* Display image at startup.  */
  DEBUG_FLAG_ENTRY("images"),
#define trace_images (debug_flags[4].val)
  /* Display pthread_debug info.  */
  DEBUG_FLAG_ENTRY("pthreaddbg")
#define trace_pthreaddbg (debug_flags[5].val)
};

#define NBR_DEBUG_FLAGS (sizeof (debug_flags) / sizeof (debug_flags[0]))

/* Connect inet device I/O channel.  */
static unsigned short conn_channel;

/* Widely used hex digit to ascii.  */
static const char hex[] = "0123456789abcdef";

/* Socket characteristics.  Apparently, there are no declaration for it in
   standard headers.  */
struct sockchar
{
  unsigned short prot;
  unsigned char type;
  unsigned char af;
};

/* Chain of images loaded.  */
extern IMCB* ctl$gl_imglstptr;

/* IA64 integer register representation.  */
union ia64_ireg
{
  unsigned __int64 v;
  unsigned char b[8];
};

/* IA64 register numbers, as defined by ia64-tdep.h.  */
#define IA64_GR0_REGNUM		0
#define IA64_GR32_REGNUM	(IA64_GR0_REGNUM + 32)

/* Floating point registers; 128 82-bit wide registers.  */
#define IA64_FR0_REGNUM		128

/* Predicate registers; There are 64 of these one bit registers.  It'd
   be more convenient (implementation-wise) to use a single 64 bit
   word with all of these register in them.  Note that there's also a
   IA64_PR_REGNUM below which contains all the bits and is used for
   communicating the actual values to the target.  */
#define IA64_PR0_REGNUM		256

/* Branch registers: 8 64-bit registers for holding branch targets.  */
#define IA64_BR0_REGNUM		320

/* Virtual frame pointer; this matches IA64_FRAME_POINTER_REGNUM in
   gcc/config/ia64/ia64.h.  */
#define IA64_VFP_REGNUM		328

/* Virtual return address pointer; this matches
   IA64_RETURN_ADDRESS_POINTER_REGNUM in gcc/config/ia64/ia64.h.  */
#define IA64_VRAP_REGNUM	329

/* Predicate registers: There are 64 of these 1-bit registers.  We
   define a single register which is used to communicate these values
   to/from the target.  We will somehow contrive to make it appear
   that IA64_PR0_REGNUM through IA64_PR63_REGNUM hold the actual values.  */
#define IA64_PR_REGNUM		330

/* Instruction pointer: 64 bits wide.  */
#define IA64_IP_REGNUM		331

/* Process Status Register.  */
#define IA64_PSR_REGNUM		332

/* Current Frame Marker (raw form may be the cr.ifs).  */
#define IA64_CFM_REGNUM		333

/* Application registers; 128 64-bit wide registers possible, but some
   of them are reserved.  */
#define IA64_AR0_REGNUM		334
#define IA64_KR0_REGNUM		(IA64_AR0_REGNUM + 0)
#define IA64_KR7_REGNUM		(IA64_KR0_REGNUM + 7)

#define IA64_RSC_REGNUM		(IA64_AR0_REGNUM + 16)
#define IA64_BSP_REGNUM		(IA64_AR0_REGNUM + 17)
#define IA64_BSPSTORE_REGNUM	(IA64_AR0_REGNUM + 18)
#define IA64_RNAT_REGNUM	(IA64_AR0_REGNUM + 19)
#define IA64_FCR_REGNUM		(IA64_AR0_REGNUM + 21)
#define IA64_EFLAG_REGNUM	(IA64_AR0_REGNUM + 24)
#define IA64_CSD_REGNUM		(IA64_AR0_REGNUM + 25)
#define IA64_SSD_REGNUM		(IA64_AR0_REGNUM + 26)
#define IA64_CFLG_REGNUM	(IA64_AR0_REGNUM + 27)
#define IA64_FSR_REGNUM		(IA64_AR0_REGNUM + 28)
#define IA64_FIR_REGNUM		(IA64_AR0_REGNUM + 29)
#define IA64_FDR_REGNUM		(IA64_AR0_REGNUM + 30)
#define IA64_CCV_REGNUM		(IA64_AR0_REGNUM + 32)
#define IA64_UNAT_REGNUM	(IA64_AR0_REGNUM + 36)
#define IA64_FPSR_REGNUM	(IA64_AR0_REGNUM + 40)
#define IA64_ITC_REGNUM		(IA64_AR0_REGNUM + 44)
#define IA64_PFS_REGNUM		(IA64_AR0_REGNUM + 64)
#define IA64_LC_REGNUM		(IA64_AR0_REGNUM + 65)
#define IA64_EC_REGNUM		(IA64_AR0_REGNUM + 66)

/* NAT (Not A Thing) Bits for the general registers; there are 128 of
   these.  */
#define IA64_NAT0_REGNUM	462

/* Process registers when a condition is caught.  */
struct ia64_all_regs
{
  union ia64_ireg gr[32];
  union ia64_ireg br[8];
  union ia64_ireg ip;
  union ia64_ireg psr;
  union ia64_ireg bsp;
  union ia64_ireg cfm;
  union ia64_ireg pfs;
  union ia64_ireg pr;
};

static struct ia64_all_regs excp_regs;
static struct ia64_all_regs sel_regs;
static pthread_t sel_regs_pthread;

/* IO channel for the terminal.  */
static unsigned short term_chan;

/* Output buffer and length.  */
static char term_buf[128];
static int term_buf_len;

/* Buffer for communication with gdb.  */
static unsigned char gdb_buf[sizeof (struct ia64_all_regs) * 2 + 64];
static unsigned int gdb_blen;

/* Previous primary handler.  */
static void *prevhnd;

/* Entry point address and bundle.  */
static unsigned __int64 entry_pc;
static unsigned char entry_saved[16];

/* Write on the terminal.  */

#include <errno.h>
#include <stdio.h>

static void term_raw_write(const char *str, unsigned int len) {
    unsigned short status;
    struct _iosb iosb;

    if (str == NULL) {
        fputs("Invalid argument: str is NULL\n", stderr);
        return;
    }

    status = sys$qiow(EFN$C_ENF, term_chan, IO$_WRITEVBLK, &iosb, 0, 0, (void *)str, len, 0, 0, 0, 0);

    if (!(status & STS$M_SUCCESS)) {
        fputs("Error: sys$qiow failed\n", stderr);
        errno = status;
        return;
    }

    status = iosb.iosb$w_status;
    if (!(status & STS$M_SUCCESS)) {
        fputs("Error: I/O operation unsuccessful\n", stderr);
        LIB$SIGNAL(status);
    }
}

/* Flush the term buffer.  */

static void term_flush(void) {
    if (term_buf_len == 0) return;
    if (term_raw_write(term_buf, term_buf_len) != 0) {
        // Handle error appropriately (logging, retry, etc.)
        return;
    }
    term_buf_len = 0;
}

/* Write a single character, without translation.  */

static void term_raw_putchar(char c) {
    if (term_buf_len >= sizeof(term_buf)) {
        term_flush();
    }
    if (term_buf_len < sizeof(term_buf)) {
        term_buf[term_buf_len++] = c;
    }
}

/* Write character C.  Translate '\n' to '\n\r'.  */

static void term_putc(char c) {
    if (c < 32) {
        if (c != '\r' && c != '\n') {
            c = '.';
        }
    }
    term_raw_putchar(c);
    if (c == '\n') {
        term_raw_putchar('\r');
        term_flush();
    }
}

/* Write a C string.  */

#include <stddef.h>

static void term_puts(const char *str) {
    if (str == NULL) {
        return;
    }

    for (; *str != '\0'; ++str) {
        term_putc(*str);
    }
}

/* Write LEN bytes from STR.  */

#include <stddef.h>

static void term_write(const char *str, unsigned int len) {
    if (str == NULL) {
        return;
    }
    
    for (size_t i = 0; i < len; i++) {
        term_putc(str[i]);
    }
}

/* Write using FAO formatting.  */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static void term_fao(const char *str, unsigned int str_len, ...) {
    va_list vargs;
    int i;
    long long *args;
    int status;
    struct dsc$descriptor_s dstr = {str_len, DSC$K_DTYPE_T, DSC$K_CLASS_S, (__char_ptr32)str};
    char buf[128];
    $DESCRIPTOR(buf_desc, buf);

    va_start(vargs, str_len);
    int cnt = va_arg(vargs, int) - 2;
    args = malloc(cnt * sizeof(long long));
    if (!args) {
        va_end(vargs);
        return;
    }

    for (i = 0; i < cnt; i++) {
        args[i] = va_arg(vargs, long long);
    }

    status = sys$faol_64(&dstr, &buf_desc.dsc$w_length, &buf_desc, args);
    free(args);

    if (status & 1) {
        for (i = 0; i < buf_desc.dsc$w_length; i++) {
            term_raw_putchar(buf[i]);
            if (buf[i] == '\n') {
                term_flush();
            }
        }
    }

    va_end(vargs);
}

#define TERM_FAO(STR, ...) term_fao (STR, sizeof (STR) - 1, __VA_ARGS__)

/* New line.  */

static void term_putnl(void) {
    term_putc('\n');
}

/* Initialize terminal.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUCCESS(status) ((status & STS$M_SUCCESS) != 0)

static void handle_error(unsigned int status) {
    LIB$SIGNAL(status);
    exit(EXIT_FAILURE);
}

static void term_init(void) {
    unsigned int status;
    unsigned short len;
    char resstring[LNM$C_NAMLENGTH];
    static const $DESCRIPTOR(tabdesc, "LNM$FILE_DEV");
    static const $DESCRIPTOR(logdesc, "SYS$OUTPUT");
    $DESCRIPTOR(term_desc, resstring);
    ILE3 item_lst[2] = {0};

    item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
    item_lst[0].ile3$w_code = LNM$_STRING;
    item_lst[0].ile3$ps_bufaddr = resstring;
    item_lst[0].ile3$ps_retlen_addr = &len;

    status = SYS$TRNLNM(0, (void *)&tabdesc, (void *)&logdesc, 0, item_lst);
    if (!SUCCESS(status)) {
        handle_error(status);
    }

    term_desc.dsc$w_length = len;
    if (resstring[0] == 0x1B) {
        term_desc.dsc$w_length -= 4;
        term_desc.dsc$a_pointer += 4;
    }

    status = sys$assign(&term_desc, &term_chan, 0, 0);
    if (!SUCCESS(status)) {
        handle_error(status);
    }
}

/* Convert from native endianness to network endianness (and vice-versa).  */

#include <stdint.h>

static uint16_t wordswap(uint16_t v) {
    return (v << 8) | (v >> 8);
}

/* Initialize the socket connection, and wait for a client.  */

#include <stdbool.h>

static bool perform_qiow(unsigned short channel, unsigned int func_code, struct _iosb* iosb, unsigned long long p1) {
    unsigned int status = sys$qiow(EFN$C_ENF, channel, func_code, iosb, 0, 0, 0, 0, p1, 0, 0, 0);
    if (status & STS$M_SUCCESS)
        status = iosb->iosb$w_status;
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
        return false;
    }
    return true;
}

static bool assign_channel(const struct dsc$descriptor_s* device, unsigned short* channel) {
    unsigned int status = sys$assign((void *)device, channel, 0, 0);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
        return false;
    }
    return true;
}

static void sock_init(void) {
    struct _iosb iosb;

    unsigned short listen_channel;
    struct sockchar listen_sockchar = {TCPIP$C_TCP, TCPIP$C_STREAM, TCPIP$C_AF_INET};

    unsigned short conn_channel;

    int optval = 1;
    ILE2 reuseaddr_itemlst = {sizeof(optval), TCPIP$C_REUSEADDR, &optval};
    ILE2 sockopt_itemlst = {sizeof(reuseaddr_itemlst), TCPIP$C_SOCKOPT, &reuseaddr_itemlst};

    struct sockaddr_in serv_addr = {TCPIP$C_AF_INET, wordswap(serv_port), TCPIP$C_INADDR_ANY};

    ILE2 serv_itemlst = {sizeof(serv_addr), TCPIP$C_SOCK_NAME, &serv_addr};

    ILE3 cli_itemlst;
    unsigned short cli_addrlen;
    struct sockaddr_in cli_addr;

    static const $DESCRIPTOR(inet_device, "TCPIP$DEVICE:");

    if (!assign_channel(&inet_device, &listen_channel) || !assign_channel(&inet_device, &conn_channel)) {
        term_puts("Failed to assign I/O channel(s)\n");
        return;
    }

    if (!perform_qiow(listen_channel, IO$_SETMODE, &iosb, (unsigned long long)&listen_sockchar)) {
        term_puts("Failed to create socket\n");
        return;
    }

    if (!perform_qiow(listen_channel, IO$_SETMODE, &iosb, (unsigned long long)&sockopt_itemlst)) {
        term_puts("Failed to set socket option\n");
        return;
    }

    ots$fill(&serv_addr, sizeof(serv_addr), 0);

    if (!perform_qiow(listen_channel, IO$_SETMODE, &iosb, (unsigned long long)&serv_itemlst)) {
        term_puts("Failed to bind socket\n");
        return;
    }

    if (!perform_qiow(listen_channel, IO$_SETMODE, &iosb, 1)) {
        term_puts("Failed to set socket passive\n");
        return;
    }

    TERM_FAO("Waiting for a client connection on port: !ZW!/", wordswap(serv_addr.sin_port));

    if (!perform_qiow(listen_channel, IO$_ACCESS | IO$M_ACCEPT, &iosb, (unsigned long long)&conn_channel)) {
        term_puts("Failed to accept client connection\n");
        return;
    }

    cli_itemlst = (ILE3){sizeof(cli_addr), TCPIP$C_SOCK_NAME, &cli_addr, &cli_addrlen};
    ots$fill(&cli_addr, sizeof(cli_addr), 0);

    if (!perform_qiow(conn_channel, IO$_SENSEMODE, &iosb, (unsigned long long)&cli_itemlst)) {
        term_puts("Failed to get client name\n");
        return;
    }

    TERM_FAO("Accepted connection from host: !UB.!UB,!UB.!UB, port: !UW!/",
            (cli_addr.sin_addr.s_addr >> 0) & 0xff,
            (cli_addr.sin_addr.s_addr >> 8) & 0xff,
            (cli_addr.sin_addr.s_addr >> 16) & 0xff,
            (cli_addr.sin_addr.s_addr >> 24) & 0xff,
            wordswap(cli_addr.sin_port));
}

/* Close the socket.  */

#include <stdio.h>

#define SUCCESS(status) ((status) & STS$M_SUCCESS)

static void print_error_and_signal(const char *message, unsigned int status) {
    term_puts(message);
    LIB$SIGNAL(status);
}

static void sock_close(void) {
    struct _iosb iosb;
    unsigned int status;

    status = sys$qiow(EFN$C_ENF, conn_channel, IO$_DEACCESS, &iosb, 0, 0, 0, 0, 0, 0, 0, 0);

    if (!SUCCESS(status)) {
        print_error_and_signal("Failed to close socket\n", status);
    } else if (!SUCCESS(iosb.iosb$w_status)) {
        print_error_and_signal("Failed to close socket\n", iosb.iosb$w_status);
    }

    status = sys$dassgn(conn_channel);

    if (!SUCCESS(status)) {
        print_error_and_signal("Failed to deassign I/O channel\n", status);
    }
}

/* Mark a page as R/W.  Return old rights.  */

#include <stdint.h>
#include <stdbool.h>

#define PSL$C_USER 0
#define PRT$C_UW 0

extern unsigned int SYS$SETPRT_64(void *startva, uint64_t len, int acmode, int flags, void *retva, uint64_t *retlen, unsigned int *oldprot);

static unsigned int page_set_rw(uint64_t startva, uint64_t len, unsigned int *oldprot) {
    uint64_t retva;
    uint64_t retlen;

    return SYS$SETPRT_64((void *)startva, len, PSL$C_USER, PRT$C_UW, (void *)&retva, &retlen, oldprot);
}

/* Restore page rights.  */

static void page_restore_rw(unsigned __int64 startva, unsigned __int64 len, unsigned int prot) {
    unsigned int status;
    unsigned __int64 retva;
    unsigned __int64 retlen;
    unsigned int oldprot;

    status = SYS$SETPRT_64((void *)startva, len, PSL$C_USER, prot, (void *)&retva, &retlen, &oldprot);
    if ((status & STS$M_SUCCESS) == 0) {
        LIB$SIGNAL(status);
    }
}

/* Get the TEB (thread environment block).  */

#include <pthread.h>
#include <ia64intrin.h>

static pthread_t get_teb(void) {
    return (pthread_t)__getReg(_IA64_REG_TP);
}

/* Enable thread scheduling if VAL is true.  */

static unsigned int set_thread_scheduling(int val) {
    if (!dbgext_func) {
        return 0;
    }

    struct dbgext_control_block blk = {
        .dbgext$w_function_code = DBGEXT$K_STOP_ALL_OTHER_TASKS,
        .dbgext$w_facility_id = CMA$_FACILITY,
        .dbgext$l_stop_value = val
    };

    unsigned int status = dbgext_func(&blk);

    if (!(status & STS$M_SUCCESS)) {
        TERM_FAO("set_thread_scheduling error, val=!SL, status=!XL!/", val, blk.dbgext$l_status);
        lib$signal(status);
    }

    return blk.dbgext$l_stop_value;
}

/* Get next thread (after THR).  Start with 0.  */

#include <stdbool.h>

#define SUCCESS_FLAG(status) ((status) & STS$M_SUCCESS)

static unsigned int thread_next(unsigned int thr) {
    struct dbgext_control_block blk;
    unsigned int status;

    if (dbgext_func == NULL) {
        return 0;
    }

    blk.dbgext$w_function_code = DBGEXT$K_NEXT_TASK;
    blk.dbgext$w_facility_id = CMA$_FACILITY;
    blk.dbgext$l_ada_flags = 0;
    blk.dbgext$l_task_value = thr;

    status = dbgext_func(&blk);
    if (!SUCCESS_FLAG(status)) {
        lib$signal(status);
        return 0;
    }

    return blk.dbgext$l_task_value;
}

/* Pthread Debug callbacks.  */

#include <errno.h>

static int read_callback(pthreadDebugClient_t context, pthreadDebugTargetAddr_t addr, pthreadDebugAddr_t buf, size_t size) {
    if (trace_pthreaddbg) {
        TERM_FAO("read_callback (!XH, !XH, !SL)!/", addr, buf, size);
    }

    if (ots$move(buf, size, addr) != 0) {
        return -1;  // Assuming ots$move returns non-zero on error
    }

    return 0;
}

#include <stdio.h>
#include <errno.h>

static int write_callback(pthreadDebugClient_t context, pthreadDebugTargetAddr_t addr, pthreadDebugLongConstAddr_t buf, size_t size) {
    if (trace_pthreaddbg) {
        TERM_FAO("write_callback (0x%lX, 0x%lX, %lu bytes)", addr, buf, size);
    }

    if (addr == NULL || buf == NULL || size == 0) {
        fprintf(stderr, "Invalid parameters: address, buffer, or size is incorrect.\n");
        return -1;
    }

    if (ots$move(addr, size, buf) != 0) {
        fprintf(stderr, "Failed to move data: %s.\n", strerror(errno));
        return -1;
    }
    
    return 0;
}

static int suspend_callback(pthreadDebugClient_t context) {
    return 0;
}

static int resume_callback(pthreadDebugClient_t context)
{
    (void)context; // Suppress unused parameter warning
    return 0;
}

#include <errno.h>

static int kthdinfo_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid, pthreadDebugKThreadInfo_p thread_info) {
    if (trace_pthreaddbg) {
        term_puts("kthinfo_callback");
    }
    return ENOSYS;
}

#include <errno.h>

static int hold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid) {
    if (trace_pthreaddbg) {
        term_puts("hold_callback");
    }
    return ENOSYS;
}

#include <unistd.h>

static int unhold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid) {
    if (trace_pthreaddbg) {
        if (write(STDOUT_FILENO, "unhold_callback\n", 16) == -1) {
            return errno; // Return the current error number if write fails
        }
    }
    return ENOSYS;
}

static int getfreg_callback(__attribute__((unused)) pthreadDebugClient_t context,
                            __attribute__((unused)) pthreadDebugFregs_t *reg,
                            __attribute__((unused)) pthreadDebugKId_t kid) {
    if (trace_pthreaddbg) {
        term_puts("getfreg_callback");
    }
    return ENOSYS;
}

static int setfreg_callback(pthreadDebugClient_t context, const pthreadDebugFregs_t *reg, pthreadDebugKId_t kid) {
  if (trace_pthreaddbg) {
    term_puts("setfreg_callback");
  }
  return ENOSYS;
}

static int getreg_callback(pthreadDebugClient_t context, pthreadDebugRegs_t *reg, pthreadDebugKId_t kid) {
    if (trace_pthreaddbg) {
        term_puts("getreg_callback");
    }
    return ENOSYS;
}

static int setreg_callback(pthreadDebugClient_t context, const pthreadDebugRegs_t *reg, pthreadDebugKId_t kid) {
  if (trace_pthreaddbg) {
    term_puts("setreg_callback");
  }
  return ENOSYS;
}

static int output_callback(pthreadDebugClient_t context, pthreadDebugConstString_t line) {
    if (line == NULL) {
        return -1; // Return an error if the line is null
    }
    term_puts(line);
    term_putnl();
    return 0;
}

static int error_callback(pthreadDebugClient_t context, pthreadDebugConstString_t line) {
    if (line != NULL) {
        term_puts(line);
        term_putnl();
        return 0;
    }
    return -1; // Handle the error case where line is NULL
}

typedef struct {
  // Add necessary fields if applicable
} pthreadDebugClient_t;

typedef char *pthreadDebugAddr_t;

#define STS$M_SUCCESS 0x1 // Define success mask based on specific system

extern unsigned int lib$get_vm(int *len, unsigned int *res, int flag);
extern void LIB$SIGNAL(unsigned int status);
extern void TERM_FAO(const char *format, ...);
extern int trace_pthreaddbg;

pthreadDebugAddr_t malloc_callback(pthreadDebugClient_t caller_context, size_t size) {
  unsigned int status;
  unsigned int res;
  int len = size + 16;

  status = lib$get_vm(&len, &res, 0);

  if ((status & STS$M_SUCCESS) == 0) {
    LIB$SIGNAL(status);
    return NULL; // Ensure function returns NULL on failure
  }

  if (trace_pthreaddbg) {
    TERM_FAO("malloc_callback (%zu) -> %X", size, res);
  }

  *(unsigned int *)res = len;
  return (pthreadDebugAddr_t)(res + 16);
}

#include <pthread.h>
#include <stdio.h>

static void free_callback(pthreadDebugClient_t caller_context, pthreadDebugAddr_t address) {
    unsigned int status;
    unsigned int *res_ptr;
    int len;

    if (address == NULL) {
        fprintf(stderr, "Error: Invalid address\n");
        return;
    }

    res_ptr = (unsigned int *)(address - 16);
    if (!res_ptr) {
        fprintf(stderr, "Error: Invalid address computation\n");
        return;
    }

    len = *res_ptr;
    if (trace_pthreaddbg) {
        TERM_FAO("free_callback (!XA)!/", address);
    }

    status = lib$free_vm(&len, &res_ptr, 0);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
    }
}

static int speckthd_callback(__attribute__((unused)) pthreadDebugClient_t caller_context,
                             __attribute__((unused)) pthreadDebugSpecialType_t type,
                             __attribute__((unused)) pthreadDebugKId_t *kernel_tid)
{
    return ENOTSUP;
}

static pthreadDebugCallbacks_t pthread_debug_callbacks = {
  PTHREAD_DEBUG_VERSION,
  read_callback,
  write_callback,
  suspend_callback,
  resume_callback,
  kthdinfo_callback,
  hold_callback,
  unhold_callback,
  getfreg_callback,
  setfreg_callback,
  getreg_callback,
  setreg_callback,
  output_callback,
  error_callback,
  malloc_callback,
  free_callback,
  speckthd_callback
};

/* Name of the pthread shared library.  */
static const $DESCRIPTOR (pthread_rtl_desc, "PTHREAD$RTL");

/* List of symbols to extract from pthread debug library.  */
struct pthread_debug_entry
{
  const unsigned int namelen;
  const __char_ptr32 name;
  __void_ptr32 func;
};

#define DEBUG_ENTRY(str) { sizeof(str) - 1, str, 0 }

static struct pthread_debug_entry pthread_debug_entries[] = {
  DEBUG_ENTRY("pthreadDebugContextInit"),
  DEBUG_ENTRY("pthreadDebugThdSeqInit"),
  DEBUG_ENTRY("pthreadDebugThdSeqNext"),
  DEBUG_ENTRY("pthreadDebugThdSeqDestroy"),
  DEBUG_ENTRY("pthreadDebugThdGetInfo"),
  DEBUG_ENTRY("pthreadDebugThdGetInfoAddr"),
  DEBUG_ENTRY("pthreadDebugThdGetReg"),
  DEBUG_ENTRY("pthreadDebugCmd")
};

/* Pthread debug context.  */
static pthreadDebugContext_t debug_context;

/* Wrapper around pthread debug entry points.  */

static int pthread_debug_thd_seq_init(pthreadDebugId_t *id) {
    if (pthread_debug_entries[1].func == NULL) {
        return -1; // Return error code if function pointer is NULL
    }
    typedef int (*DebugFunc)(void *, pthreadDebugId_t *);
    DebugFunc func = (DebugFunc)pthread_debug_entries[1].func;
    return func(debug_context, id);
}

#include <stddef.h>

typedef struct {
  void *func;
} pthreadDebugEntry_t;

extern pthreadDebugEntry_t pthread_debug_entries[];
extern void *debug_context;

static int pthread_debug_thd_seq_next(pthreadDebugId_t *id) {
  if (pthread_debug_entries == NULL || id == NULL) {
    return -1; // error handling for NULL pointers
  }

  void *func_ptr = pthread_debug_entries[2].func;
  if (func_ptr == NULL) {
    return -1; // error handling for NULL function pointer
  }

  typedef int (*FuncType)(void *, pthreadDebugId_t *);
  FuncType func = (FuncType)func_ptr;
  
  return func(debug_context, id);
}

#include <stddef.h>

static int pthread_debug_thd_seq_destroy(void) {
  if (pthread_debug_entries[3].func == NULL) {
    return -1; // Return an error code if the function pointer is NULL
  }
  
  int (*func_ptr)(void *) = (int (*)(void *))pthread_debug_entries[3].func;
  return func_ptr(debug_context);
}

#include <stdio.h>

static int pthread_debug_thd_get_info(pthreadDebugId_t id, pthreadDebugThreadInfo_t *info) {
    if (debug_context == NULL || pthread_debug_entries[4].func == NULL) {
        return -1; // Return an error code if any required component is unavailable
    }

    int (*func_ptr)(void*, pthreadDebugId_t, pthreadDebugThreadInfo_t*) = pthread_debug_entries[4].func;
    return func_ptr(debug_context, id, info);
}

static int pthread_debug_thd_get_info_addr(pthread_t thr, pthreadDebugThreadInfo_t *info) {
    if (pthread_debug_entries[5].func == NULL) {
        return -1; // Indicate a failure due to missing function
    }
    typedef int (*DebugFuncType)(void*, pthread_t, pthreadDebugThreadInfo_t*);
    DebugFuncType debugFunc = (DebugFuncType)pthread_debug_entries[5].func;
    return debugFunc(debug_context, thr, info);
}

#include <stddef.h>

typedef struct {
  void *func;
} pthreadDebugEntry_t;

static pthreadDebugEntry_t pthread_debug_entries[7];
typedef int pthreadDebugId_t;
typedef int pthreadDebugRegs_t;

static int pthread_debug_thd_get_reg(pthreadDebugId_t thr, pthreadDebugRegs_t *regs) {
  if (pthread_debug_entries[6].func == NULL) {
    return -1; // Return an appropriate error code if function pointer is NULL
  }

  typedef int (*DebugFuncPtr)(void*, pthreadDebugId_t, pthreadDebugRegs_t*);
  DebugFuncPtr debugFunc = (DebugFuncPtr)pthread_debug_entries[6].func;
  return debugFunc(debug_context, thr, regs);
}

#include <stdio.h>
#include <errno.h>

static int stub_pthread_debug_cmd(const char *cmd) {
    if (cmd == NULL) {
        fprintf(stderr, "Error: Command is NULL\n");
        return EINVAL;
    }
    
    if (pthread_debug_entries[7].func == NULL) {
        fprintf(stderr, "Error: Function not implemented\n");
        return ENOSYS;
    }

    typedef int (*DebugFunc)(void *, const char *);
    DebugFunc debugFunc = (DebugFunc)pthread_debug_entries[7].func;
    return debugFunc(debug_context, cmd);
}

/* Show all the threads.  */

#include <stdio.h>
#include <pthread.h>

static void threads_show(void) {
    pthreadDebugId_t id;
    pthreadDebugThreadInfo_t info;
    int res;

    res = pthread_debug_thd_seq_init(&id);
    if (res != 0) {
        TERM_FAO("seq init failed, res=%d", res);
        return;
    }

    while (pthread_debug_thd_get_info(id, &info) == 0) {
        if (pthread_debug_thd_seq_next(&id) != 0) {
            break;
        }
    }
    
    pthread_debug_thd_seq_destroy();
}

/* Initialize pthread support.  */

#include <stddef.h>

static void threads_init(void) {
    static const $DESCRIPTOR(dbgext_desc, "PTHREAD$DBGEXT");
    static const $DESCRIPTOR(pthread_debug_desc, "PTHREAD$DBGSHR");
    static const $DESCRIPTOR(dbgsymtable_desc, "PTHREAD_DBG_SYMTABLE");

    int status;
    void* dbg_symtable = NULL;
    void* caller_context = NULL;

    status = lib$find_image_symbol((void*)&pthread_rtl_desc, (void*)&dbgext_desc, (int*)&dbgext_func);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
        return;
    }

    status = lib$find_image_symbol((void*)&pthread_rtl_desc, (void*)&dbgsymtable_desc, (int*)&dbg_symtable);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
        return;
    }

    for (size_t i = 0; i < sizeof(pthread_debug_entries) / sizeof(pthread_debug_entries[0]); i++) {
        struct dsc$descriptor_s sym = {
            pthread_debug_entries[i].namelen,
            DSC$K_DTYPE_T, 
            DSC$K_CLASS_S, 
            (void*)pthread_debug_entries[i].name
        };

        status = lib$find_image_symbol((void*)&pthread_debug_desc, (void*)&sym, (int*)&pthread_debug_entries[i].func);
        if (!(status & STS$M_SUCCESS)) {
            lib$signal(status);
            return;
        }
    }

    if (trace_pthreaddbg) {
        TERM_FAO("debug symtable: !XH!/", dbg_symtable);
    }

    status = ((int (*)(void*, void*, void*, void*))pthread_debug_entries[0].func)(&caller_context, &pthread_debug_callbacks, dbg_symtable, &debug_context);
    if (status != 0) {
        TERM_FAO("cannot initialize pthread_debug: !UL!/", status);
        return;
    }

    TERM_FAO("pthread debug done!/", 0);
}

/* Convert an hexadecimal character to a nibble.  Return -1 in case of
   error.  */

static int hex2nibble(unsigned char h) {
    if ((h >= '0' && h <= '9') || (h >= 'A' && h <= 'F') || (h >= 'a' && h <= 'f')) {
        return (h >= '0' && h <= '9') ? h - '0'
             : (h >= 'A' && h <= 'F') ? h - 'A' + 10
             : h - 'a' + 10;
    }
    return -1;
}

/* Convert an hexadecimal 2 character string to a byte.  Return -1 in case
   of error.  */

static int hex2byte(const unsigned char *p) {
    int h = hex2nibble(p[0]);
    int l = hex2nibble(p[1]);

    if (h < 0 || l < 0) {
        return -1;
    }
    return (h << 4) | l;
}

/* Convert a byte V to a 2 character strings P.  */

#include <stddef.h>

#define HEX_SIZE 16

static const char hex[HEX_SIZE] = "0123456789ABCDEF";

static int byte2hex(unsigned char *p, unsigned char v)
{
    if (p == NULL) {
        return -1; // Indicate error due to null pointer
    }
    p[0] = hex[(v >> 4) & 0xF];
    p[1] = hex[v & 0xF];
    return 0; // Indicate success
}

/* Convert a quadword V to a 16 character strings P.  */

static void quad2hex(unsigned char *p, unsigned __int64 v) {
    if (!p) {
        return;
    }
    static const unsigned char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++, v <<= 4) {
        p[i] = hex[(v >> 60) & 0xF];
    }
}

#include <stddef.h>
#include <limits.h>

static void long2pkt(unsigned int v) {
    if (gdb_blen + 8 > SIZE_MAX) return;
    for (int i = 0; i < 8; i++) {
        gdb_buf[gdb_blen + i] = hex[(v >> (28 - 4 * i)) & 0x0f];
    }
    gdb_blen += 8;
}

/* Generate an error packet.  */

#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 256

static char gdb_buf[MAX_BUFFER_SIZE];
static size_t gdb_blen;

static void byte2hex(char *buffer, unsigned int value) {
    snprintf(buffer, 3, "%02X", value & 0xFF);
}

static void packet_error(unsigned int err) {
    if (gdb_blen < MAX_BUFFER_SIZE - 4) {
        gdb_buf[1] = 'E';
        byte2hex(gdb_buf + 2, err);
        gdb_blen = 4;
    }
}

/* Generate an OK packet.  */

static void packet_ok(void) {
    const char ok_message[] = "OK";
    gdb_buf[1] = ok_message[0];
    gdb_buf[2] = ok_message[1];
    gdb_blen = 3;
}

/* Append a register to the packet.  */

static int ireg2pkt(const unsigned char *p) {
    if (!p) return -1; // Error handling for null pointer
    for (int i = 0; i < 8; i++) {
        byte2hex(gdb_buf + gdb_blen, p[i]);
        gdb_blen += 2;
    }
    return 0; // Indicate success
}

/* Append a C string (ASCIZ) to the packet.  */

#include <string.h>
#include <stdio.h>

#define GDB_BUF_SIZE 1024

static int gdb_blen = 0;
static char gdb_buf[GDB_BUF_SIZE];

static void str2pkt(const char *str) {
    if (str == NULL) {
        fprintf(stderr, "Error: Input string is NULL.\n");
        return;
    }
    
    size_t str_len = strlen(str);
    
    if (gdb_blen + str_len >= GDB_BUF_SIZE) {
        fprintf(stderr, "Error: Buffer overflow detected.\n");
        return;
    }
    
    memcpy(&gdb_buf[gdb_blen], str, str_len);
    gdb_blen += str_len;
}

/* Extract a number fro the packet.  */

static unsigned __int64
pkt2val (const unsigned char *pkt, unsigned int *pos)
{
  unsigned __int64 res = 0;
  unsigned int i;

  while (1)
    {
      int r = hex2nibble (pkt[*pos]);

      if (r < 0)
	return res;
      res = (res << 4) | r;
      (*pos)++;
    }
}

/* Append LEN bytes from B to the current gdb packet (encode in binary).  */

static void mem2bin(const unsigned char *b, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        unsigned char current = b[i];
        if (current == '#' || current == '$' || current == '}' || current == '*' || current == 0) {
            if (gdb_blen + 2 >= GDB_BUF_SIZE) {
                // Handle buffer overflow error
                return;
            }
            gdb_buf[gdb_blen++] = '}';
            gdb_buf[gdb_blen++] = current ^ 0x20;
        } else {
            if (gdb_blen >= GDB_BUF_SIZE) {
                // Handle buffer overflow error
                return;
            }
            gdb_buf[gdb_blen++] = current;
        }
    }
}

/* Append LEN bytes from B to the current gdb packet (encode in hex).  */

static void mem2hex(const unsigned char *b, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        if (gdb_blen + 2 > GDB_BUF_SIZE) {
            // Handle buffer overflow error appropriately
            return;
        }
        byte2hex(gdb_buf + gdb_blen, b[i]);
        gdb_blen += 2;
    }
}

/* Handle the 'q' packet.  */

static void handle_q_packet(const unsigned char *pkt, unsigned int pktlen) {
    static unsigned int first_thread;
    static unsigned int last_thread;

    static const char xfer_uib[] = "qXfer:uib:read:";
    static const char qfthreadinfo[] = "qfThreadInfo";
    static const char qsthreadinfo[] = "qsThreadInfo";
    static const char qthreadextrainfo[] = "qThreadExtraInfo,";
    static const char qsupported[] = "qSupported:";

    if (pktlen == 2 && pkt[1] == 'C') {
        gdb_buf[0] = '$';
        gdb_buf[1] = 'Q';
        gdb_buf[2] = 'C';
        gdb_blen = 3;
        if (has_threads)
            long2pkt((unsigned long)get_teb());
        return;
    }

    if (strncmp((const char *)pkt, xfer_uib, sizeof(xfer_uib) - 1) == 0) {
        unsigned __int64 pc;
        unsigned int pos = sizeof(xfer_uib) - 1;
        unsigned int off, len;
        union {
            unsigned char bytes[32];
            struct {
                unsigned __int64 code_start_va;
                unsigned __int64 code_end_va;
                unsigned __int64 uib_start_va;
                unsigned __int64 gp_value;
            } data;
        } uei = {0};
        int res;

        packet_error(0);

        pc = pkt2val(pkt, &pos);
        if (pkt[pos++] != ':' || ((off = pkt2val(pkt, &pos)) != 0) 
            || pkt[pos++] != ',' || ((len = pkt2val(pkt, &pos)) != 0x20) 
            || pkt[pos] != '#') {
            return;
        }

        res = SYS$GET_UNWIND_ENTRY_INFO(pc, &uei.data, 0);
        if (res != SS$_NORMAL) {
            memset(uei.bytes, 0, sizeof(uei.bytes));
        }

        if (trace_unwind) {
            TERM_FAO("Unwind request for !XH, status=!XL, uib=!XQ, GP=!XQ!/",
                     pc, res, uei.data.uib_start_va, uei.data.gp_value);
        }

        gdb_buf[0] = '$';
        gdb_buf[1] = 'l';
        gdb_blen = 2;
        mem2bin(uei.bytes, sizeof(uei.bytes));
        return;
    }

    if (strncmp((const char *)pkt, qfthreadinfo, sizeof(qfthreadinfo) - 1) == 0) {
        gdb_buf[0] = '$';
        gdb_buf[1] = 'm';
        gdb_blen = 2;

        if (!has_threads) {
            gdb_buf[1] = 'l';
            return;
        }
        
        first_thread = thread_next(0);
        last_thread = first_thread;
        long2pkt(first_thread);
        return;
    }

    if (strncmp((const char *)pkt, qsthreadinfo, sizeof(qsthreadinfo) - 1) == 0) {
        gdb_buf[0] = '$';
        gdb_buf[1] = 'm';
        gdb_blen = 2;

        while (dbgext_func) {
            unsigned int res = thread_next(last_thread);
            if (res == first_thread || gdb_blen > sizeof(gdb_buf) - 16) {
                break;
            }

            if (gdb_blen > 2) {
                gdb_buf[gdb_blen++] = ',';
            }

            long2pkt(res);
            last_thread = res;
        }

        if (gdb_blen == 2) {
            gdb_buf[1] = 'l';
        }
        return;
    }

    if (strncmp((const char *)pkt, qthreadextrainfo, sizeof(qthreadextrainfo) - 1) == 0) {
        unsigned int pos = sizeof(qthreadextrainfo) - 1;
        pthreadDebugThreadInfo_t info;
        int res;

        packet_error(0);
        if (!has_threads) return;

        pthread_t thr = (pthread_t)pkt2val(pkt, &pos);
        if (pkt[pos] != '#' || (res = pthread_debug_thd_get_info_addr(thr, &info)) != 0) {
            TERM_FAO("qThreadExtraInfo (!XH) failed: !SL!/", thr, res);
            return;
        }

        gdb_buf[0] = '$';
        gdb_blen = 1;
        mem2hex((const unsigned char *)"VMS-thread", 11);
        return;
    }

    if (strncmp((const char *)pkt, qsupported, sizeof(qsupported) - 1) == 0) {
        gdb_buf[0] = '$';
        gdb_blen = 1;
        str2pkt("qXfer:uib:read+");
        return;
    }

    if (trace_pkt) {
        term_puts("unknown <: ");
        term_write((char *)pkt, pktlen);
        term_putnl();
    }
}

/* Handle the 'v' packet.  */

static int handle_v_packet(const unsigned char *pkt, unsigned int pktlen) {
    static const char vcontq[] = "vCont?";
    const size_t VCONTQ_LEN = sizeof(vcontq) - 1;

    if (pktlen == VCONTQ_LEN && ots$strcmp_eql(pkt, VCONTQ_LEN, vcontq, VCONTQ_LEN)) {
        gdb_buf[0] = '$';
        gdb_blen = 1;
        str2pkt("vCont;c;s");
    } else if (trace_pkt) {
        term_puts("unknown <: ");
        term_write((char *)pkt, pktlen);
        term_putnl();
    }

    return 0;
}

/* Get regs for the selected thread.  */

struct ia64_all_regs *get_selected_regs(void) {
    pthreadDebugRegs_t regs;
    int res;

    if (selected_thread == 0 || selected_thread == get_teb()) {
        return &excp_regs;
    }

    if (selected_thread != sel_regs_pthread) {
        res = pthread_debug_thd_get_reg(selected_id, &regs);
        if (res != 0) {
            return &excp_regs;  // Handle error by returning excp_regs
        }
        sel_regs_pthread = selected_thread;
        sel_regs.gr[1].v = regs.gp;
        sel_regs.gr[4].v = regs.r4;
        sel_regs.gr[5].v = regs.r5;
        sel_regs.gr[6].v = regs.r6;
        sel_regs.gr[7].v = regs.r7;
        sel_regs.gr[12].v = regs.sp;
        sel_regs.br[0].v = regs.rp;
        sel_regs.br[1].v = regs.b1;
        sel_regs.br[2].v = regs.b2;
        sel_regs.br[3].v = regs.b3;
        sel_regs.br[4].v = regs.b4;
        sel_regs.br[5].v = regs.b5;
        sel_regs.ip.v = regs.ip;
        sel_regs.bsp.v = regs.bspstore; // Assume it is correct
        sel_regs.pfs.v = regs.pfs;
        sel_regs.pr.v = regs.pr;
    }

    return &sel_regs;
}

/* Create a status packet.  */

static void packet_status(void) {
    gdb_blen = 0;
    if (has_threads) {
        snprintf(gdb_buf, sizeof(gdb_buf), "$T05thread:%lx;", (unsigned long)get_teb());
        gdb_blen = strlen(gdb_buf);
    } else {
        str2pkt("$S05");
    }
}

/* Return 1 to continue.  */

static int handle_packet(unsigned char *pkt, unsigned int len) {
    unsigned int pos = 1;

    gdb_buf[0] = '$';
    gdb_blen = 1;

    if (len < 1) {
        packet_error(0);
        return 0;
    }

    switch (pkt[0]) {
        case '?':
            if (len == 1) {
                packet_status();
                return 0;
            }
            break;
        case 'c':
            if (len == 1) {
                excp_regs.psr.v &= ~(unsigned __int64)PSR$M_SS;
                return 1;
            }
            break;
        case 'g':
            if (len == 1) {
                unsigned int i;
                struct ia64_all_regs *regs = get_selected_regs();
                unsigned char *p = regs->gr[0].b;

                for (i = 0; i < 8 * 32; i++) {
                    byte2hex(gdb_buf + 1 + 2 * i, p[i]);
                }
                gdb_blen += 2 * 8 * 32;
                return 0;
            }
            break;
        case 'H':
            if (pkt[1] == 'g') {
                handle_Hg_packet(pkt, len, &pos);
            } else if (pkt[1] == 'c' && ((pkt[2] == '-' && pkt[3] == '1' && len == 4) || (pkt[2] == '0' && len == 3))) {
                packet_ok();
            } else {
                packet_error(0);
                return 0;
            }
            break;
        case 'k':
            SYS$EXIT(SS$_NORMAL);
            break;
        case 'm':
            handle_m_packet(pkt, len, &pos);
            break;
        case 'M':
            handle_M_packet(pkt, len, &pos);
            break;
        case 'p':
            handle_p_packet(pkt, len, &pos);
            break;
        case 'q':
            handle_q_packet(pkt, len);
            break;
        case 's':
            if (len == 1) {
                excp_regs.psr.v |= (unsigned __int64)PSR$M_SS;
                return 1;
            }
            break;
        case 'T':
            handle_T_packet(pkt, len, &pos);
            break;
        case 'v':
            return handle_v_packet(pkt, len);
        case 'V':
            if (len > 3 && pkt[1] == 'M' && pkt[2] == 'S' && pkt[3] == ' ') {
                if (has_threads) {
                    pkt[len] = 0;
                    stub_pthread_debug_cmd((char *)pkt + 4);
                    packet_ok();
                } else {
                    packet_error(0);
                }
            }
            break;
        default:
            if (trace_pkt) {
                term_puts("unknown <: ");
                term_write((char *)pkt, len);
                term_putnl();
            }
            break;
    }
    return 0;
}

static void handle_Hg_packet(unsigned char *pkt, unsigned int len, unsigned int *pos) {
    int res;
    unsigned __int64 val;
    pthreadDebugThreadInfo_t info;

    val = pkt2val(pkt, pos);
    if (*pos != len) {
        packet_error(0);
        return;
    }
    if (val == 0) {
        selected_thread = get_teb();
        selected_id = 0;
    } else if (!has_threads) {
        packet_error(0);
        return;
    } else {
        res = pthread_debug_thd_get_info_addr((pthread_t)val, &info);
        if (res != 0) {
            TERM_FAO("qThreadExtraInfo (!XH) failed: !SL!/", val, res);
            packet_error(0);
            return;
        }
        selected_thread = info.teb;
        selected_id = info.sequence;
    }
    packet_ok();
}

static void handle_m_packet(unsigned char *pkt, unsigned int len, unsigned int *pos) {
    unsigned __int64 addr;
    unsigned __int64 paddr;
    unsigned int l;
    unsigned int i;

    addr = pkt2val(pkt, pos);
    if (pkt[*pos] != ',') {
        packet_error(0);
        return;
    }
    (*pos)++;
    l = pkt2val(pkt, pos);
    if (pkt[*pos] != '#') {
        packet_error(0);
        return;
    }

    i = l + (addr & VMS_PAGE_MASK);
    paddr = addr & ~VMS_PAGE_MASK;
    while (1) {
        if (__prober(paddr, 0) != 1) {
            packet_error(2);
            return;
        }
        if (i < VMS_PAGE_SIZE)
            break;
        i -= VMS_PAGE_SIZE;
        paddr += VMS_PAGE_SIZE;
    }

    for (i = 0; i < l; i++)
        byte2hex(gdb_buf + 1 + 2 * i, ((unsigned char *)addr)[i]);
    gdb_blen += 2 * l;
}

static void handle_M_packet(unsigned char *pkt, unsigned int len, unsigned int *pos) {
    unsigned __int64 addr;
    unsigned __int64 paddr;
    unsigned int l;
    unsigned int i;
    unsigned int oldprot;

    addr = pkt2val(pkt, pos);
    if (pkt[*pos] != ',') {
        packet_error(0);
        return;
    }
    (*pos)++;
    l = pkt2val(pkt, pos);
    if (pkt[*pos] != ':') {
        packet_error(0);
        return;
    }
    (*pos)++;
    page_set_rw(addr, l, &oldprot);

    i = l + (addr & VMS_PAGE_MASK);
    paddr = addr & ~VMS_PAGE_MASK;
    while (1) {
        if (__probew(paddr, 0) != 1) {
            page_restore_rw(addr, l, oldprot);
            packet_error(0);
            return;
        }
        if (i < VMS_PAGE_SIZE)
            break;
        i -= VMS_PAGE_SIZE;
        paddr += VMS_PAGE_SIZE;
    }

    for (i = 0; i < l; i++) {
        int v = hex2byte(pkt + *pos);
        *pos += 2;
        ((unsigned char *)addr)[i] = v;
    }

    for (i = 0; i < l; i += 15)
        __fc(addr + i);
    __fc(addr + l);

    page_restore_rw(addr, l, oldprot);
    packet_ok();
}

static void handle_p_packet(unsigned char *pkt, unsigned int len, unsigned int *pos) {
    unsigned int num;
    struct ia64_all_regs *regs = get_selected_regs();

    num = pkt2val(pkt, pos);
    if (*pos != len) {
        packet_error(0);
        return;
    }

    switch (num) {
        case IA64_IP_REGNUM:
            ireg2pkt(regs->ip.b);
            break;
        case IA64_BR0_REGNUM:
            ireg2pkt(regs->br[0].b);
            break;
        case IA64_PSR_REGNUM:
            ireg2pkt(regs->psr.b);
            break;
        case IA64_BSP_REGNUM:
            ireg2pkt(regs->bsp.b);
            break;
        case IA64_CFM_REGNUM:
            ireg2pkt(regs->cfm.b);
            break;
        case IA64_PFS_REGNUM:
            ireg2pkt(regs->pfs.b);
            break;
        case IA64_PR_REGNUM:
            ireg2pkt(regs->pr.b);
            break;
        default:
            TERM_FAO("gdbserv: unhandled reg !UW!/", num);
            packet_error(0);
            return;
    }
}

static void handle_T_packet(unsigned char *pkt, unsigned int len, unsigned int *pos) {
    unsigned __int64 val;
    unsigned int fthr, thr;

    if (!has_threads) {
        packet_ok();
        return;
    }

    val = pkt2val(pkt, pos);
    if (*pos != len)
        return;

    packet_error(0);

    fthr = thread_next(0);
    thr = fthr;
    do {
        if (val == thr) {
            packet_ok();
            return;
        }
        thr = thread_next(thr);
    } while (thr != fthr);
}

/* Raw write to gdb.  */

#include <stdbool.h>

static bool is_success(unsigned int status) {
  return (status & STS$M_SUCCESS) != 0;
}

static void handle_error(unsigned int status) {
  term_puts("Failed to write data to gdb\n");
  LIB$SIGNAL(status);
}

static void sock_write(const unsigned char *buf, int len) {
  struct _iosb iosb;
  unsigned int status;

  status = sys$qiow(EFN$C_ENF, conn_channel, IO$_WRITEVBLK, &iosb, 0, 0, (char *)buf, len, 0, 0, 0, 0);
  
  if (!is_success(status)) {
    handle_error(status);
    return;
  }

  if (!is_success(iosb.iosb$w_status)) {
    handle_error(iosb.iosb$w_status);
  }
}

/* Compute the checksum and send the packet.  */

#include <stdio.h>

static int calculate_checksum(const unsigned char *buffer, unsigned int length) {
    unsigned char checksum = 0;
    for (unsigned int i = 1; i < length; i++) {
        checksum += buffer[i];
    }
    return checksum;
}

static void append_checksum_to_buffer(unsigned char *buffer, unsigned int length, unsigned char checksum) {
    buffer[length] = '#';
    byte2hex(buffer + length + 1, checksum);
}

static void trace_packet(const unsigned char *buffer, unsigned int length) {
    term_puts(">: ");
    term_write((const char *)buffer, length);
    term_putnl();
}

static void send_pkt(void) {
    if (gdb_blen < 2) {
        fprintf(stderr, "Invalid packet length\n");
        return;
    }

    unsigned char chksum = calculate_checksum(gdb_buf, gdb_blen);
    append_checksum_to_buffer(gdb_buf, gdb_blen, chksum);

    if (sock_write(gdb_buf, gdb_blen + 3) < 0) {
        fprintf(stderr, "Failed to send packet\n");
        return;
    }

    if (trace_pkt > 1) {
        trace_packet(gdb_buf, gdb_blen + 3);
    }
}

/* Read and handle one command.  Return 1 is execution must resume.  */

#include <stdbool.h>

static int one_command(void) {
    struct _iosb iosb;
    unsigned int status;
    unsigned int offset = 0, dollars_offset = 0, sharp_offset = 0;
    unsigned int command_offset, command_length;

    while (true) {
        offset = 0;
        while (true) {
            status = sys$qiow(EFN$C_ENF, conn_channel, IO$_READVBLK, &iosb, 0, 0, gdb_buf + offset, sizeof(gdb_buf) - offset, 0, 0, 0, 0);
            if (status & STS$M_SUCCESS) status = iosb.iosb$w_status;
            if (!(status & STS$M_SUCCESS)) {
                term_puts("Failed to read data from connection\n");
                LIB$SIGNAL(status);
            }

            gdb_blen = offset + iosb.iosb$w_bcnt;

            if (offset == 0) {
                for (dollars_offset = 0; dollars_offset < gdb_blen && gdb_buf[dollars_offset] != '$'; dollars_offset++);
                if (dollars_offset >= gdb_blen) {
                    continue;
                }
                for (sharp_offset = dollars_offset + 1; sharp_offset < gdb_blen && gdb_buf[sharp_offset] != '#'; sharp_offset++);
            } else if (sharp_offset >= offset) {
                for (; sharp_offset < gdb_blen && gdb_buf[sharp_offset] != '#'; sharp_offset++);
            }

            if ((sharp_offset + 2) <= gdb_blen) break;

            offset = gdb_blen;
            if (gdb_blen == sizeof(gdb_buf)) {
                offset = 0;
            }
        }

        unsigned char checksum = 0;
        for (unsigned int i = dollars_offset + 1; i < sharp_offset; i++)
            checksum += gdb_buf[i];
        
        if (hex2byte(gdb_buf + sharp_offset + 1) != checksum) {
            term_puts("Discard bad checksum packet\n");
            continue;
        } else {
            sock_write((const unsigned char *)"+", 1);
            break;
        }
    }

    if (trace_pkt > 1) {
        term_puts("<: ");
        term_write((char *)gdb_buf + dollars_offset, sharp_offset - dollars_offset + 1);
        term_putnl();
    }

    command_offset = dollars_offset + 1;
    command_length = sharp_offset - dollars_offset - 1;

    if (handle_packet(gdb_buf + command_offset, command_length) == 1) {
        return 1;
    }

    send_pkt();
    return 0;
}

/* Display the condition given by SIG64.  */

#include <stdbool.h>

static void display_exception(struct chf64$signal_array *sig64, struct chf$mech_array *mech) {
    unsigned int status;
    char message[160];
    unsigned short message_length;
    $DESCRIPTOR(msg_descriptor, message);
    unsigned char out_address[4];

    status = SYS$GETMSG(sig64->chf64$q_sig_name, &message_length, &msg_descriptor, 0, out_address);
    bool success = (status & STS$M_SUCCESS) != 0;

    if (success) {
        char formatted_msg[160];
        unsigned short formatted_msg_length;
        struct dsc$descriptor_s formatted_msg_descriptor = { sizeof(formatted_msg), DSC$K_DTYPE_T, DSC$K_CLASS_S, formatted_msg };
        
        msg_descriptor.dsc$w_length = message_length;
        status = SYS$FAOL_64(&msg_descriptor, &formatted_msg_length, &formatted_msg_descriptor, &sig64->chf64$q_sig_arg1);
        success = (status & STS$M_SUCCESS) != 0;

        if (success) {
            term_write(formatted_msg, formatted_msg_length);
        }
    }

    if (!success) {
        term_puts("no message");
    }
    
    term_putnl();

    if (trace_excp > 1) {
        TERM_FAO(" Frame: !XH, Depth: !4SL, Esf: !XH!/", mech->chf$q_mch_frame, mech->chf$q_mch_depth, mech->chf$q_mch_esf_addr);
    }
}

/* Get all registers from current thread.  */

static void read_all_registers(struct chf$mech_array *mech) {
    if (!mech || !mech->chf$q_mch_esf_addr || !mech->chf$ph_mch_sig64_addr) {
        return; // Error handling for NULL pointers
    }

    struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
    struct chf64$signal_array *sig64 = (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;
    
    if (sig64->chf64$w_sig_arg_count < 2) {
        return; // Error handling for out of bounds access
    }
    
    unsigned int cnt = sig64->chf64$w_sig_arg_count;
    unsigned __int64 pc = (&sig64->chf64$q_sig_name)[cnt - 2];

    excp_regs.ip.v = pc;
    excp_regs.psr.v = intstk->intstk$q_ipsr;

    unsigned __int64 bsp = intstk->intstk$q_bsp;
    unsigned int sof = intstk->intstk$q_ifs & 0x7f;
    unsigned int delta = ((bsp >> 3) & 0x3f) + sof;
    excp_regs.bsp.v = bsp + ((sof + delta / 0x3f) << 3);

    excp_regs.cfm.v = intstk->intstk$q_ifs & 0x3fffffffff;
    excp_regs.pfs.v = intstk->intstk$q_pfs;
    excp_regs.pr.v = intstk->intstk$q_preds;

    unsigned __int64 *gr_values[] = {
        &intstk->intstk$q_gp, &intstk->intstk$q_r2, &intstk->intstk$q_r3,
        &intstk->intstk$q_r4, &intstk->intstk$q_r5, &intstk->intstk$q_r6,
        &intstk->intstk$q_r7, &intstk->intstk$q_r8, &intstk->intstk$q_r9,
        &intstk->intstk$q_r10, &intstk->intstk$q_r11, NULL, &intstk->intstk$q_r13,
        &intstk->intstk$q_r14, &intstk->intstk$q_r15, &intstk->intstk$q_r16,
        &intstk->intstk$q_r17, &intstk->intstk$q_r18, &intstk->intstk$q_r19,
        &intstk->intstk$q_r20, &intstk->intstk$q_r21, &intstk->intstk$q_r22,
        &intstk->intstk$q_r23, &intstk->intstk$q_r24, &intstk->intstk$q_r25,
        &intstk->intstk$q_r26, &intstk->intstk$q_r27, &intstk->intstk$q_r28,
        &intstk->intstk$q_r29, &intstk->intstk$q_r30, &intstk->intstk$q_r31};

    excp_regs.gr[0].v = 0;
    for (int i = 1; i <= 31; ++i) {
        excp_regs.gr[i].v = gr_values[i - 1] ? *gr_values[i - 1] : ((unsigned __int64)intstk + intstk->intstk$l_stkalign);
    }

    unsigned __int64 *br_values[] = {
        &intstk->intstk$q_b0, &intstk->intstk$q_b1, &intstk->intstk$q_b2,
        &intstk->intstk$q_b3, &intstk->intstk$q_b4, &intstk->intstk$q_b5,
        &intstk->intstk$q_b6, &intstk->intstk$q_b7};

    for (int i = 0; i < 8; ++i) {
        excp_regs.br[i].v = br_values[i] ? *br_values[i] : 0;
    }
}

/* Write all registers to current thread.  FIXME: not yet complete.  */

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t v;
} PSR;

typedef struct {
    PSR psr;
} ExcpRegs;

typedef struct {
    uint32_t intstk$q_ipsr;
} Intstk;

typedef struct {
    uintptr_t chf$q_mch_esf_addr;
} MechArray;

extern ExcpRegs excp_regs;

static void write_all_registers(MechArray *mech) {
    if (mech == NULL) {
        return; // Error handling for NULL pointer
    }

    Intstk *intstk = (Intstk *)(mech->chf$q_mch_esf_addr);
    if (intstk == NULL) {
        return; // Error handling for invalid memory address
    }

    intstk->intstk$q_ipsr = excp_regs.psr.v;
}

/* Do debugging.  Report status to gdb and execute commands.  */

static void do_debug(struct chf$mech_array *mech) {
    struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
    unsigned int old_ast = 0;
    unsigned int old_sch = 0;
    unsigned int status;

    status = sys$setast(0);
    if (status == SS$_WASCLR) {
        old_ast = 0;
    } else if (status == SS$_WASSET) {
        old_ast = 1;
    } else {
        lib$signal(status);
    }

    if (has_threads) {
        old_sch = set_thread_scheduling(0);
    }

    read_all_registers(mech);

    packet_status();
    send_pkt();

    while (one_command() == 0);

    write_all_registers(mech);

    if (has_threads) {
        set_thread_scheduling(old_sch);
    }

    status = sys$setast(old_ast);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
    }
}

/* The condition handler.  That's the core of the stub.  */

#include <stddef.h>

static int excp_handler(struct chf$signal_array *sig, struct chf$mech_array *mech) {
  struct chf64$signal_array *sig64 = (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;
  unsigned int code = sig->chf$l_sig_name & STS$M_COND_ID;
  unsigned int cnt = sig64->chf64$w_sig_arg_count;
  unsigned __int64 pc;
  unsigned int ret;
  static int in_handler = 0;

  if (code == (LIB$_KEYNOTFOU & STS$M_COND_ID)) {
    return SS$_RESIGNAL_64;
  }

  in_handler++;
  if (in_handler > 1) {
    TERM_FAO("gdbstub: exception in handler (pc=!XH)!!!/", (&sig64->chf64$q_sig_name)[cnt - 2]);
    sys$exit(sig->chf$l_sig_name);
  }

  pc = (&sig64->chf64$q_sig_name)[cnt - 2];
  if (trace_excp) {
    TERM_FAO("excp_handler: code: !XL, pc=!XH!/", code, pc);
  }

  if (code == (SS$_BREAK & STS$M_COND_ID) && pc == entry_pc && entry_pc != 0) {
    static unsigned int entry_prot;
    if (trace_entry) {
      term_puts("initial entry breakpoint\n");
    }
    page_set_rw(entry_pc, 16, &entry_prot);
    ots$move((void *)entry_pc, 16, entry_saved);
    __fc(entry_pc);
    page_restore_rw(entry_pc, 16, entry_prot);
  }

  switch (code) {
    case SS$_ACCVIO & STS$M_COND_ID:
      if (trace_excp <= 1) {
        display_excp(sig64, mech);
      }
    case SS$_BREAK & STS$M_COND_ID:
    case SS$_OPCDEC & STS$M_COND_ID:
    case SS$_TBIT & STS$M_COND_ID:
    case SS$_DEBUG & STS$M_COND_ID:
      if (trace_excp > 1) {
        int i;
        struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
        display_excp(sig64, mech);
        TERM_FAO(" intstk: !XH!/", intstk);
        for (i = 0; i < cnt + 1; i++) {
          TERM_FAO("   !XH!/", ((unsigned __int64 *)sig64)[i]);
        }
      }
      do_debug(mech);
      ret = SS$_CONTINUE_64;
      break;
    default:
      display_excp(sig64, mech);
      ret = SS$_RESIGNAL_64;
      break;
  }

  in_handler--;
  sel_regs_pthread = 0;
  return ret;
}

/* Setup internal trace flags according to GDBSTUB$TRACE logical.  */

#include <stdbool.h>

#define MAX_LOGICAL_NAME_LENGTH LNM$C_NAMLENGTH
#define MAX_DEBUG_FLAGS NBR_DEBUG_FLAGS

static void safe_LIB$SIGNAL(unsigned int status) {
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
    }
}

static bool is_delimiter(char c) {
    return c == ',' || c == ';';
}

static void handle_unknown_directive(const $DESCRIPTOR *sub_desc) {
    TERM_FAO("GDBSTUB$TRACE: unknown directive !AS!/", sub_desc);
}

static bool compare_and_increment_flag(const $DESCRIPTOR *sub_desc) {
    for (int j = 0; j < MAX_DEBUG_FLAGS; j++) {
        if (str$case_blind_compare(sub_desc, (void *)&debug_flags[j].name) == 0) {
            debug_flags[j].val++;
            return true;
        }
    }
    return false;
}

static void trace_init(void) {
    unsigned int status;
    unsigned short len;
    char resstring[MAX_LOGICAL_NAME_LENGTH];
    static const $DESCRIPTOR(tabdesc, "LNM$DCL_LOGICAL");
    static const $DESCRIPTOR(logdesc, "GDBSTUB$TRACE");
    $DESCRIPTOR(sub_desc, resstring);
    ILE3 item_lst[2] = {
        { .ile3$w_length = MAX_LOGICAL_NAME_LENGTH, .ile3$w_code = LNM$_STRING, .ile3$ps_bufaddr = resstring, .ile3$ps_retlen_addr = &len },
        { .ile3$w_length = 0, .ile3$w_code = 0 }
    };

    status = SYS$TRNLNM(0, (void *)&tabdesc, (void *)&logdesc, 0, &item_lst);
    if (status == SS$_NOLOGNAM) {
        return;
    }
    safe_LIB$SIGNAL(status);

    unsigned int start = 0;
    for (unsigned int i = 0; i <= len; i++) {
        if ((i == len || is_delimiter(resstring[i])) && i != start) {
            sub_desc.dsc$a_pointer = resstring + start;
            sub_desc.dsc$w_length = i - start;

            if (!compare_and_increment_flag(&sub_desc)) {
                handle_unknown_directive(&sub_desc);
            }

            start = i + 1;
        }
    }

    TERM_FAO("GDBSTUB$TRACE=!AD ->", len, resstring);
    for (unsigned int i = 0; i < MAX_DEBUG_FLAGS; i++) {
        if (debug_flags[i].val > 0) {
            TERM_FAO(" !AS=!ZL", &debug_flags[i].name, debug_flags[i].val);
        }
    }
    term_putnl();
}


/* Entry point.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int stub_start(unsigned __int64 *progxfer, void *cli_util, EIHD *imghdr, IFD *imgfile, unsigned int linkflag, unsigned int cliflag) {
    static int initialized = 0;
    int is_attached = va_count() == 4;
    int has_threads = 0;
    unsigned __int64 entry_pc = 0;
    IMCB *imcb;

    if (initialized) {
        term_puts("gdbstub: re-entry\n");
    } else {
        initialized = 1;
    }

    term_init();
    term_puts("Hello from gdb stub\n");
    trace_init();

    if (trace_entry && !is_attached) {
        TERM_FAO("xfer: !XH, imghdr: !XH, ifd: !XH!/", progxfer, imghdr, imgfile);
        for (int i = -2; i < 8; i++) {
            TERM_FAO("  at !2SW: !XH!/", i, progxfer[i]);
        }
    }

    if (!is_attached) {
        for (int i = 0; progxfer[i]; i++) {
            entry_pc = progxfer[i];
        }

        if (trace_entry) {
            if (entry_pc == 0) {
                term_puts("No entry point\n");
                return 0;
            } else {
                TERM_FAO("Entry: !XH!/", entry_pc);
            }
        }
    } else {
        entry_pc = progxfer[0];
    }

    for (imcb = ctl$gl_imglstptr->imcb$l_flink; imcb != ctl$gl_imglstptr; imcb = imcb->imcb$l_flink) {
        if (ots$strcmp_eql(pthread_rtl_desc.dsc$a_pointer, pthread_rtl_desc.dsc$w_length, imcb->imcb$t_log_image_name + 1, imcb->imcb$t_log_image_name[0])) {
            has_threads = 1;
        }

        if (trace_images) {
            log_image_info(imcb);
        }
    }

    if (has_threads) {
        threads_init();
    }

    sock_init();

    unsigned int status = sys$setexv(0, excp_handler, PSL$C_USER, (__void_ptr32)&prevhnd);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
    }

    if (is_attached) {
        return excp_handler((struct chf$signal_array *)progxfer[2], (struct chf$mech_array *)progxfer[3]);
    }

    if (!set_breakpoint(entry_pc)) {
        while (one_command() == 0) {
            ;
        }
    }

    return SS$_CONTINUE;
}

static void log_image_info(IMCB *imcb) {
    unsigned int j;
    LDRIMG *ldrimg = imcb->imcb$l_ldrimg;
    LDRISD *ldrisd;
    TERM_FAO("!XA-!XA ", imcb->imcb$l_starting_address, imcb->imcb$l_end_address);

    switch (imcb->imcb$b_act_code) {
        case IMCB$K_MAIN_PROGRAM:
            term_puts("prog");
            break;
        case IMCB$K_MERGED_IMAGE:
            term_puts("mrge");
            break;
        case IMCB$K_GLOBAL_IMAGE_SECTION:
            term_puts("glob");
            break;
        default:
            term_puts("????");
    }
    TERM_FAO(" !AD !40AC!/", 1, "KESU" + (imcb->imcb$b_access_mode & 3), imcb->imcb$t_log_image_name);

    if ((long)ldrimg < 0 || trace_images < 2) {
        return;
    }

    ldrisd = ldrimg->ldrimg$l_segments;
    for (j = 0; j < ldrimg->ldrimg$l_segcount; j++) {
        log_segment_info(&ldrisd[j]);
    }

    ldrisd = ldrimg->ldrimg$l_dyn_seg;
    if (ldrisd) {
        TERM_FAO("   dynamic            !XA-!XA!/", ldrisd->ldrisd$p_base, (unsigned __int64)ldrisd->ldrisd$p_base + ldrisd->ldrisd$i_len - 1);
    }
}

static void log_segment_info(LDRISD *ldrisd) {
    unsigned int flags = ldrisd->ldrisd$i_flags;
    term_puts("   ");
    term_putc(flags & 0x04 ? 'R' : '-');
    term_putc(flags & 0x02 ? 'W' : '-');
    term_putc(flags & 0x01 ? 'X' : '-');
    term_puts(flags & 0x01000000 ? " Prot" : "     ");
    term_puts(flags & 0x04000000 ? " Shrt" : "     ");
    term_puts(flags & 0x08000000 ? " Shrd" : "     ");
    TERM_FAO(" !XA-!XA!/", ldrisd->ldrisd$p_base, (unsigned __int64)ldrisd->ldrisd$p_base + ldrisd->ldrisd$i_len - 1);
}

static int set_breakpoint(unsigned __int64 entry_pc) {
    static const unsigned char initbp[16] = {0x01, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00};
    unsigned int entry_prot;
    unsigned int status;

    status = page_set_rw(entry_pc, 16, &entry_prot);
    if (!(status & STS$M_SUCCESS)) {
        if ((status & STS$M_COND_ID) == (SS$_NOT_PROCESS_VA & STS$M_COND_ID)) {
            entry_pc = 0;
            term_puts("gdbstub: cannot set breakpoint on entry\n");
            return 0;
        } else {
            LIB$SIGNAL(status);
            return 0;
        }
    }

    if (entry_pc != 0) {
        ots$move(entry_saved, 16, (void *)entry_pc);
        ots$move((void *)entry_pc, 16, (void *)initbp);
        __fc(entry_pc);
        page_restore_rw(entry_pc, 16, entry_prot);
    }

    return 1;
}

/* Declare the entry point of this relocatable module.  */

struct xfer_vector
{
  __int64 impure_start;
  __int64 impure_end;
  int (*entry) ();
};

#pragma __extern_model save
#pragma __extern_model strict_refdef "XFER_PSECT"
struct xfer_vector xfer_vector = {0, 0, stub_start};
#pragma __extern_model restore
