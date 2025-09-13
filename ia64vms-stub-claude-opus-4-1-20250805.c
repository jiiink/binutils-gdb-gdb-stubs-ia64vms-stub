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

static void
term_raw_write(const char *str, unsigned int len)
{
    if (str == NULL || len == 0) {
        return;
    }

    struct _iosb iosb;
    unsigned short status = sys$qiow(EFN$C_ENF,
                                     term_chan,
                                     IO$_WRITEVBLK,
                                     &iosb,
                                     0,
                                     0,
                                     str,
                                     len,
                                     0, 0, 0, 0);

    if ((status & STS$M_SUCCESS) != 0) {
        status = iosb.iosb$w_status;
    }
    
    if ((status & STS$M_SUCCESS) == 0) {
        LIB$SIGNAL(status);
    }
}

/* Flush the term buffer.  */

static void term_flush(void)
{
    if (term_buf_len == 0) {
        return;
    }
    
    term_raw_write(term_buf, term_buf_len);
    term_buf_len = 0;
}

/* Write a single character, without translation.  */

static void term_raw_putchar(char c)
{
    if (term_buf_len >= sizeof(term_buf))
    {
        term_flush();
    }
    
    if (term_buf_len < sizeof(term_buf))
    {
        term_buf[term_buf_len] = c;
        term_buf_len++;
    }
}

/* Write character C.  Translate '\n' to '\n\r'.  */

static void
term_putc (char c)
{
  char output_char = c;
  
  if (c < 32 && c != '\r' && c != '\n')
    {
      output_char = '.';
    }
  
  term_raw_putchar (output_char);
  
  if (c == '\n')
    {
      term_raw_putchar ('\r');
      term_flush ();
    }
}

/* Write a C string.  */

static void term_puts(const char *str)
{
  if (str == NULL) {
    return;
  }
  
  while (*str != '\0') {
    term_putc(*str);
    str++;
  }
}

/* Write LEN bytes from STR.  */

static void term_write(const char *str, unsigned int len)
{
    if (str == NULL) {
        return;
    }
    
    for (unsigned int i = 0; i < len; i++) {
        term_putc(str[i]);
    }
}

/* Write using FAO formatting.  */

static void
term_fao (const char *str, unsigned int str_len, ...)
{
  va_list vargs;
  int cnt;
  int i;
  __int64 *args;
  int status;
  struct dsc$descriptor_s dstr =
    { str_len, DSC$K_DTYPE_T, DSC$K_CLASS_S, (__char_ptr32)str };
  char buf[128];
  $DESCRIPTOR (buf_desc, buf);

  va_start (vargs, str_len);
  va_count (cnt);
  
  if (cnt < 2) {
    va_end (vargs);
    return;
  }
  
  cnt -= 2;
  if (cnt > 0) {
    args = (__int64 *) __ALLOCA (cnt * sizeof (__int64));
    if (!args) {
      va_end (vargs);
      return;
    }
    for (i = 0; i < cnt; i++)
      args[i] = va_arg (vargs, __int64);
  } else {
    args = NULL;
  }

  status = sys$faol_64 (&dstr, &buf_desc.dsc$w_length, &buf_desc, args);
  if (!(status & 1)) {
    va_end (vargs);
    return;
  }

  for (i = 0; i < buf_desc.dsc$w_length && i < sizeof(buf); i++) {
    term_raw_putchar (buf[i]);
    if (buf[i] == '\n')
      term_flush ();
  }
      
  va_end (vargs);
}

#define TERM_FAO(STR, ...) term_fao (STR, sizeof (STR) - 1, __VA_ARGS__)

/* New line.  */

static void term_putnl(void)
{
    term_putc('\n');
}

/* Initialize terminal.  */

static void
term_init (void)
{
  unsigned int status;
  unsigned short len;
  char resstring[LNM$C_NAMLENGTH];
  static const $DESCRIPTOR (tabdesc, "LNM$FILE_DEV");
  static const $DESCRIPTOR (logdesc, "SYS$OUTPUT");
  $DESCRIPTOR (term_desc, resstring);
  ILE3 item_lst[2];

  item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;

  status = SYS$TRNLNM (0, (void *) &tabdesc, (void *) &logdesc, 0, item_lst);
  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);

  term_desc.dsc$w_length = len;

  if (resstring[0] == 0x1B)
    {
      term_desc.dsc$w_length -= 4;
      term_desc.dsc$a_pointer += 4;
    }

  status = sys$assign (&term_desc, &term_chan, 0, 0);
  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);
}

/* Convert from native endianness to network endianness (and vice-versa).  */

static unsigned int wordswap(unsigned int v)
{
    const unsigned int LOW_BYTE_MASK = 0xFFU;
    const unsigned int BYTE_SHIFT = 8U;
    
    unsigned int low_byte = v & LOW_BYTE_MASK;
    unsigned int high_byte = (v >> BYTE_SHIFT) & LOW_BYTE_MASK;
    
    return (low_byte << BYTE_SHIFT) | high_byte;
}

/* Initialize the socket connection, and wait for a client.  */

static void
sock_init (void)
{
  struct _iosb iosb;
  unsigned int status;
  unsigned short listen_channel;
  struct sockchar listen_sockchar;
  unsigned short cli_addrlen;
  struct sockaddr_in cli_addr;
  ILE3 cli_itemlst;
  struct sockaddr_in serv_addr;
  ILE2 serv_itemlst;
  int optval = 1;
  ILE2 sockopt_itemlst;
  ILE2 reuseaddr_itemlst;
  static const $DESCRIPTOR (inet_device, "TCPIP$DEVICE:");

  listen_sockchar.prot = TCPIP$C_TCP;
  listen_sockchar.type = TCPIP$C_STREAM;
  listen_sockchar.af   = TCPIP$C_AF_INET;

  status = sys$assign ((void *) &inet_device, &listen_channel, 0, 0);
  if (status & STS$M_SUCCESS)
    status = sys$assign ((void *) &inet_device, &conn_channel, 0, 0);
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to assign I/O channel(s)\n");
      LIB$SIGNAL (status);
    }

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb,
                     0, 0, &listen_sockchar, 0, 0, 0, 0, 0);
  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to create socket\n");
      LIB$SIGNAL (status);
    }

  reuseaddr_itemlst.ile2$w_length   = sizeof (optval);
  reuseaddr_itemlst.ile2$w_code     = TCPIP$C_REUSEADDR;
  reuseaddr_itemlst.ile2$ps_bufaddr = &optval;

  sockopt_itemlst.ile2$w_length   = sizeof (reuseaddr_itemlst);
  sockopt_itemlst.ile2$w_code     = TCPIP$C_SOCKOPT;
  sockopt_itemlst.ile2$ps_bufaddr = &reuseaddr_itemlst;

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb,
                     0, 0, 0, 0, 0, 0, (__int64) &sockopt_itemlst, 0);
  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to set socket option\n");
      LIB$SIGNAL (status);
    }

  ots$fill (&serv_addr, sizeof (serv_addr), 0);
  serv_addr.sin_family = TCPIP$C_AF_INET;
  serv_addr.sin_port = wordswap (serv_port);
  serv_addr.sin_addr.s_addr = TCPIP$C_INADDR_ANY;

  serv_itemlst.ile2$w_length   = sizeof (serv_addr);
  serv_itemlst.ile2$w_code     = TCPIP$C_SOCK_NAME;
  serv_itemlst.ile2$ps_bufaddr = &serv_addr;

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb,
                     0, 0, 0, 0, (__int64) &serv_itemlst, 0, 0, 0);
  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to bind socket\n");
      LIB$SIGNAL (status);
    }

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb,
                     0, 0, 0, 0, 0, 1, 0, 0);
  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to set socket passive\n");
      LIB$SIGNAL (status);
    }

  TERM_FAO ("Waiting for a client connection on port: !ZW!/",
            wordswap (serv_addr.sin_port));

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_ACCESS|IO$M_ACCEPT, &iosb,
                     0, 0, 0, 0, 0, (__int64) &conn_channel, 0, 0);

  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to accept client connection\n");
      LIB$SIGNAL (status);
    }

  cli_itemlst.ile3$w_length = sizeof (cli_addr);
  cli_itemlst.ile3$w_code = TCPIP$C_SOCK_NAME;
  cli_itemlst.ile3$ps_bufaddr = &cli_addr;
  cli_itemlst.ile3$ps_retlen_addr = &cli_addrlen;
  ots$fill (&cli_addr, sizeof(cli_addr), 0);
  status = sys$qiow (EFN$C_ENF, conn_channel, IO$_SENSEMODE, &iosb,
                     0, 0, 0, 0, 0, (__int64) &cli_itemlst, 0, 0);
  if (status & STS$M_SUCCESS)
    status = iosb.iosb$w_status;
  if (!(status & STS$M_SUCCESS))
    {
      term_puts ("Failed to get client name\n");
      LIB$SIGNAL (status);
    }

  TERM_FAO ("Accepted connection from host: !UB.!UB,!UB.!UB, port: !UW!/",
            (cli_addr.sin_addr.s_addr >> 0) & 0xff,
            (cli_addr.sin_addr.s_addr >> 8) & 0xff,
            (cli_addr.sin_addr.s_addr >> 16) & 0xff,
            (cli_addr.sin_addr.s_addr >> 24) & 0xff,
            wordswap (cli_addr.sin_port));
}

/* Close the socket.  */

static void
sock_close (void)
{
  struct _iosb iosb;
  unsigned int status;

  status = sys$qiow (EFN$C_ENF,
                     conn_channel,
                     IO$_DEACCESS,
                     &iosb,
                     0,
                     0,
                     0, 0, 0, 0, 0, 0);

  if ((status & STS$M_SUCCESS) != 0)
    status = iosb.iosb$w_status;
  
  if ((status & STS$M_SUCCESS) == 0)
    {
      term_puts ("Failed to close socket\n");
      LIB$SIGNAL (status);
    }

  status = sys$dassgn (conn_channel);

  if ((status & STS$M_SUCCESS) == 0)
    {
      term_puts ("Failed to deassign I/O channel\n");
      LIB$SIGNAL (status);
    }
}

/* Mark a page as R/W.  Return old rights.  */

static unsigned int page_set_rw(unsigned __int64 startva, unsigned __int64 len, unsigned int *oldprot)
{
    if (oldprot == NULL) {
        return 0;
    }
    
    unsigned __int64 retva = 0;
    unsigned __int64 retlen = 0;
    
    return SYS$SETPRT_64((void *)startva, len, PSL$C_USER, PRT$C_UW, (void *)&retva, &retlen, oldprot);
}

/* Restore page rights.  */

static void
page_restore_rw (unsigned __int64 startva, unsigned __int64 len,
		unsigned int prot)
{
  unsigned int status;
  unsigned __int64 retva;
  unsigned __int64 retlen;
  unsigned int oldprot;

  status = SYS$SETPRT_64 ((void *)startva, len, PSL$C_USER, prot,
			  (void *)&retva, &retlen, &oldprot);
  if ((status & STS$M_SUCCESS) == 0)
    LIB$SIGNAL (status);
}

/* Get the TEB (thread environment block).  */

static pthread_t get_teb(void)
{
    return (pthread_t)__getReg(_IA64_REG_TP);
}

/* Enable thread scheduling if VAL is true.  */

static unsigned int
set_thread_scheduling (int val)
{
  struct dbgext_control_block blk;
  unsigned int status;

  if (!dbgext_func)
    return 0;

  blk.dbgext$w_function_code = DBGEXT$K_STOP_ALL_OTHER_TASKS;
  blk.dbgext$w_facility_id = CMA$_FACILITY;
  blk.dbgext$l_stop_value = val;

  status = dbgext_func (&blk);
  if ((status & STS$M_SUCCESS) == 0)
    {
      TERM_FAO ("set_thread_scheduling error, val=!SL, status=!XL!/",
		val, blk.dbgext$l_status);
      lib$signal (status);
    }

  return blk.dbgext$l_stop_value;
}

/* Get next thread (after THR).  Start with 0.  */

static unsigned int
thread_next(unsigned int thr)
{
    struct dbgext_control_block blk;
    unsigned int status;

    if (dbgext_func == NULL) {
        return 0;
    }

    memset(&blk, 0, sizeof(blk));
    blk.dbgext$w_function_code = DBGEXT$K_NEXT_TASK;
    blk.dbgext$w_facility_id = CMA$_FACILITY;
    blk.dbgext$l_task_value = thr;

    status = dbgext_func(&blk);
    if ((status & STS$M_SUCCESS) == 0) {
        lib$signal(status);
    }

    return blk.dbgext$l_task_value;
}

/* Pthread Debug callbacks.  */

static int read_callback(pthreadDebugClient_t context,
                         pthreadDebugTargetAddr_t addr,
                         pthreadDebugAddr_t buf,
                         size_t size)
{
    if (context == NULL || buf == NULL) {
        return -1;
    }
    
    if (size == 0) {
        return 0;
    }
    
    if (trace_pthreaddbg) {
        TERM_FAO("read_callback (!XH, !XH, !SL)!/", addr, buf, size);
    }
    
    ots$move(buf, size, addr);
    return 0;
}

static int
write_callback (pthreadDebugClient_t context,
		pthreadDebugTargetAddr_t addr,
		pthreadDebugLongConstAddr_t buf,
		size_t size)
{
  if (context == NULL || addr == NULL || buf == NULL) {
    return -1;
  }
  
  if (size == 0) {
    return 0;
  }
  
  if (trace_pthreaddbg) {
    TERM_FAO ("write_callback (!XH, !XH, !SL)!/", addr, buf, size);
  }
  
  ots$move (addr, size, buf);
  return 0;
}

static int suspend_callback(pthreadDebugClient_t context)
{
    (void)context;
    return 0;
}

static int resume_callback(pthreadDebugClient_t context)
{
    (void)context;
    return 0;
}

static int kthdinfo_callback(pthreadDebugClient_t context,
                            pthreadDebugKId_t kid,
                            pthreadDebugKThreadInfo_p thread_info)
{
    if (trace_pthreaddbg) {
        term_puts("kthinfo_callback");
    }
    return ENOSYS;
}

static int hold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid)
{
    (void)context;
    (void)kid;
    
    if (trace_pthreaddbg)
    {
        term_puts("hold_callback");
    }
    
    return ENOSYS;
}

static int unhold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid)
{
    (void)context;
    (void)kid;
    
    if (trace_pthreaddbg)
    {
        term_puts("unhold_callback");
    }
    
    return ENOSYS;
}

static int getfreg_callback(pthreadDebugClient_t context,
                           pthreadDebugFregs_t *reg,
                           pthreadDebugKId_t kid)
{
    (void)context;
    (void)reg;
    (void)kid;
    
    if (trace_pthreaddbg) {
        term_puts("getfreg_callback");
    }
    
    return ENOSYS;
}

static int setfreg_callback(pthreadDebugClient_t context,
                           const pthreadDebugFregs_t *reg,
                           pthreadDebugKId_t kid)
{
    (void)context;
    (void)reg;
    (void)kid;
    
    if (trace_pthreaddbg) {
        term_puts("setfreg_callback");
    }
    
    return ENOSYS;
}

static int getreg_callback(pthreadDebugClient_t context,
                          pthreadDebugRegs_t *reg,
                          pthreadDebugKId_t kid)
{
    (void)context;
    (void)reg;
    (void)kid;
    
    if (trace_pthreaddbg) {
        term_puts("getreg_callback");
    }
    
    return ENOSYS;
}

static int setreg_callback(pthreadDebugClient_t context,
                          const pthreadDebugRegs_t *reg,
                          pthreadDebugKId_t kid)
{
    if (trace_pthreaddbg) {
        term_puts("setreg_callback");
    }
    return ENOSYS;
}

static int output_callback(pthreadDebugClient_t context, pthreadDebugConstString_t line)
{
    (void)context;
    
    if (line == NULL) {
        return -1;
    }
    
    term_puts(line);
    term_putnl();
    
    return 0;
}

static int error_callback(pthreadDebugClient_t context, pthreadDebugConstString_t line)
{
    (void)context;
    
    if (line == NULL) {
        return -1;
    }
    
    term_puts(line);
    term_putnl();
    
    return 0;
}

static pthreadDebugAddr_t
malloc_callback(pthreadDebugClient_t caller_context, size_t size)
{
    const size_t HEADER_SIZE = 16;
    const size_t MIN_SIZE = 1;
    
    if (size < MIN_SIZE) {
        return NULL;
    }
    
    if (size > SIZE_MAX - HEADER_SIZE) {
        return NULL;
    }
    
    int total_size = (int)(size + HEADER_SIZE);
    unsigned int allocated_address = 0;
    unsigned int status = lib$get_vm(&total_size, &allocated_address, 0);
    
    if ((status & STS$M_SUCCESS) == 0) {
        LIB$SIGNAL(status);
        return NULL;
    }
    
    if (allocated_address == 0) {
        return NULL;
    }
    
    unsigned int *header = (unsigned int *)allocated_address;
    *header = (unsigned int)total_size;
    
    if (trace_pthreaddbg) {
        TERM_FAO("malloc_callback (!UL) -> !XA!/", size, allocated_address);
    }
    
    return (char *)allocated_address + HEADER_SIZE;
}

static void
free_callback (pthreadDebugClient_t caller_context, pthreadDebugAddr_t address)
{
  unsigned int status;
  unsigned int *memory_base;
  int allocation_size;

  if (address == 0) {
    return;
  }

  memory_base = (unsigned int *)((unsigned int)address - 16);
  allocation_size = *memory_base;

  if (trace_pthreaddbg) {
    TERM_FAO ("free_callback (!XA)!/", address);
  }

  status = lib$free_vm (&allocation_size, memory_base, 0);
  if (!(status & STS$M_SUCCESS)) {
    LIB$SIGNAL (status);
  }
}

static int speckthd_callback(pthreadDebugClient_t caller_context,
                            pthreadDebugSpecialType_t type,
                            pthreadDebugKId_t *kernel_tid)
{
    (void)caller_context;
    (void)type;
    (void)kernel_tid;
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

static int pthread_debug_thd_seq_init(pthreadDebugId_t *id)
{
    typedef int (*debug_func_t)(void *, pthreadDebugId_t *);
    
    if (id == NULL) {
        return -1;
    }
    
    if (pthread_debug_entries == NULL || pthread_debug_entries[1].func == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[1].func;
    return func(debug_context, id);
}

static int pthread_debug_thd_seq_next(pthreadDebugId_t *id)
{
    typedef int (*debug_func_t)(void *, pthreadDebugId_t *);
    
    if (pthread_debug_entries == NULL || id == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[2].func;
    if (func == NULL) {
        return -1;
    }
    
    return func(debug_context, id);
}

static int pthread_debug_thd_seq_destroy(void)
{
    typedef int (*debug_func_t)(void*);
    
    if (pthread_debug_entries == NULL || pthread_debug_entries[3].func == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[3].func;
    return func(debug_context);
}

static int pthread_debug_thd_get_info(pthreadDebugId_t id, pthreadDebugThreadInfo_t *info)
{
    typedef int (*debug_func_t)(void *, pthreadDebugId_t, pthreadDebugThreadInfo_t *);
    
    if (pthread_debug_entries == NULL || pthread_debug_entries[4].func == NULL) {
        return -1;
    }
    
    if (info == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[4].func;
    return func(debug_context, id, info);
}

static int pthread_debug_thd_get_info_addr(pthread_t thr, pthreadDebugThreadInfo_t *info)
{
    typedef int (*debug_func_t)(void *, pthread_t, pthreadDebugThreadInfo_t *);
    
    if (pthread_debug_entries == NULL || info == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[5].func;
    
    if (func == NULL) {
        return -1;
    }
    
    return func(debug_context, thr, info);
}

static int pthread_debug_thd_get_reg(pthreadDebugId_t thr, pthreadDebugRegs_t *regs)
{
    typedef int (*debug_func_t)(void *, pthreadDebugId_t, pthreadDebugRegs_t *);
    
    if (pthread_debug_entries == NULL || pthread_debug_entries[6].func == NULL) {
        return -1;
    }
    
    if (regs == NULL) {
        return -1;
    }
    
    debug_func_t func = (debug_func_t)pthread_debug_entries[6].func;
    return func(debug_context, thr, regs);
}

static int stub_pthread_debug_cmd(const char *cmd)
{
    typedef int (*debug_cmd_func)(void *, const char *);
    
    if (pthread_debug_entries == NULL || pthread_debug_entries[7].func == NULL) {
        return -1;
    }
    
    debug_cmd_func func = (debug_cmd_func)pthread_debug_entries[7].func;
    return func(debug_context, cmd);
}

/* Show all the threads.  */

static void threads_show(void)
{
    pthreadDebugId_t id;
    pthreadDebugThreadInfo_t info;
    int res;

    res = pthread_debug_thd_seq_init(&id);
    if (res != 0)
    {
        TERM_FAO("seq init failed, res=!SL!/", res);
        return;
    }

    do
    {
        if (pthread_debug_thd_get_info(id, &info) != 0)
        {
            TERM_FAO("thd_get_info !SL failed!/", id);
            break;
        }
    } while (pthread_debug_thd_seq_next(&id) == 0);

    pthread_debug_thd_seq_destroy();
}

/* Initialize pthread support.  */

static void
threads_init (void)
{
  static const $DESCRIPTOR (dbgext_desc, "PTHREAD$DBGEXT");
  static const $DESCRIPTOR (pthread_debug_desc, "PTHREAD$DBGSHR");
  static const $DESCRIPTOR (dbgsymtable_desc, "PTHREAD_DBG_SYMTABLE");
  void *dbg_symtable = NULL;
  void *caller_context = NULL;
  int status;
  size_t i;
  size_t entry_count;

  status = lib$find_image_symbol
    ((void *) &pthread_rtl_desc, (void *) &dbgext_desc,
     (int *) &dbgext_func);
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
      return;
    }
  
  status = lib$find_image_symbol
    ((void *) &pthread_rtl_desc, (void *) &dbgsymtable_desc,
     (int *) &dbg_symtable);
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
      return;
    }

  entry_count = sizeof (pthread_debug_entries) / sizeof (pthread_debug_entries[0]);
  for (i = 0; i < entry_count; i++)
    {
      struct dsc$descriptor_s sym;
      sym.dsc$w_length = pthread_debug_entries[i].namelen;
      sym.dsc$b_dtype = DSC$K_DTYPE_T;
      sym.dsc$b_class = DSC$K_CLASS_S;
      sym.dsc$a_pointer = pthread_debug_entries[i].name;
      
      status = lib$find_image_symbol
        ((void *) &pthread_debug_desc, (void *) &sym,
         (int *) &pthread_debug_entries[i].func);
      if (!(status & STS$M_SUCCESS))
        {
          lib$signal (status);
          return;
        }
    }

  if (trace_pthreaddbg)
    {
      TERM_FAO ("debug symtable: !XH!/", dbg_symtable);
    }
    
  if (pthread_debug_entries[0].func != NULL)
    {
      typedef int (*init_func_t)(void **, void *, void *, void *);
      init_func_t init_func = (init_func_t) pthread_debug_entries[0].func;
      status = init_func(&caller_context, &pthread_debug_callbacks, 
                        dbg_symtable, &debug_context);
      if (status != 0)
        {
          TERM_FAO ("cannot initialize pthread_debug: !UL!/", status);
        }
    }
    
  TERM_FAO ("pthread debug done!/", 0);
}

/* Convert an hexadecimal character to a nibble.  Return -1 in case of
   error.  */

static int hex2nibble(unsigned char h)
{
    if (h >= '0' && h <= '9') {
        return h - '0';
    }
    if (h >= 'A' && h <= 'F') {
        return h - 'A' + 10;
    }
    if (h >= 'a' && h <= 'f') {
        return h - 'a' + 10;
    }
    return -1;
}

/* Convert an hexadecimal 2 character string to a byte.  Return -1 in case
   of error.  */

static int
hex2byte(const unsigned char *p)
{
  if (p == NULL) {
    return -1;
  }
  
  int high_nibble = hex2nibble(p[0]);
  int low_nibble = hex2nibble(p[1]);
  
  if (high_nibble < 0 || low_nibble < 0) {
    return -1;
  }
  
  return (high_nibble << 4) | low_nibble;
}

/* Convert a byte V to a 2 character strings P.  */

static void byte2hex(unsigned char *p, unsigned char v)
{
    if (p == NULL) {
        return;
    }
    
    p[0] = hex[(v >> 4) & 0x0F];
    p[1] = hex[v & 0x0F];
}

/* Convert a quadword V to a 16 character strings P.  */

static void
quad2hex (unsigned char *p, unsigned __int64 v)
{
  if (p == NULL) {
    return;
  }
  
  for (int i = 0; i < 16; i++)
    {
      p[i] = hex[(v >> 60) & 0x0F];
      v <<= 4;
    }
}

static void
long2pkt (unsigned int v)
{
  for (int i = 0; i < 8; i++)
    {
      gdb_buf[gdb_blen + i] = hex[(v >> 28) & 0x0f];
      v <<= 4;
    }
  gdb_blen += 8;
}

/* Generate an error packet.  */

static void packet_error(unsigned int err)
{
    const size_t ERROR_PREFIX_POS = 1;
    const size_t ERROR_CODE_POS = 2;
    const size_t ERROR_PACKET_LEN = 4;
    
    gdb_buf[ERROR_PREFIX_POS] = 'E';
    byte2hex(gdb_buf + ERROR_CODE_POS, err);
    gdb_blen = ERROR_PACKET_LEN;
}

/* Generate an OK packet.  */

static void packet_ok(void)
{
    static const char OK_RESPONSE[] = {'$', 'O', 'K'};
    
    if (gdb_buf == NULL) {
        return;
    }
    
    for (size_t i = 0; i < sizeof(OK_RESPONSE); i++) {
        gdb_buf[i] = OK_RESPONSE[i];
    }
    
    gdb_blen = sizeof(OK_RESPONSE);
}

/* Append a register to the packet.  */

static void
ireg2pkt(const unsigned char *p)
{
    if (p == NULL) {
        return;
    }
    
    const int REG_SIZE = 8;
    const int HEX_CHARS_PER_BYTE = 2;
    
    for (int i = 0; i < REG_SIZE; i++) {
        byte2hex(gdb_buf + gdb_blen, p[i]);
        gdb_blen += HEX_CHARS_PER_BYTE;
    }
}

/* Append a C string (ASCIZ) to the packet.  */

static void str2pkt(const char *str)
{
    if (str == NULL) {
        return;
    }
    
    size_t len = strlen(str);
    if (len == 0) {
        return;
    }
    
    if (gdb_blen + len > sizeof(gdb_buf)) {
        len = sizeof(gdb_buf) - gdb_blen;
    }
    
    memcpy(&gdb_buf[gdb_blen], str, len);
    gdb_blen += len;
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

static void
mem2bin (const unsigned char *b, unsigned int len)
{
  unsigned int i;
  for (i = 0; i < len; i++)
    {
      unsigned char c = b[i];
      if (c == '#' || c == '$' || c == '}' || c == '*' || c == 0)
        {
          gdb_buf[gdb_blen++] = '}';
          gdb_buf[gdb_blen++] = c ^ 0x20;
        }
      else
        {
          gdb_buf[gdb_blen++] = c;
        }
    }
}

/* Append LEN bytes from B to the current gdb packet (encode in hex).  */

static void
mem2hex(const unsigned char *b, unsigned int len)
{
    if (b == NULL) {
        return;
    }
    
    for (unsigned int i = 0; i < len; i++) {
        byte2hex(gdb_buf + gdb_blen, b[i]);
        gdb_blen += 2;
    }
}

/* Handle the 'q' packet.  */

static void
handle_q_packet (const unsigned char *pkt, unsigned int pktlen)
{
  static unsigned int first_thread;
  static unsigned int last_thread;

  static const char xfer_uib[] = "qXfer:uib:read:";
  static const char qfthreadinfo[] = "qfThreadInfo";
  static const char qsthreadinfo[] = "qsThreadInfo";
  static const char qthreadextrainfo[] = "qThreadExtraInfo,";
  static const char qsupported[] = "qSupported:";

  #define XFER_UIB_LEN (sizeof(xfer_uib) - 1)
  #define QFTHREADINFO_LEN (sizeof(qfthreadinfo) - 1)
  #define QSTHREADINFO_LEN (sizeof(qsthreadinfo) - 1)
  #define QTHREADEXTRAINFO_LEN (sizeof(qthreadextrainfo) - 1)
  #define QSUPPORTED_LEN (sizeof(qsupported) - 1)

  if (pktlen == 2 && pkt[1] == 'C')
  {
    handle_current_thread();
  }
  else if (pktlen > XFER_UIB_LEN &&
           ots$strcmp_eql(pkt, XFER_UIB_LEN, xfer_uib, XFER_UIB_LEN))
  {
    handle_xfer_uib(pkt, XFER_UIB_LEN);
  }
  else if (pktlen == QFTHREADINFO_LEN &&
           ots$strcmp_eql(pkt, QFTHREADINFO_LEN, qfthreadinfo, QFTHREADINFO_LEN))
  {
    handle_first_thread_info(&first_thread, &last_thread);
  }
  else if (pktlen == QSTHREADINFO_LEN &&
           ots$strcmp_eql(pkt, QSTHREADINFO_LEN, qsthreadinfo, QSTHREADINFO_LEN))
  {
    handle_subsequent_thread_info(first_thread, &last_thread);
  }
  else if (pktlen > QTHREADEXTRAINFO_LEN &&
           ots$strcmp_eql(pkt, QTHREADEXTRAINFO_LEN, qthreadextrainfo, QTHREADEXTRAINFO_LEN))
  {
    handle_thread_extra_info(pkt, QTHREADEXTRAINFO_LEN);
  }
  else if (pktlen > QSUPPORTED_LEN &&
           ots$strcmp_eql(pkt, QSUPPORTED_LEN, qsupported, QSUPPORTED_LEN))
  {
    handle_supported_features();
  }
  else
  {
    handle_unknown_packet(pkt, pktlen);
  }
}

static void handle_current_thread(void)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'Q';
  gdb_buf[2] = 'C';
  gdb_blen = 3;
  if (has_threads)
  {
    long2pkt((unsigned long)get_teb());
  }
}

static void handle_xfer_uib(const unsigned char *pkt, unsigned int start_pos)
{
  unsigned __int64 pc;
  unsigned int pos = start_pos;
  unsigned int off;
  unsigned int len;
  union
  {
    unsigned char bytes[32];
    struct
    {
      unsigned __int64 code_start_va;
      unsigned __int64 code_end_va;
      unsigned __int64 uib_start_va;
      unsigned __int64 gp_value;
    } data;
  } uei;
  int res;

  packet_error(0);

  pc = pkt2val(pkt, &pos);
  if (pkt[pos] != ':')
  {
    return;
  }
  pos++;
  off = pkt2val(pkt, &pos);
  if (pkt[pos] != ',' || off != 0)
  {
    return;
  }
  pos++;
  len = pkt2val(pkt, &pos);
  if (pkt[pos] != '#' || len != 0x20)
  {
    return;
  }

  res = SYS$GET_UNWIND_ENTRY_INFO(pc, &uei.data, 0);
  if (res == SS$_NODATA || res != SS$_NORMAL)
  {
    ots$fill(uei.bytes, sizeof(uei.bytes), 0);
  }

  if (trace_unwind)
  {
    TERM_FAO("Unwind request for !XH, status=!XL, uib=!XQ, GP=!XQ!/",
             pc, res, uei.data.uib_start_va, uei.data.gp_value);
  }

  gdb_buf[0] = '$';
  gdb_buf[1] = 'l';
  gdb_blen = 2;
  mem2bin(uei.bytes, sizeof(uei.bytes));
}

static void handle_first_thread_info(unsigned int *first_thread, unsigned int *last_thread)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'm';
  gdb_blen = 2;

  if (!has_threads)
  {
    gdb_buf[1] = 'l';
    return;
  }
  *first_thread = thread_next(0);
  *last_thread = *first_thread;
  long2pkt(*first_thread);
}

static void handle_subsequent_thread_info(unsigned int first_thread, unsigned int *last_thread)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'm';
  gdb_blen = 2;
  
  while (dbgext_func)
  {
    unsigned int res = thread_next(*last_thread);
    if (res == first_thread)
    {
      break;
    }
    if (gdb_blen > 2)
    {
      gdb_buf[gdb_blen++] = ',';
    }
    long2pkt(res);
    *last_thread = res;
    if (gdb_blen > sizeof(gdb_buf) - 16)
    {
      break;
    }
  }

  if (gdb_blen == 2)
  {
    gdb_buf[1] = 'l';
  }
}

static void handle_thread_extra_info(const unsigned char *pkt, unsigned int start_pos)
{
  pthread_t thr;
  unsigned int pos = start_pos;
  pthreadDebugThreadInfo_t info;
  int res;

  packet_error(0);
  if (!has_threads)
  {
    return;
  }

  thr = (pthread_t)pkt2val(pkt, &pos);
  if (pkt[pos] != '#')
  {
    return;
  }
  res = pthread_debug_thd_get_info_addr(thr, &info);
  if (res != 0)
  {
    TERM_FAO("qThreadExtraInfo (!XH) failed: !SL!/", thr, res);
    return;
  }
  gdb_buf[0] = '$';
  gdb_blen = 1;
  mem2hex((const unsigned char *)"VMS-thread", 11);
}

static void handle_supported_features(void)
{
  gdb_buf[0] = '$';
  gdb_blen = 1;
  str2pkt("qXfer:uib:read+");
}

static void handle_unknown_packet(const unsigned char *pkt, unsigned int pktlen)
{
  if (trace_pkt)
  {
    term_puts("unknown <: ");
    term_write((char *)pkt, pktlen);
    term_putnl();
  }
}

/* Handle the 'v' packet.  */

static int handle_v_packet(const unsigned char *pkt, unsigned int pktlen)
{
    static const char vcontq[] = "vCont?";
    static const size_t VCONTQ_LEN = sizeof(vcontq) - 1;

    if (pkt == NULL) {
        return -1;
    }

    if (pktlen == VCONTQ_LEN && 
        ots$strcmp_eql(pkt, VCONTQ_LEN, vcontq, VCONTQ_LEN)) {
        gdb_buf[0] = '$';
        gdb_blen = 1;
        str2pkt("vCont;c;s");
        return 0;
    }

    if (trace_pkt) {
        term_puts("unknown <: ");
        term_write((char *)pkt, pktlen);
        term_putnl();
    }
    
    return 0;
}

/* Get regs for the selected thread.  */

static struct ia64_all_regs *
get_selected_regs (void)
{
  pthreadDebugRegs_t regs;
  int res;

  if (selected_thread == 0 || selected_thread == get_teb ())
    return &excp_regs;

  if (selected_thread == sel_regs_pthread)
    return &sel_regs;

  res = pthread_debug_thd_get_reg (selected_id, &regs);
  if (res != 0)
    {
      return &excp_regs;
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
  sel_regs.bsp.v = regs.bspstore;
  sel_regs.pfs.v = regs.pfs;
  sel_regs.pr.v = regs.pr;
  return &sel_regs;
}

/* Create a status packet.  */

static void packet_status(void)
{
    const char *status_prefix = has_threads ? "$T05thread:" : "$S05";
    
    gdb_blen = 0;
    str2pkt(status_prefix);
    
    if (has_threads)
    {
        unsigned long teb_value = (unsigned long)get_teb();
        long2pkt(teb_value);
        gdb_buf[gdb_blen++] = ';';
    }
}

/* Return 1 to continue.  */

static int
handle_packet (unsigned char *pkt, unsigned int len)
{
  unsigned int pos;

  gdb_buf[0] = '$';
  gdb_blen = 1;

  pos = 1;
  switch (pkt[0])
    {
    case '?':
      if (len == 1)
	{
	  packet_status ();
	  return 0;
	}
      break;
    case 'c':
      if (len == 1)
	{
	  excp_regs.psr.v &= ~(unsigned __int64)PSR$M_SS;
	  return 1;
	}
      packet_error (0);
      break;
    case 'g':
      if (len == 1)
	{
	  handle_g_packet();
	  return 0;
	}
      break;
    case 'H':
      return handle_H_packet(pkt, len);
    case 'k':
      SYS$EXIT (SS$_NORMAL);
      break;
    case 'm':
      return handle_m_packet(pkt, len, pos);
    case 'M':
      return handle_M_packet(pkt, len, pos);
    case 'p':
      return handle_p_packet(pkt, len, pos);
    case 'q':
      handle_q_packet (pkt, len);
      break;
    case 's':
      if (len == 1)
	{
	  excp_regs.psr.v |= (unsigned __int64)PSR$M_SS;
	  return 1;
	}
      packet_error (0);
      break;
    case 'T':
      return handle_T_packet(pkt, len, pos);
    case 'v':
      return handle_v_packet (pkt, len);
    case 'V':
      return handle_V_packet(pkt, len);
    default:
      if (trace_pkt)
	{
	  term_puts ("unknown <: ");
	  term_write ((char *)pkt, len);
	  term_putnl ();
	}
      break;
    }
  return 0;
}

static void handle_g_packet(void)
{
  unsigned int i;
  struct ia64_all_regs *regs = get_selected_regs ();
  unsigned char *p = regs->gr[0].b;

  for (i = 0; i < 8 * 32; i++)
    byte2hex (gdb_buf + 1 + 2 * i, p[i]);
  gdb_blen += 2 * 8 * 32;
}

static int handle_H_packet(unsigned char *pkt, unsigned int len)
{
  unsigned int pos = 1;
  
  if (pkt[1] == 'g')
    {
      return handle_Hg_packet(pkt, len, pos);
    }
  
  if (pkt[1] == 'c' && 
      ((len == 4 && pkt[2] == '-' && pkt[3] == '1') ||
       (len == 3 && pkt[2] == '0')))
    {
      packet_ok ();
      return 0;
    }
  
  packet_error (0);
  return 0;
}

static int handle_Hg_packet(unsigned char *pkt, unsigned int len, unsigned int pos)
{
  int res;
  unsigned __int64 val;
  pthreadDebugThreadInfo_t info;
  
  pos++;
  val = pkt2val (pkt, &pos);
  if (pos != len)
    {
      packet_error (0);
      return 0;
    }
  
  if (val == 0)
    {
      selected_thread = get_teb ();
      selected_id = 0;
      packet_ok ();
      return 0;
    }
  
  if (!has_threads)
    {
      packet_error (0);
      return 0;
    }
  
  res = pthread_debug_thd_get_info_addr ((pthread_t) val, &info);
  if (res != 0)
    {
      TERM_FAO ("qThreadExtraInfo (!XH) failed: !SL!/", val, res);
      packet_error (0);
      return 0;
    }
  
  selected_thread = info.teb;
  selected_id = info.sequence;
  packet_ok ();
  return 0;
}

static int check_memory_access(unsigned __int64 addr, unsigned int l, int write_access)
{
  unsigned int i = l + (addr & VMS_PAGE_MASK);
  unsigned __int64 paddr = addr & ~VMS_PAGE_MASK;
  
  while (1)
    {
      int probe_result = write_access ? __probew(paddr, 0) : __prober(paddr, 0);
      if (probe_result != 1)
        return 0;
      if (i < VMS_PAGE_SIZE)
        break;
      i -= VMS_PAGE_SIZE;
      paddr += VMS_PAGE_SIZE;
    }
  return 1;
}

static int handle_m_packet(unsigned char *pkt, unsigned int len, unsigned int pos)
{
  unsigned __int64 addr;
  unsigned int l;
  unsigned int i;

  addr = pkt2val (pkt, &pos);
  if (pkt[pos] != ',')
    {
      packet_error (0);
      return 0;
    }
  pos++;
  l = pkt2val (pkt, &pos);
  if (pkt[pos] != '#')
    {
      packet_error (0);
      return 0;
    }

  if (!check_memory_access(addr, l, 0))
    {
      packet_error (2);
      return 0;
    }

  for (i = 0; i < l; i++)
    byte2hex (gdb_buf + 1 + 2 * i, ((unsigned char *)addr)[i]);
  gdb_blen += 2 * l;
  return 0;
}

static int handle_M_packet(unsigned char *pkt, unsigned int len, unsigned int pos)
{
  unsigned __int64 addr;
  unsigned int l;
  unsigned int i;
  unsigned int oldprot;

  addr = pkt2val (pkt, &pos);
  if (pkt[pos] != ',')
    {
      packet_error (0);
      return 0;
    }
  pos++;
  l = pkt2val (pkt, &pos);
  if (pkt[pos] != ':')
    {
      packet_error (0);
      return 0;
    }
  pos++;
  
  page_set_rw (addr, l, &oldprot);

  if (!check_memory_access(addr, l, 1))
    {
      page_restore_rw (addr, l, oldprot);
      return 0;
    }

  for (i = 0; i < l; i++)
    {
      int v = hex2byte (pkt + pos);
      pos += 2;
      ((unsigned char *)addr)[i] = v;
    }

  for (i = 0; i < l; i += 15)
    __fc (addr + i);
  __fc (addr + l);

  page_restore_rw (addr, l, oldprot);
  packet_ok ();
  return 0;
}

static int handle_p_packet(unsigned char *pkt, unsigned int len, unsigned int pos)
{
  unsigned int num;
  struct ia64_all_regs *regs = get_selected_regs ();

  num = pkt2val (pkt, &pos);
  if (pos != len)
    {
      packet_error (0);
      return 0;
    }

  switch (num)
    {
    case IA64_IP_REGNUM:
      ireg2pkt (regs->ip.b);
      break;
    case IA64_BR0_REGNUM:
      ireg2pkt (regs->br[0].b);
      break;
    case IA64_PSR_REGNUM:
      ireg2pkt (regs->psr.b);
      break;
    case IA64_BSP_REGNUM:
      ireg2pkt (regs->bsp.b);
      break;
    case IA64_CFM_REGNUM:
      ireg2pkt (regs->cfm.b);
      break;
    case IA64_PFS_REGNUM:
      ireg2pkt (regs->pfs.b);
      break;
    case IA64_PR_REGNUM:
      ireg2pkt (regs->pr.b);
      break;
    default:
      TERM_FAO ("gdbserv: unhandled reg !UW!/", num);
      packet_error (0);
      return 0;
    }
  return 0;
}

static int handle_T_packet(unsigned char *pkt, unsigned int len, unsigned int pos)
{
  int res;
  unsigned __int64 val;
  unsigned int fthr, thr;
  
  if (!has_threads)
    {
      packet_ok ();
      return 0;
    }
  
  val = pkt2val (pkt, &pos);
  packet_error (0);
  if (pos != len)
    return 0;

  fthr = thread_next (0);
  thr = fthr;
  do
    {
      if (val == thr)
        {
          packet_ok ();
          return 0;
        }
      thr = thread_next (thr);
    }
  while (thr != fthr);
  
  return 0;
}

static int handle_V_packet(unsigned char *pkt, unsigned int len)
{
  if (len > 3 && pkt[1] == 'M' && pkt[2] == 'S' && pkt[3] == ' ')
    {
      if (has_threads)
        {
          pkt[len] = 0;
          stub_pthread_debug_cmd ((char *)pkt + 4);
          packet_ok ();
        }
      else
        packet_error (0);
    }
  return 0;
}

/* Raw write to gdb.  */

static void
sock_write (const unsigned char *buf, int len)
{
  struct _iosb iosb;
  unsigned int status;

  if (buf == NULL || len <= 0) {
    return;
  }

  status = sys$qiow (EFN$C_ENF,
		     conn_channel,
		     IO$_WRITEVBLK,
		     &iosb,
		     0,
		     0,
		     (char *)buf,
		     len,
		     0, 0, 0, 0);
  
  if ((status & STS$M_SUCCESS) == 0) {
    term_puts ("Failed to write data to gdb\n");
    LIB$SIGNAL (status);
    return;
  }
  
  status = iosb.iosb$w_status;
  if ((status & STS$M_SUCCESS) == 0) {
    term_puts ("Failed to write data to gdb\n");
    LIB$SIGNAL (status);
  }
}

/* Compute the checksum and send the packet.  */

static void send_pkt(void)
{
    if (gdb_buf == NULL || gdb_blen == 0) {
        return;
    }

    unsigned char checksum = calculate_checksum();
    append_checksum(checksum);
    
    if (sock_write(gdb_buf, gdb_blen + 3) < 0) {
        return;
    }

    trace_packet();
}

static unsigned char calculate_checksum(void)
{
    unsigned char checksum = 0;
    
    for (unsigned int i = 1; i < gdb_blen; i++) {
        checksum += gdb_buf[i];
    }
    
    return checksum;
}

static void append_checksum(unsigned char checksum)
{
    gdb_buf[gdb_blen] = '#';
    byte2hex(gdb_buf + gdb_blen + 1, checksum);
}

static void trace_packet(void)
{
    if (trace_pkt <= 1) {
        return;
    }
    
    term_puts(">: ");
    term_write((char *)gdb_buf, gdb_blen + 3);
    term_putnl();
}

/* Read and handle one command.  Return 1 is execution must resume.  */

static int one_command(void)
{
    struct _iosb iosb;
    unsigned int status;
    unsigned int off;
    unsigned int dollar_off;
    unsigned int sharp_off;

    while (1)
    {
        if (receive_packet(&iosb, &off, &dollar_off, &sharp_off) != 0)
            continue;

        if (validate_packet(dollar_off, sharp_off) != 0)
            continue;

        break;
    }

    if (trace_pkt > 1)
    {
        term_puts("<: ");
        term_write((char *)gdb_buf + dollar_off, sharp_off - dollar_off + 1);
        term_putnl();
    }

    if (handle_packet(gdb_buf + dollar_off + 1, sharp_off - dollar_off - 1) == 1)
        return 1;

    send_pkt();
    return 0;
}

static int receive_packet(struct _iosb *iosb, unsigned int *off, unsigned int *dollar_off, unsigned int *sharp_off)
{
    unsigned int status;
    
    *off = 0;
    *dollar_off = 0;
    *sharp_off = 0;

    while (1)
    {
        status = sys$qiow(EFN$C_ENF, conn_channel, IO$_READVBLK, iosb, 0, 0,
                         gdb_buf + *off, sizeof(gdb_buf) - *off, 0, 0, 0, 0);
        
        if (status & STS$M_SUCCESS)
            status = iosb->iosb$w_status;
        
        if (!(status & STS$M_SUCCESS))
        {
            term_puts("Failed to read data from connection\n");
            LIB$SIGNAL(status);
        }

#ifdef RAW_DUMP
        term_puts("{: ");
        term_write((char *)gdb_buf + *off, iosb->iosb$w_bcnt);
        term_putnl();
#endif

        gdb_blen = *off + iosb->iosb$w_bcnt;

        if (*off == 0)
        {
            if (find_packet_start(dollar_off, sharp_off) != 0)
            {
                *off = 0;
                continue;
            }
        }
        else if (*sharp_off >= *off)
        {
            find_packet_end(*sharp_off, sharp_off);
        }

        if (*sharp_off + 2 <= gdb_blen)
            return 0;

        *off = gdb_blen;
        if (gdb_blen == sizeof(gdb_buf))
            *off = 0;
    }
}

static int find_packet_start(unsigned int *dollar_off, unsigned int *sharp_off)
{
    unsigned int i;

    for (i = 0; i < gdb_blen; i++)
    {
        if (gdb_buf[i] == '$')
        {
            *dollar_off = i;
            break;
        }
    }

    if (i >= gdb_blen)
        return -1;

    for (i = *dollar_off + 1; i < gdb_blen; i++)
    {
        if (gdb_buf[i] == '#')
        {
            *sharp_off = i;
            break;
        }
    }

    return 0;
}

static void find_packet_end(unsigned int start, unsigned int *sharp_off)
{
    unsigned int i;

    for (i = start; i < gdb_blen; i++)
    {
        if (gdb_buf[i] == '#')
        {
            *sharp_off = i;
            break;
        }
    }
}

static int validate_packet(unsigned int dollar_off, unsigned int sharp_off)
{
    unsigned char chksum = 0;
    unsigned int i;
    int v;

    for (i = dollar_off + 1; i < sharp_off; i++)
        chksum += gdb_buf[i];

    v = hex2byte(gdb_buf + sharp_off + 1);
    
    if (v != chksum)
    {
        term_puts("Discard bad checksum packet\n");
        return -1;
    }

    sock_write((const unsigned char *)"+", 1);
    return 0;
}

/* Display the condition given by SIG64.  */

static void
display_excp (struct chf64$signal_array *sig64, struct chf$mech_array *mech)
{
  unsigned int status;
  char msg[160];
  unsigned short msglen;
  $DESCRIPTOR (msg_desc, msg);
  unsigned char outadr[4];

  if (!sig64 || !mech) {
    term_puts ("invalid parameters");
    term_putnl ();
    return;
  }

  status = SYS$GETMSG (sig64->chf64$q_sig_name, &msglen, &msg_desc, 0, outadr);
  if (!(status & STS$M_SUCCESS)) {
    term_puts ("no message");
    term_putnl ();
    return;
  }

  char msg2[160];
  unsigned short msg2len;
  struct dsc$descriptor_s msg2_desc =
    { sizeof (msg2), DSC$K_DTYPE_T, DSC$K_CLASS_S, msg2};
  msg_desc.dsc$w_length = msglen;
  status = SYS$FAOL_64 (&msg_desc, &msg2len, &msg2_desc,
                        &sig64->chf64$q_sig_arg1);
  if (status & STS$M_SUCCESS) {
    term_write (msg2, msg2len);
  }
  term_putnl ();

  if (trace_excp > 1) {
    TERM_FAO (" Frame: !XH, Depth: !4SL, Esf: !XH!/",
              mech->chf$q_mch_frame, mech->chf$q_mch_depth,
              mech->chf$q_mch_esf_addr);
  }
}

/* Get all registers from current thread.  */

static void
read_all_registers (struct chf$mech_array *mech)
{
  if (!mech || !mech->chf$q_mch_esf_addr || !mech->chf$ph_mch_sig64_addr) {
    return;
  }

  struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
  struct chf64$signal_array *sig64 = (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;
  
  unsigned int cnt = sig64->chf64$w_sig_arg_count;
  if (cnt < 2) {
    return;
  }
  
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
  
  unsigned __int64 *gr_regs[] = {
    NULL,
    &intstk->intstk$q_gp,
    &intstk->intstk$q_r2,
    &intstk->intstk$q_r3,
    &intstk->intstk$q_r4,
    &intstk->intstk$q_r5,
    &intstk->intstk$q_r6,
    &intstk->intstk$q_r7,
    &intstk->intstk$q_r8,
    &intstk->intstk$q_r9,
    &intstk->intstk$q_r10,
    &intstk->intstk$q_r11,
    NULL,
    &intstk->intstk$q_r13,
    &intstk->intstk$q_r14,
    &intstk->intstk$q_r15,
    &intstk->intstk$q_r16,
    &intstk->intstk$q_r17,
    &intstk->intstk$q_r18,
    &intstk->intstk$q_r19,
    &intstk->intstk$q_r20,
    &intstk->intstk$q_r21,
    &intstk->intstk$q_r22,
    &intstk->intstk$q_r23,
    &intstk->intstk$q_r24,
    &intstk->intstk$q_r25,
    &intstk->intstk$q_r26,
    &intstk->intstk$q_r27,
    &intstk->intstk$q_r28,
    &intstk->intstk$q_r29,
    &intstk->intstk$q_r30,
    &intstk->intstk$q_r31
  };
  
  excp_regs.gr[0].v = 0;
  
  for (int i = 1; i < 32; i++) {
    if (i == 12) {
      excp_regs.gr[12].v = (unsigned __int64)intstk + intstk->intstk$l_stkalign;
    } else if (gr_regs[i]) {
      excp_regs.gr[i].v = *gr_regs[i];
    }
  }
  
  unsigned __int64 *br_regs[] = {
    &intstk->intstk$q_b0,
    &intstk->intstk$q_b1,
    &intstk->intstk$q_b2,
    &intstk->intstk$q_b3,
    &intstk->intstk$q_b4,
    &intstk->intstk$q_b5,
    &intstk->intstk$q_b6,
    &intstk->intstk$q_b7
  };
  
  for (int i = 0; i < 8; i++) {
    excp_regs.br[i].v = *br_regs[i];
  }
}

/* Write all registers to current thread.  FIXME: not yet complete.  */

static void write_all_registers(struct chf$mech_array *mech)
{
    if (mech == NULL || mech->chf$q_mch_esf_addr == NULL) {
        return;
    }
    
    struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
    intstk->intstk$q_ipsr = excp_regs.psr.v;
}

/* Do debugging.  Report status to gdb and execute commands.  */

static void
do_debug (struct chf$mech_array *mech)
{
  struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
  unsigned int old_ast = 0;
  unsigned int old_sch = 0;
  unsigned int status;

  status = sys$setast (0);
  if (status == SS$_WASSET)
    old_ast = 1;
  else if (status != SS$_WASCLR)
    lib$signal (status);

  if (has_threads)
    old_sch = set_thread_scheduling (0);

  read_all_registers (mech);

  packet_status ();
  send_pkt ();

  while (one_command () == 0)
    ;

  write_all_registers (mech);

  if (has_threads)
    set_thread_scheduling (old_sch);

  status = sys$setast (old_ast);
  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);
}

/* The condition handler.  That's the core of the stub.  */

static int excp_handler(struct chf$signal_array *sig, struct chf$mech_array *mech)
{
    struct chf64$signal_array *sig64 = (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;
    unsigned int code = sig->chf$l_sig_name & STS$M_COND_ID;
    unsigned int cnt = sig64->chf64$w_sig_arg_count;
    unsigned __int64 pc;
    static int in_handler = 0;

    if (code == (LIB$_KEYNOTFOU & STS$M_COND_ID)) {
        return SS$_RESIGNAL_64;
    }

    in_handler++;
    if (in_handler > 1) {
        if (in_handler == 2) {
            TERM_FAO("gdbstub: exception in handler (pc=!XH)!!!/", (&sig64->chf64$q_sig_name)[cnt - 2]);
        }
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

    int ret = SS$_RESIGNAL_64;
    
    if (code == (SS$_ACCVIO & STS$M_COND_ID)) {
        if (trace_excp <= 1) {
            display_excp(sig64, mech);
        }
        do_debug(mech);
        ret = SS$_CONTINUE_64;
    } else if (code == (SS$_BREAK & STS$M_COND_ID) ||
               code == (SS$_OPCDEC & STS$M_COND_ID) ||
               code == (SS$_TBIT & STS$M_COND_ID) ||
               code == (SS$_DEBUG & STS$M_COND_ID)) {
        if (trace_excp > 1) {
            struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;
            display_excp(sig64, mech);
            TERM_FAO(" intstk: !XH!/", intstk);
            for (int i = 0; i < cnt + 1; i++) {
                TERM_FAO("   !XH!/", ((unsigned __int64 *)sig64)[i]);
            }
        }
        do_debug(mech);
        ret = SS$_CONTINUE_64;
    } else {
        display_excp(sig64, mech);
    }

    in_handler--;
    sel_regs_pthread = 0;
    return ret;
}

/* Setup internal trace flags according to GDBSTUB$TRACE logical.  */

static void
trace_init (void)
{
  unsigned int status;
  unsigned short len;
  char resstring[LNM$C_NAMLENGTH];
  static const $DESCRIPTOR (tabdesc, "LNM$DCL_LOGICAL");
  static const $DESCRIPTOR (logdesc, "GDBSTUB$TRACE");
  $DESCRIPTOR (sub_desc, resstring);
  ILE3 item_lst[2];

  item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;

  status = SYS$TRNLNM (0, (void *)&tabdesc, (void *)&logdesc, 0, &item_lst);
  if (status == SS$_NOLOGNAM)
    return;
  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);

  parse_trace_directives(resstring, len, &sub_desc);
  display_trace_settings(resstring, len);
}

static void
parse_trace_directives(char *resstring, unsigned short len, void *sub_desc_ptr)
{
  unsigned int i, start = 0;
  $DESCRIPTOR *sub_desc = ($DESCRIPTOR *)sub_desc_ptr;

  for (i = 0; i <= len; i++)
    {
      if (is_delimiter(i, len, resstring[i]) && i != start)
        {
          sub_desc->dsc$a_pointer = resstring + start;
          sub_desc->dsc$w_length = i - start;
          process_single_directive(sub_desc);
          start = i + 1;
        }
    }
}

static int
is_delimiter(unsigned int pos, unsigned short len, char ch)
{
  return (pos == len || ch == ',' || ch == ';');
}

static void
process_single_directive(void *sub_desc_ptr)
{
  int j;
  $DESCRIPTOR *sub_desc = ($DESCRIPTOR *)sub_desc_ptr;

  for (j = 0; j < NBR_DEBUG_FLAGS; j++)
    {
      if (str$case_blind_compare(sub_desc, (void *)&debug_flags[j].name) == 0)
        {
          debug_flags[j].val++;
          return;
        }
    }
  TERM_FAO("GDBSTUB$TRACE: unknown directive !AS!/", sub_desc);
}

static void
display_trace_settings(char *resstring, unsigned short len)
{
  unsigned int i;

  TERM_FAO("GDBSTUB$TRACE=!AD ->", len, resstring);
  for (i = 0; i < NBR_DEBUG_FLAGS; i++)
    {
      if (debug_flags[i].val > 0)
        TERM_FAO(" !AS=!ZL", &debug_flags[i].name, debug_flags[i].val);
    }
  term_putnl();
}


/* Entry point.  */

static int stub_start(unsigned __int64 *progxfer, void *cli_util,
                     EIHD *imghdr, IFD *imgfile,
                     unsigned int linkflag, unsigned int cliflag) {
    static int initialized;
    int cnt;
    int is_attached;
    
    if (initialized) {
        term_puts("gdbstub: re-entry\n");
    } else {
        initialized = 1;
    }
    
    va_count(cnt);
    is_attached = (cnt == 4);
    
    term_init();
    term_puts("Hello from gdb stub\n");
    trace_init();
    
    if (trace_entry && !is_attached) {
        print_trace_info(progxfer, imghdr, imgfile);
    }
    
    if (!is_attached) {
        entry_pc = find_entry_point(progxfer);
        if (trace_entry) {
            print_entry_point(entry_pc);
        }
    } else {
        entry_pc = progxfer[0];
    }
    
    has_threads = check_for_threads();
    
    if (has_threads) {
        threads_init();
    }
    
    sock_init();
    
    if (!set_exception_handler()) {
        return SS$_CONTINUE;
    }
    
    if (is_attached) {
        return excp_handler((struct chf$signal_array *)progxfer[2],
                          (struct chf$mech_array *)progxfer[3]);
    }
    
    if (!set_entry_breakpoint()) {
        while (one_command() == 0) {
            ;
        }
    }
    
    return SS$_CONTINUE;
}

static unsigned __int64 find_entry_point(unsigned __int64 *progxfer) {
    unsigned __int64 entry = 0;
    int i;
    
    for (i = 0; progxfer[i]; i++) {
        entry = progxfer[i];
    }
    
    return entry;
}

static void print_trace_info(unsigned __int64 *progxfer, EIHD *imghdr, IFD *imgfile) {
    int i;
    
    TERM_FAO("xfer: !XH, imghdr: !XH, ifd: !XH!/", progxfer, imghdr, imgfile);
    
    for (i = -2; i < 8; i++) {
        TERM_FAO("  at !2SW: !XH!/", i, progxfer[i]);
    }
}

static void print_entry_point(unsigned __int64 entry) {
    if (entry == 0) {
        term_puts("No entry point\n");
    } else {
        TERM_FAO("Entry: !XH!/", entry);
    }
}

static int check_for_threads(void) {
    IMCB *imcb;
    int found_threads = 0;
    
    for (imcb = ctl$gl_imglstptr->imcb$l_flink;
         imcb != ctl$gl_imglstptr;
         imcb = imcb->imcb$l_flink) {
        
        if (ots$strcmp_eql(pthread_rtl_desc.dsc$a_pointer,
                          pthread_rtl_desc.dsc$w_length,
                          imcb->imcb$t_log_image_name + 1,
                          imcb->imcb$t_log_image_name[0])) {
            found_threads = 1;
        }
        
        if (trace_images) {
            print_image_info(imcb);
        }
    }
    
    return found_threads;
}

static void print_image_info(IMCB *imcb) {
    LDRIMG *ldrimg;
    
    TERM_FAO("!XA-!XA ", imcb->imcb$l_starting_address, imcb->imcb$l_end_address);
    
    print_image_type(imcb->imcb$b_act_code);
    
    TERM_FAO(" !AD !40AC!/",
            1, "KESU" + (imcb->imcb$b_access_mode & 3),
            imcb->imcb$t_log_image_name);
    
    ldrimg = imcb->imcb$l_ldrimg;
    if ((long)ldrimg >= 0 && trace_images >= 2) {
        print_segments(ldrimg);
    }
}

static void print_image_type(unsigned char act_code) {
    switch (act_code) {
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
        break;
    }
}

static void print_segments(LDRIMG *ldrimg) {
    LDRISD *ldrisd;
    unsigned int j;
    
    ldrisd = ldrimg->ldrimg$l_segments;
    for (j = 0; j < ldrimg->ldrimg$l_segcount; j++) {
        print_segment_info(&ldrisd[j]);
    }
    
    ldrisd = ldrimg->ldrimg$l_dyn_seg;
    if (ldrisd) {
        TERM_FAO("   dynamic            !XA-!XA!/",
                ldrisd->ldrisd$p_base,
                (unsigned __int64)ldrisd->ldrisd$p_base + ldrisd->ldrisd$i_len - 1);
    }
}

static void print_segment_info(LDRISD *segment) {
    unsigned int flags = segment->ldrisd$i_flags;
    
    term_puts("   ");
    term_putc((flags & 0x04) ? 'R' : '-');
    term_putc((flags & 0x02) ? 'W' : '-');
    term_putc((flags & 0x01) ? 'X' : '-');
    term_puts((flags & 0x01000000) ? " Prot" : "     ");
    term_puts((flags & 0x04000000) ? " Shrt" : "     ");
    term_puts((flags & 0x08000000) ? " Shrd" : "     ");
    
    TERM_FAO(" !XA-!XA!/",
            segment->ldrisd$p_base,
            (unsigned __int64)segment->ldrisd$p_base + segment->ldrisd$i_len - 1);
}

static int set_exception_handler(void) {
    unsigned int status;
    
    status = sys$setexv(0, excp_handler, PSL$C_USER, (__void_ptr32)&prevhnd);
    if (!(status & STS$M_SUCCESS)) {
        LIB$SIGNAL(status);
        return 0;
    }
    
    return 1;
}

static int set_entry_breakpoint(void) {
    static const unsigned char initbp[16] = {
        0x01, 0x08, 0x00, 0x40, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00
    };
    unsigned int entry_prot;
    unsigned int status;
    
    if (entry_pc == 0) {
        return 0;
    }
    
    status = page_set_rw(entry_pc, 16, &entry_prot);
    
    if (!(status & STS$M_SUCCESS)) {
        if ((status & STS$M_COND_ID) == (SS$_NOT_PROCESS_VA & STS$M_COND_ID)) {
            entry_pc = 0;
            term_puts("gdbstub: cannot set breakpoint on entry\n");
            return 0;
        }
        LIB$SIGNAL(status);
        return 0;
    }
    
    ots$move(entry_saved, 16, (void *)entry_pc);
    ots$move((void *)entry_pc, 16, (void *)initbp);
    __fc(entry_pc);
    page_restore_rw(entry_pc, 16, entry_prot);
    
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
