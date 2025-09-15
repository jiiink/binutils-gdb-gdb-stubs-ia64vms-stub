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
term_raw_write (const char *str, unsigned int len)
{
  unsigned short status;
  struct _iosb iosb;

  status = sys$qiow (EFN$C_ENF,
                     term_chan,
                     IO$_WRITEVBLK,
                     &iosb,
                     0,
                     0,
                     (char *) str,
                     len,
                     0,
                     0,
                     0,
                     0);

  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }

  /* Since LIB$SIGNAL does not return, we only reach here if the call to
   * sys$qiow was successful. In that case, we must check the final I/O
   * completion status from the I/O status block (IOSB). */
  if (!(iosb.iosb$w_status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (iosb.iosb$w_status);
    }
}

/* Flush the term buffer.  */

static void
term_flush(void)
{
    if (term_buf_len == 0)
    {
        return;
    }

    char *current_pos = term_buf;
    size_t remaining = term_buf_len;

    while (remaining > 0)
    {
        ssize_t written = term_raw_write(current_pos, remaining);

        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            size_t bytes_flushed = term_buf_len - remaining;
            if (bytes_flushed > 0)
            {
                memmove(term_buf, current_pos, remaining);
            }
            term_buf_len = remaining;
            return;
        }

        current_pos += written;
        remaining -= (size_t)written;
    }

    term_buf_len = 0;
}

/* Write a single character, without translation.  */

static void
term_raw_putchar (char c)
{
  if (term_buf_len >= sizeof (term_buf))
  {
    term_flush ();
  }

  if (term_buf_len < sizeof (term_buf))
  {
    term_buf[term_buf_len++] = c;
  }
}

/* Write character C.  Translate '\n' to '\n\r'.  */

static void
term_putc (char c)
{
  switch (c)
    {
    case '\n':
      term_raw_putchar ('\n');
      term_raw_putchar ('\r');
      term_flush ();
      break;
    case '\r':
      term_raw_putchar ('\r');
      break;
    default:
      term_raw_putchar ((c < 32) ? '.' : c);
      break;
    }
}

/* Write a C string.  */

static void
term_puts (const char *str)
{
  if (!str)
    {
      return;
    }

  while (*str)
    {
      term_putc (*str);
      str++;
    }
}

/* Write LEN bytes from STR.  */

static void
term_write (const char *str, unsigned int len)
{
  if (!str)
    {
      return;
    }

  for (unsigned int i = 0; i < len; i++)
    {
      term_putc (str[i]);
    }
}

/* Write using FAO formatting.  */

static void
term_fao (const char *str, unsigned int str_len, ...)
{
  enum { FAO_BUFFER_SIZE = 128 };
  char buf[FAO_BUFFER_SIZE];
  struct dsc$descriptor_s dstr =
    { str_len, DSC$K_DTYPE_T, DSC$K_CLASS_S, (__char_ptr32)str };
  $DESCRIPTOR (buf_desc, buf);

  va_list vargs;
  int64_t *args = NULL;
  int total_args;
  int num_var_args;
  int status;
  int i;
  unsigned short j;

  va_start (vargs, str_len);

  va_count (total_args);
  num_var_args = (total_args >= 2) ? (total_args - 2) : 0;

  if (num_var_args > 0)
    {
      args = malloc ((size_t)num_var_args * sizeof (int64_t));
      if (!args)
        {
          va_end (vargs);
          return;
        }

      for (i = 0; i < num_var_args; i++)
        {
          args[i] = va_arg (vargs, int64_t);
        }
    }

  status = sys$faol_64 (&dstr, &buf_desc.dsc$w_length, &buf_desc, args);

  if (status & 1)
    {
      for (j = 0; j < buf_desc.dsc$w_length; j++)
        {
          term_raw_putchar (buf[j]);
          if (buf[j] == '\n')
            {
              term_flush ();
            }
        }
    }

  free (args);
  va_end (vargs);
}

#define TERM_FAO(STR, ...) term_fao (STR, sizeof (STR) - 1, __VA_ARGS__)

/* New line.  */

static inline void
term_putnl (void)
{
  term_putc ('\n');
}

/* Initialize terminal.  */

static void
term_init (void)
{
  unsigned int status;
  unsigned short len;
  char resstring[LNM$C_NAMLENGTH];
  ILE3 item_lst[2];
  static const $DESCRIPTOR (tabdesc, "LNM$FILE_DEV");
  static const $DESCRIPTOR (logdesc, "SYS$OUTPUT");
  $DESCRIPTOR (term_desc, resstring);
  const unsigned int ESCAPE_SEQUENCE_LENGTH = 4;

  item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;

  status = SYS$TRNLNM(0, (void *)&tabdesc, (void *)&logdesc, 0, item_lst);
  if (!(status & STS$M_SUCCESS))
  {
    LIB$SIGNAL(status);
  }

  term_desc.dsc$w_length = len;

  if (resstring[0] == '\x1B')
  {
    term_desc.dsc$w_length -= ESCAPE_SEQUENCE_LENGTH;
    term_desc.dsc$a_pointer += ESCAPE_SEQUENCE_LENGTH;
  }

  status = sys$assign(&term_desc, &term_chan, 0, 0);
  if (!(status & STS$M_SUCCESS))
  {
    LIB$SIGNAL(status);
  }
}

/* Convert from native endianness to network endianness (and vice-versa).  */

#include <stdint.h>

static uint16_t wordswap(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

/* Initialize the socket connection, and wait for a client.  */

static void
check_vms_status (unsigned int status, const char *message)
{
  if (!(status & STS$M_SUCCESS))
    {
      term_puts (message);
      term_puts ("\n");
      LIB$SIGNAL (status);
    }
}

static void
check_qio_status (unsigned int status, struct _iosb *iosb,
		  const char *message)
{
  if (status & STS$M_SUCCESS)
    {
      status = iosb->iosb$w_status;
    }
  check_vms_status (status, message);
}

static void
sock_init (void)
{
  struct _iosb iosb;
  unsigned int status;
  unsigned short listen_channel;

  static const $DESCRIPTOR (inet_device, "TCPIP$DEVICE:");

  status = sys$assign ((void *) &inet_device, &listen_channel, 0, 0);
  if (status & STS$M_SUCCESS)
    {
      status = sys$assign ((void *) &inet_device, &conn_channel, 0, 0);
    }
  check_vms_status (status, "Failed to assign I/O channel(s)");

  struct sockchar listen_sockchar = {
    .prot = TCPIP$C_TCP,
    .type = TCPIP$C_STREAM,
    .af = TCPIP$C_AF_INET
  };

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb, 0, 0,
		     &listen_sockchar, 0, 0, 0, 0, 0);
  check_qio_status (status, &iosb, "Failed to create socket");

  const int optval = 1;
  ILE2 reuseaddr_itemlst = {
    .ile2$w_length = sizeof (optval),
    .ile2$w_code = TCPIP$C_REUSEADDR,
    .ile2$ps_bufaddr = (void *) &optval
  };

  ILE2 sockopt_itemlst = {
    .ile2$w_length = sizeof (reuseaddr_itemlst),
    .ile2$w_code = TCPIP$C_SOCKOPT,
    .ile2$ps_bufaddr = &reuseaddr_itemlst
  };

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb, 0, 0,
		     0, 0, 0, 0, (__int64) &sockopt_itemlst, 0);
  check_qio_status (status, &iosb, "Failed to set socket option");

  struct sockaddr_in serv_addr = { 0 };
  serv_addr.sin_family = TCPIP$C_AF_INET;
  serv_addr.sin_port = wordswap (serv_port);
  serv_addr.sin_addr.s_addr = TCPIP$C_INADDR_ANY;

  ILE2 serv_itemlst = {
    .ile2$w_length = sizeof (serv_addr),
    .ile2$w_code = TCPIP$C_SOCK_NAME,
    .ile2$ps_bufaddr = &serv_addr
  };

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb, 0, 0,
		     0, 0, (__int64) &serv_itemlst, 0, 0, 0);
  check_qio_status (status, &iosb, "Failed to bind socket");

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_SETMODE, &iosb, 0, 0,
		     0, 0, 0, 1, 0, 0);
  check_qio_status (status, &iosb, "Failed to set socket passive");

  TERM_FAO ("Waiting for a client connection on port: !ZW!/",
	    wordswap (serv_addr.sin_port));

  status = sys$qiow (EFN$C_ENF, listen_channel, IO$_ACCESS | IO$M_ACCEPT,
		     &iosb, 0, 0, 0, 0, 0, (__int64) &conn_channel, 0, 0);
  check_qio_status (status, &iosb, "Failed to accept client connection");

  unsigned short cli_addrlen;
  struct sockaddr_in cli_addr = { 0 };
  ILE3 cli_itemlst = {
    .ile3$w_length = sizeof (cli_addr),
    .ile3$w_code = TCPIP$C_SOCK_NAME,
    .ile3$ps_bufaddr = &cli_addr,
    .ile3$ps_retlen_addr = &cli_addrlen
  };

  status = sys$qiow (EFN$C_ENF, conn_channel, IO$_SENSEMODE, &iosb, 0, 0,
		     0, 0, 0, (__int64) &cli_itemlst, 0, 0);
  check_qio_status (status, &iosb, "Failed to get client name");

  TERM_FAO ("Accepted connection from host: !UB.!UB,!UB.!UB, port: !UW!/",
	    (cli_addr.sin_addr.s_addr >> 0) & 0xff,
	    (cli_addr.sin_addr.s_addr >> 8) & 0xff,
	    (cli_addr.sin_addr.s_addr >> 16) & 0xff,
	    (cli_addr.sin_addr.s_addr >> 24) & 0xff,
	    wordswap (cli_addr.sin_port));
}

/* Close the socket.  */

static void
handle_vms_error(unsigned int status, const char *message)
{
    if (!(status & STS$M_SUCCESS))
    {
        term_puts(message);
        LIB$SIGNAL(status);
    }
}

static void
sock_close (void)
{
    struct _iosb iosb;
    unsigned int status;

    status = sys$qiow(EFN$C_ENF,
                      conn_channel,
                      IO$_DEACCESS,
                      &iosb,
                      0,
                      0,
                      0, 0, 0, 0, 0, 0);

    if (status & STS$M_SUCCESS)
    {
        status = iosb.iosb$w_status;
    }
    handle_vms_error(status, "Failed to close socket\n");

    status = sys$dassgn(conn_channel);
    handle_vms_error(status, "Failed to deassign I/O channel\n");
}

/* Mark a page as R/W.  Return old rights.  */

static unsigned int
page_set_rw (unsigned __int64 startva, unsigned __int64 len,
	     unsigned int *oldprot)
{
  return SYS$SETPRT_64 ((void *)startva, len, PSL$C_USER, PRT$C_UW,
			  NULL, NULL, oldprot);
}

/* Restore page rights.  */

static void
page_restore_rw (const uint64_t startva, const uint64_t len,
                 const unsigned int prot)
{
  const unsigned int status =
    SYS$SETPRT_64 ((void *)startva, len, PSL$C_USER, prot, NULL, NULL, NULL);

  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }
}

/* Get the TEB (thread environment block).  */

static pthread_t get_teb(void)
{
    const uintptr_t thread_pointer_val = (uintptr_t)__getReg(_IA64_REG_TP);
    return (pthread_t)thread_pointer_val;
}

/* Enable thread scheduling if VAL is true.  */

static void
handle_scheduling_error (unsigned int signal_status, unsigned int log_status, int val)
{
  TERM_FAO ("set_thread_scheduling error, val=!SL, status=!XL!/",
            val, log_status);
  lib$signal (signal_status);
}

static unsigned int
set_thread_scheduling (int val)
{
  if (!dbgext_func)
    {
      return 0;
    }

  struct dbgext_control_block blk = {
    .dbgext$w_function_code = DBGEXT$K_STOP_ALL_OTHER_TASKS,
    .dbgext$w_facility_id = CMA$_FACILITY,
    .dbgext$l_stop_value = val,
    .dbgext$l_status = 0
  };

  const unsigned int status = dbgext_func (&blk);
  if (!(status & STS$M_SUCCESS))
    {
      handle_scheduling_error (status, blk.dbgext$l_status, val);
    }

  return blk.dbgext$l_stop_value;
}

/* Get next thread (after THR).  Start with 0.  */

static unsigned int thread_next(const unsigned int thr)
{
    if (!dbgext_func)
    {
        return 0;
    }

    struct dbgext_control_block blk = {
        .dbgext$w_function_code = DBGEXT$K_NEXT_TASK,
        .dbgext$w_facility_id   = CMA$_FACILITY,
        .dbgext$l_ada_flags     = 0,
        .dbgext$l_task_value    = thr
    };

    const unsigned int status = dbgext_func(&blk);
    if (!(status & STS$M_SUCCESS))
    {
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
    (void)context;

    if (trace_pthreaddbg)
    {
        TERM_FAO("read_callback (!XH, !XH, !SL)!/", addr, buf, size);
    }

    if (size > 0 && (buf == NULL || addr == NULL))
    {
        return -1;
    }

    ots$move(buf, size, addr);
    return 0;
}

static int
write_callback(pthreadDebugClient_t context,
               pthreadDebugTargetAddr_t addr,
               pthreadDebugLongConstAddr_t buf,
               size_t size)
{
    (void)context;

    if (size == 0)
    {
        return 0;
    }

    if (!addr || !buf)
    {
        return -1;
    }

    if (trace_pthreaddbg)
    {
        TERM_FAO("write_callback (!XH, !XH, !SL)!/", addr, buf, size);
    }

    ots$move(addr, size, buf);

    return 0;
}

static int suspend_callback(pthreadDebugClient_t context)
{
    /* Always suspended. */
    (void)context; // Mark context as intentionally unused
    return 0;
}

static int
resume_callback (pthreadDebugClient_t context)
{
  (void)context;
  return 0;
}

static int
kthdinfo_callback (pthreadDebugClient_t context,
		   pthreadDebugKId_t kid,
		   pthreadDebugKThreadInfo_p thread_info)
{
  (void)context;
  (void)kid;
  (void)thread_info;

  if (trace_pthreaddbg)
    {
      term_puts ("kthinfo_callback");
    }

  return ENOSYS;
}

static int hold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid)
{
    (void)context;
    (void)kid;

    if (trace_pthreaddbg) {
        term_puts("hold_callback");
    }

    return ENOSYS;
}

static int unhold_callback(pthreadDebugClient_t context, pthreadDebugKId_t kid)
{
    (void)context;
    (void)kid;

    if (trace_pthreaddbg) {
        term_puts("unhold_callback");
    }
    return ENOSYS;
}

static int
getfreg_callback (pthreadDebugClient_t context,
		  pthreadDebugFregs_t *reg,
		  pthreadDebugKId_t kid)
{
  (void) context;
  (void) reg;
  (void) kid;

  if (trace_pthreaddbg)
    {
      term_puts ("getfreg_callback");
    }
  return ENOSYS;
}

static int
setfreg_callback(pthreadDebugClient_t context,
                 const pthreadDebugFregs_t *reg,
                 pthreadDebugKId_t kid)
{
    (void)context;
    (void)reg;
    (void)kid;

    if (trace_pthreaddbg)
    {
        term_puts("setfreg_callback");
    }

    return ENOSYS;
}

static int
getreg_callback (pthreadDebugClient_t context,
		 pthreadDebugRegs_t *reg,
		 pthreadDebugKId_t kid)
{
  (void)context;
  (void)reg;
  (void)kid;

  if (trace_pthreaddbg)
    {
      term_puts ("getreg_callback");
    }

  return ENOSYS;
}

static int
setreg_callback (pthreadDebugClient_t context,
		 const pthreadDebugRegs_t *reg,
		 pthreadDebugKId_t kid)
{
  (void)context;
  (void)reg;
  (void)kid;

  if (trace_pthreaddbg)
    {
      term_puts ("setreg_callback");
    }
  return ENOSYS;
}

static int output_callback(pthreadDebugClient_t context,
                           pthreadDebugConstString_t line)
{
    (void)context;

    if (line != NULL) {
        (void)term_puts(line);
    }

    (void)term_putnl();

    return 0;
}

static int
error_callback(pthreadDebugClient_t context,
               pthreadDebugConstString_t line)
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
    (void)caller_context;

    static const int HEADER_SIZE = 16;

    if (size > (size_t)INT_MAX - HEADER_SIZE)
    {
        LIB$SIGNAL(SS$_INSFMEM);
    }

    int allocation_size = size + HEADER_SIZE;
    unsigned int block_address = 0;

    const unsigned int status = lib$get_vm(&allocation_size, &block_address, 0);
    if (!(status & STS$M_SUCCESS))
    {
        LIB$SIGNAL(status);
    }

    if (trace_pthreaddbg)
    {
        TERM_FAO("malloc_callback (!UL) -> !XA!/", size, block_address);
    }

    void * const block_ptr = (void *)(uintptr_t)block_address;

    *(unsigned int *)block_ptr = allocation_size;

    return (char *)block_ptr + HEADER_SIZE;
}

static void
free_callback (pthreadDebugClient_t caller_context, pthreadDebugAddr_t address)
{
  (void)caller_context;

  const size_t METADATA_OFFSET = 16;
  unsigned int *metadata_ptr = (unsigned int *)((char *)address - METADATA_OFFSET);

  int block_size = (int)(*metadata_ptr);
  unsigned int base_address = (unsigned int)(uintptr_t)metadata_ptr;

  if (trace_pthreaddbg)
    {
      TERM_FAO ("free_callback (!XA)!/", address);
    }

  unsigned int status = lib$free_vm (&block_size, &base_address, 0);
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }
}

static int
speckthd_callback (pthreadDebugClient_t caller_context,
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

typedef int (*pthread_debug_init_func_t)(void *context, pthreadDebugId_t *id);

#define THD_SEQ_INIT_FUNC_INDEX 1

static int
pthread_debug_thd_seq_init (pthreadDebugId_t *id)
{
    void * const func_ptr = pthread_debug_entries[THD_SEQ_INIT_FUNC_INDEX].func;

    if (func_ptr == NULL)
    {
        return -1;
    }

    pthread_debug_init_func_t init_func = (pthread_debug_init_func_t)func_ptr;
    return init_func(debug_context, id);
}

static int
pthread_debug_thd_seq_next (pthreadDebugId_t *id)
{
  typedef int (*thd_seq_next_func_t)(void *, pthreadDebugId_t *);

  thd_seq_next_func_t func_to_call =
    (thd_seq_next_func_t)pthread_debug_entries[2].func;

  if (func_to_call == NULL || id == NULL)
  {
    return -1;
  }

  return func_to_call(debug_context, id);
}

static int
pthread_debug_thd_seq_destroy(void)
{
    typedef int (*destroy_func_t)(void *);

    const size_t DESTROY_ENTRY_INDEX = 3;
    destroy_func_t destroy_func_ptr =
        (destroy_func_t)pthread_debug_entries[DESTROY_ENTRY_INDEX].func;

    if (destroy_func_ptr == NULL) {
        return -1;
    }

    return destroy_func_ptr(debug_context);
}

static int
pthread_debug_thd_get_info(pthreadDebugId_t id,
                               pthreadDebugThreadInfo_t *info)
{
    typedef int (*thd_get_info_func_t)(void *, pthreadDebugId_t,
                                       pthreadDebugThreadInfo_t *);
    const int GET_INFO_FUNC_INDEX = 4;
    thd_get_info_func_t func;

    if (info == NULL) {
        return -1;
    }

    func = (thd_get_info_func_t)pthread_debug_entries[GET_INFO_FUNC_INDEX].func;

    if (func == NULL) {
        return -1;
    }

    return func(debug_context, id, info);
}

#define PTHREAD_DEBUG_GET_INFO_ADDR_OP 5

typedef int (*pthread_debug_get_info_func_t) (void *context, pthread_t thr,
                                              pthreadDebugThreadInfo_t *info);

static int
pthread_debug_thd_get_info_addr (pthread_t thr,
                                 pthreadDebugThreadInfo_t *info)
{
  pthread_debug_get_info_func_t get_info_func =
    (pthread_debug_get_info_func_t) pthread_debug_entries[PTHREAD_DEBUG_GET_INFO_ADDR_OP].func;

  if (!get_info_func)
    {
      return -1;
    }

  return get_info_func (debug_context, thr, info);
}

#define PTHREAD_DEBUG_GET_REG_INDEX 6

typedef int (*pthread_get_reg_func_t)(void *context, pthreadDebugId_t thr, pthreadDebugRegs_t *regs);

static int
pthread_debug_thd_get_reg (pthreadDebugId_t thr,
                           pthreadDebugRegs_t *regs)
{
    if (regs == NULL) {
        return EINVAL;
    }

    pthread_get_reg_func_t get_reg_func =
        (pthread_get_reg_func_t)pthread_debug_entries[PTHREAD_DEBUG_GET_REG_INDEX].func;

    if (get_reg_func == NULL) {
        return ENOSYS;
    }

    return get_reg_func(debug_context, thr, regs);
}

#define PTHREAD_DEBUG_CMD_FUNC_INDEX 7

typedef int (*pthread_debug_cmd_t)(void *context, const char *cmd);

static int
stub_pthread_debug_cmd (const char *cmd)
{
  pthread_debug_cmd_t func_ptr =
    (pthread_debug_cmd_t) pthread_debug_entries[PTHREAD_DEBUG_CMD_FUNC_INDEX].func;

  if (func_ptr == NULL)
  {
    return -1;
  }

  return func_ptr(debug_context, cmd);
}

/* Show all the threads.  */

static void
threads_show(void)
{
    pthreadDebugId_t id;
    pthreadDebugThreadInfo_t info;

    int res = pthread_debug_thd_seq_init(&id);
    if (res != 0) {
        TERM_FAO("seq init failed, res=!SL!/", res);
        return;
    }

    do {
        if (pthread_debug_thd_get_info(id, &info) != 0) {
            TERM_FAO("thd_get_info !SL failed!/", id);
            break;
        }
    } while (pthread_debug_thd_seq_next(&id) == 0);

    pthread_debug_thd_seq_destroy();
}

/* Initialize pthread support.  */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef int (*pthread_debug_init_t)(void **, const void *, void *, void **);

static void find_required_symbol(const void *image_desc, const void *symbol_desc, void **symbol_addr)
{
    int status = lib$find_image_symbol((void *)image_desc, (void *)symbol_desc, (int *)symbol_addr);
    if (!(status & STS$M_SUCCESS))
    {
        lib$signal(status);
    }
}

static void
threads_init (void)
{
    static const $DESCRIPTOR (pthread_debug_desc, "PTHREAD$DBGSHR");
    static const $DESCRIPTOR (dbgsymtable_desc, "PTHREAD_DBG_SYMTABLE");

    void *dbg_symtable = NULL;
    void *caller_context = NULL;

    find_required_symbol(&pthread_rtl_desc, &dbgsymtable_desc, &dbg_symtable);

    for (size_t i = 0; i < ARRAY_SIZE(pthread_debug_entries); i++)
    {
        struct dsc$descriptor_s sym = {
            pthread_debug_entries[i].namelen,
            DSC$K_DTYPE_T, DSC$K_CLASS_S,
            (char *)pthread_debug_entries[i].name
        };
        find_required_symbol(&pthread_debug_desc, &sym, &pthread_debug_entries[i].func);
    }

    if (trace_pthreaddbg)
    {
        TERM_FAO ("debug symtable: !XH!/", dbg_symtable);
    }

    if (pthread_debug_entries[0].func)
    {
        pthread_debug_init_t init_func = (pthread_debug_init_t)pthread_debug_entries[0].func;
        int status = init_func(&caller_context, &pthread_debug_callbacks, dbg_symtable, &debug_context);

        if (status == 0)
        {
            TERM_FAO ("pthread debug done!/", 0);
        }
        else
        {
            TERM_FAO ("cannot initialize pthread_debug: !UL!/", status);
        }
    }
}

/* Convert an hexadecimal character to a nibble.  Return -1 in case of
   error.  */

static int
hex2nibble(unsigned char h)
{
    if (h >= '0' && h <= '9') {
        return h - '0';
    }

    unsigned char const lower_h = h | 0x20;
    if (lower_h >= 'a' && lower_h <= 'f') {
        return lower_h - 'a' + 10;
    }

    return -1;
}

/* Convert an hexadecimal 2 character string to a byte.  Return -1 in case
   of error.  */

static int
hex2byte (const unsigned char *p)
{
  if (!p)
    {
      return -1;
    }

  const int h = hex2nibble (p[0]);
  const int l = hex2nibble (p[1]);

  if (h < 0 || l < 0)
    {
      return -1;
    }

  return (h << 4) | l;
}

/* Convert a byte V to a 2 character strings P.  */

static const char hex[] = "0123456789abcdef";

static void byte2hex(unsigned char *p, unsigned char v)
{
    if (!p)
    {
        return;
    }

    p[0] = hex[v >> 4];
    p[1] = hex[v & 0xf];
}

/* Convert a quadword V to a 16 character strings P.  */

static void
quad2hex (unsigned char *p, uint64_t v)
{
  if (p == NULL)
    {
      return;
    }

  const int num_nibbles = sizeof(v) * 2;
  for (int i = 0; i < num_nibbles; ++i)
    {
      const int shift = (num_nibbles - 1 - i) * 4;
      const unsigned char nibble = (v >> shift) & 0x0F;
      p[i] = hex[nibble];
    }
}

static void
long2pkt(unsigned int v)
{
    const size_t num_hex_digits = sizeof(v) * 2;
    const int bits_per_nibble = 4;

    for (size_t i = 0; i < num_hex_digits; i++)
    {
        const unsigned int shift = (num_hex_digits - 1 - i) * bits_per_nibble;
        const unsigned int nibble = (v >> shift) & 0x0FU;

        gdb_buf[gdb_blen + i] = hex[nibble];
    }

    gdb_blen += num_hex_digits;
}

/* Generate an error packet.  */

#include <stddef.h>
#include <stdint.h>

static void
packet_error (uint8_t err)
{
  static const size_t ERROR_INDICATOR_OFFSET = 1;
  static const size_t ERROR_CODE_OFFSET = 2;
  static const size_t ERROR_PACKET_LENGTH = 4;

  gdb_buf[ERROR_INDICATOR_OFFSET] = 'E';
  byte2hex (gdb_buf + ERROR_CODE_OFFSET, err);
  gdb_blen = ERROR_PACKET_LENGTH;
}

/* Generate an OK packet.  */

static void
packet_ok (void)
{
  enum
  {
    PAYLOAD_OFFSET = 1,
    PAYLOAD_LENGTH = 2
  };

  gdb_buf[PAYLOAD_OFFSET] = 'O';
  gdb_buf[PAYLOAD_OFFSET + 1] = 'K';
  gdb_blen = PAYLOAD_OFFSET + PAYLOAD_LENGTH;
}

/* Append a register to the packet.  */

static void
ireg2pkt (const unsigned char *p)
{
  if (!p)
    {
      return;
    }

  const size_t NUM_REGISTER_BYTES = 8;
  const size_t HEX_CHARS_PER_BYTE = 2;
  const size_t space_needed = NUM_REGISTER_BYTES * HEX_CHARS_PER_BYTE;

  if (gdb_blen > sizeof (gdb_buf) - space_needed)
    {
      return;
    }

  for (size_t i = 0; i < NUM_REGISTER_BYTES; i++)
    {
      byte2hex (gdb_buf + gdb_blen, p[i]);
      gdb_blen += HEX_CHARS_PER_BYTE;
    }
}

/* Append a C string (ASCIZ) to the packet.  */

static void
str2pkt (const char *str)
{
  if (str == NULL)
    {
      return;
    }

  /* GDB_BUF_SIZE must be defined as the total size of gdb_buf */
  while (*str != '\0' && gdb_blen < GDB_BUF_SIZE)
    {
      gdb_buf[gdb_blen++] = *str++;
    }
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
  const char escape_char = '}';
  const char xor_key = 0x20;
  unsigned int i;

  for (i = 0; i < len; i++)
    {
      const unsigned char current_char = b[i];
      int is_special_char = (current_char == '#' || current_char == '$' ||
                             current_char == '}' || current_char == '*' ||
                             current_char == '\0');

      size_t space_needed = is_special_char ? 2 : 1;

      if (gdb_blen + space_needed > GDB_BUF_SIZE)
        {
          break;
        }

      if (is_special_char)
        {
          gdb_buf[gdb_blen++] = escape_char;
          gdb_buf[gdb_blen++] = current_char ^ xor_key;
        }
      else
        {
          gdb_buf[gdb_blen++] = current_char;
        }
    }
}

/* Append LEN bytes from B to the current gdb packet (encode in hex).  */

static void
mem2hex(const unsigned char *b, unsigned int len)
{
    /* GDB_BUF_SIZE is assumed to be a pre-defined macro for the total size of gdb_buf. */
    char *dest = gdb_buf + gdb_blen;
    const char * const dest_end = gdb_buf + GDB_BUF_SIZE;

    for (unsigned int i = 0; i < len; i++)
    {
        if (dest > dest_end - 2)
        {
            break;
        }
        byte2hex(dest, b[i]);
        dest += 2;
    }

    gdb_blen = (unsigned int)(dest - gdb_buf);
}

/* Handle the 'q' packet.  */

static unsigned int first_thread;
static unsigned int last_thread;

static void
handle_qC_packet (void)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'Q';
  gdb_buf[2] = 'C';
  gdb_blen = 3;
  if (has_threads)
    {
      long2pkt ((unsigned long) get_teb ());
    }
}

static int
parse_qXfer_uib_args (const unsigned char *pkt, unsigned int pkt_len,
		      unsigned int start_pos, unsigned __int64 *pc)
{
  unsigned int pos = start_pos;
  unsigned int off;
  unsigned int len;

  if (pos >= pkt_len)
    return -1;
  *pc = pkt2val (pkt, &pos);

  if (pos >= pkt_len || pkt[pos] != ':')
    return -1;
  pos++;

  if (pos >= pkt_len)
    return -1;
  off = pkt2val (pkt, &pos);

  if (pos >= pkt_len || pkt[pos] != ',' || off != 0)
    return -1;
  pos++;

  if (pos >= pkt_len)
    return -1;
  len = pkt2val (pkt, &pos);

  if (pos >= pkt_len || pkt[pos] != '#' || len != 0x20)
    return -1;

  return 0;
}

static void
handle_qXfer_uib_packet (const unsigned char *pkt, unsigned int pktlen,
			 unsigned int prefix_len)
{
  unsigned __int64 pc;

  packet_error (0);

  if (parse_qXfer_uib_args (pkt, pktlen, prefix_len, &pc) != 0)
    {
      return;
    }

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

  res = SYS$GET_UNWIND_ENTRY_INFO (pc, &uei.data, 0);
  if (res != SS$_NORMAL)
    {
      ots$fill (uei.bytes, sizeof (uei.bytes), 0);
    }

  if (trace_unwind)
    {
      TERM_FAO ("Unwind request for !XH, status=!XL, uib=!XQ, GP=!XQ!/",
		pc, res, uei.data.uib_start_va, uei.data.gp_value);
    }

  gdb_buf[0] = '$';
  gdb_buf[1] = 'l';
  gdb_blen = 2;
  mem2bin (uei.bytes, sizeof (uei.bytes));
}

static void
handle_qfThreadInfo_packet (void)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'm';
  gdb_blen = 2;

  if (!has_threads)
    {
      gdb_buf[1] = 'l';
      return;
    }
  first_thread = thread_next (0);
  last_thread = first_thread;
  long2pkt (first_thread);
}

static void
handle_qsThreadInfo_packet (void)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = 'm';
  gdb_blen = 2;
  while (dbgext_func)
    {
      unsigned int res = thread_next (last_thread);
      if (res == first_thread)
	{
	  break;
	}
      if (gdb_blen > 2)
	{
	  gdb_buf[gdb_blen++] = ',';
	}
      long2pkt (res);
      last_thread = res;

      if (gdb_blen > sizeof (gdb_buf) - 16)
	{
	  break;
	}
    }

  if (gdb_blen == 2)
    {
      gdb_buf[1] = 'l';
    }
}

static void
handle_qThreadExtraInfo_packet (const unsigned char *pkt, unsigned int pktlen,
				unsigned int prefix_len)
{
  pthread_t thr;
  unsigned int pos = prefix_len;
  pthreadDebugThreadInfo_t info;
  int res;

  packet_error (0);
  if (!has_threads)
    {
      return;
    }

  thr = (pthread_t) pkt2val (pkt, &pos);
  if (pos >= pktlen || pkt[pos] != '#')
    {
      return;
    }

  res = pthread_debug_thd_get_info_addr (thr, &info);
  if (res != 0)
    {
      TERM_FAO ("qThreadExtraInfo (!XH) failed: !SL!/", thr, res);
      return;
    }
  gdb_buf[0] = '$';
  gdb_blen = 1;
  mem2hex ((const unsigned char *) "VMS-thread", 11);
}

static void
handle_qSupported_packet (void)
{
  gdb_buf[0] = '$';
  gdb_blen = 1;
  str2pkt ("qXfer:uib:read+");
}

static void
handle_unknown_q_packet (const unsigned char *pkt, unsigned int pktlen)
{
  if (trace_pkt)
    {
      term_puts ("unknown <: ");
      term_write ((char *) pkt, pktlen);
      term_putnl ();
    }
}

static void
handle_q_packet (const unsigned char *pkt, unsigned int pktlen)
{
  static const char xfer_uib[] = "qXfer:uib:read:";
  static const char qfthreadinfo[] = "qfThreadInfo";
  static const char qsthreadinfo[] = "qsThreadInfo";
  static const char qthreadextrainfo[] = "qThreadExtraInfo,";
  static const char qsupported[] = "qSupported:";

  if (pktlen == 2 && pkt[1] == 'C')
    {
      handle_qC_packet ();
    }
  else if (pktlen > (sizeof (xfer_uib) - 1)
	   && memcmp (pkt, xfer_uib, sizeof (xfer_uib) - 1) == 0)
    {
      handle_qXfer_uib_packet (pkt, pktlen, sizeof (xfer_uib) - 1);
    }
  else if (pktlen == (sizeof (qfthreadinfo) - 1)
	   && memcmp (pkt, qfthreadinfo, sizeof (qfthreadinfo) - 1) == 0)
    {
      handle_qfThreadInfo_packet ();
    }
  else if (pktlen == (sizeof (qsthreadinfo) - 1)
	   && memcmp (pkt, qsthreadinfo, sizeof (qsthreadinfo) - 1) == 0)
    {
      handle_qsThreadInfo_packet ();
    }
  else if (pktlen > (sizeof (qthreadextrainfo) - 1)
	   && memcmp (pkt, qthreadextrainfo,
		      sizeof (qthreadextrainfo) - 1) == 0)
    {
      handle_qThreadExtraInfo_packet (pkt, pktlen,
				      sizeof (qthreadextrainfo) - 1);
    }
  else if (pktlen > (sizeof (qsupported) - 1)
	   && memcmp (pkt, qsupported, sizeof (qsupported) - 1) == 0)
    {
      handle_qSupported_packet ();
    }
  else
    {
      handle_unknown_q_packet (pkt, pktlen);
    }
}

/* Handle the 'v' packet.  */

static int
handle_v_packet (const unsigned char *pkt, unsigned int pktlen)
{
  static const char vcontq[] = "vCont?";
  const unsigned int vcontq_len = sizeof (vcontq) - 1;

  if (pktlen != vcontq_len
      || !ots$strcmp_eql (pkt, vcontq_len, vcontq, vcontq_len))
    {
      if (trace_pkt)
        {
          term_puts ("unknown <: ");
          term_write ((char *) pkt, pktlen);
          term_putnl ();
        }
      return 0;
    }

  gdb_buf[0] = '$';
  gdb_blen = 1;
  str2pkt ("vCont;c;s");

  return 0;
}

/* Get regs for the selected thread.  */

static void
populate_ia64_regs_from_pthread_regs (struct ia64_all_regs *dest,
                                      const pthreadDebugRegs_t *src)
{
  dest->gr[1].v = src->gp;
  dest->gr[4].v = src->r4;
  dest->gr[5].v = src->r5;
  dest->gr[6].v = src->r6;
  dest->gr[7].v = src->r7;
  dest->gr[12].v = src->sp;
  dest->br[0].v = src->rp;
  dest->br[1].v = src->b1;
  dest->br[2].v = src->b2;
  dest->br[3].v = src->b3;
  dest->br[4].v = src->b4;
  dest->br[5].v = src->b5;
  dest->ip.v = src->ip;
  dest->bsp.v = src->bspstore; /* FIXME: it is correct ?  */
  dest->pfs.v = src->pfs;
  dest->pr.v = src->pr;
}

static struct ia64_all_regs *
get_selected_regs (void)
{
  if (selected_thread == 0 || selected_thread == get_teb ())
    {
      return &excp_regs;
    }

  if (selected_thread == sel_regs_pthread)
    {
      return &sel_regs;
    }

  pthreadDebugRegs_t regs;
  if (pthread_debug_thd_get_reg (selected_id, &regs) != 0)
    {
      return NULL;
    }

  populate_ia64_regs_from_pthread_regs (&sel_regs, &regs);
  sel_regs_pthread = selected_thread;

  return &sel_regs;
}

/* Create a status packet.  */

static const char GDB_THREAD_STATUS_PREFIX[] = "$T05thread:";
static const char GDB_STOP_REPLY_PACKET[] = "$S05";

static void
packet_status (void)
{
  gdb_blen = 0;

  if (has_threads)
    {
      str2pkt (GDB_THREAD_STATUS_PREFIX);
      long2pkt ((unsigned long) get_teb ());
      str2pkt (";");
    }
  else
    {
      str2pkt (GDB_STOP_REPLY_PACKET);
    }
}

/* Return 1 to continue.  */

static int
check_memory_access (unsigned __int64 addr, unsigned int l, int write_access)
{
  unsigned __int64 paddr = addr & ~VMS_PAGE_MASK;
  unsigned int bytes_to_check = l + (addr & VMS_PAGE_MASK);

  while (1)
    {
      int access_ok = write_access ? __probew (paddr, 0) : __prober (paddr, 0);
      if (access_ok != 1)
	{
	  return 0;
	}
      if (bytes_to_check <= VMS_PAGE_SIZE)
	{
	  break;
	}
      bytes_to_check -= VMS_PAGE_SIZE;
      paddr += VMS_PAGE_SIZE;
    }
  return 1;
}

static int
handle_read_memory (unsigned char *pkt, unsigned int len, unsigned int *pos_ptr)
{
  unsigned int pos = *pos_ptr;
  unsigned __int64 addr = pkt2val (pkt, &pos);
  if (pos >= len || pkt[pos] != ',')
    {
      packet_error (0);
      return 0;
    }
  pos++;
  unsigned int l = pkt2val (pkt, &pos);
  if (pos >= len || pkt[pos] != '#')
    {
      packet_error (0);
      return 0;
    }

  if (!check_memory_access (addr, l, 0))
    {
      packet_error (2);
      return 0;
    }

  gdb_blen = 1;
  for (unsigned int i = 0; i < l; i++)
    {
      byte2hex (gdb_buf + gdb_blen, ((unsigned char *) addr)[i]);
      gdb_blen += 2;
    }
  return 0;
}

static int
handle_write_memory (unsigned char *pkt, unsigned int len,
		     unsigned int *pos_ptr)
{
  unsigned int pos = *pos_ptr;
  unsigned __int64 addr = pkt2val (pkt, &pos);
  if (pos >= len || pkt[pos] != ',')
    {
      packet_error (0);
      return 0;
    }
  pos++;
  unsigned int l = pkt2val (pkt, &pos);
  if (pos >= len || pkt[pos] != ':')
    {
      packet_error (0);
      return 0;
    }
  pos++;

  if ((len - pos) < (l * 2))
    {
      packet_error (0);
      return 0;
    }

  unsigned int oldprot;
  page_set_rw (addr, l, &oldprot);

  if (!check_memory_access (addr, l, 1))
    {
      page_restore_rw (addr, l, oldprot);
      return 0;
    }

  for (unsigned int i = 0; i < l; i++)
    {
      int v = hex2byte (pkt + pos);
      pos += 2;
      ((unsigned char *) addr)[i] = v;
    }

  for (unsigned int i = 0; i < l; i += 15)
    {
      __fc (addr + i);
    }
  __fc (addr + l);

  page_restore_rw (addr, l, oldprot);
  packet_ok ();
  return 0;
}

static void
write_register_to_packet (const unsigned char *reg_bytes)
{
  gdb_blen = 1;
  for (unsigned int i = 0; i < 8; i++)
    {
      byte2hex (gdb_buf + gdb_blen, reg_bytes[i]);
      gdb_blen += 2;
    }
}

static int
handle_read_single_register (unsigned char *pkt, unsigned int len,
			     unsigned int *pos_ptr)
{
  unsigned int num = pkt2val (pkt, pos_ptr);
  if (*pos_ptr != len)
    {
      packet_error (0);
      return 0;
    }

  struct ia64_all_regs *regs = get_selected_regs ();

  switch (num)
    {
    case IA64_IP_REGNUM:
      write_register_to_packet (regs->ip.b);
      break;
    case IA64_BR0_REGNUM:
      write_register_to_packet (regs->br[0].b);
      break;
    case IA64_PSR_REGNUM:
      write_register_to_packet (regs->psr.b);
      break;
    case IA64_BSP_REGNUM:
      write_register_to_packet (regs->bsp.b);
      break;
    case IA64_CFM_REGNUM:
      write_register_to_packet (regs->cfm.b);
      break;
    case IA64_PFS_REGNUM:
      write_register_to_packet (regs->pfs.b);
      break;
    case IA64_PR_REGNUM:
      write_register_to_packet (regs->pr.b);
      break;
    default:
      TERM_FAO ("gdbserv: unhandled reg !UW!/", num);
      packet_error (0);
      return 0;
    }
  return 0;
}

static int
handle_set_thread (unsigned char *pkt, unsigned int len)
{
  if (len < 2)
    {
      packet_error (0);
      return 0;
    }
  switch (pkt[1])
    {
    case 'g':
      {
	unsigned int pos = 2;
	unsigned __int64 val = pkt2val (pkt, &pos);
	if (pos != len)
	  {
	    packet_error (0);
	    return 0;
	  }

	if (val == 0)
	  {
	    selected_thread = get_teb ();
	    selected_id = 0;
	  }
	else
	  {
	    if (!has_threads)
	      {
		packet_error (0);
		return 0;
	      }
	    pthreadDebugThreadInfo_t info;
	    int res =
	      pthread_debug_thd_get_info_addr ((pthread_t) val, &info);
	    if (res != 0)
	      {
		TERM_FAO ("qThreadExtraInfo (!XH) failed: !SL!/", val, res);
		packet_error (0);
		return 0;
	      }
	    selected_thread = info.teb;
	    selected_id = info.sequence;
	  }
	packet_ok ();
	return 0;
      }
    case 'c':
      if ((len == 3 && pkt[2] == '0') ||
	  (len == 4 && pkt[2] == '-' && pkt[3] == '1'))
	{
	  packet_ok ();
	  return 0;
	}
      break;
    default:
      break;
    }

  packet_error (0);
  return 0;
}

static int
handle_thread_alive (unsigned char *pkt, unsigned int len,
		     unsigned int *pos_ptr)
{
  if (!has_threads)
    {
      packet_ok ();
      return 0;
    }

  unsigned __int64 val = pkt2val (pkt, pos_ptr);
  if (*pos_ptr != len)
    {
      packet_error (0);
      return 0;
    }

  unsigned int fthr = thread_next (0);
  if (fthr == 0)
    {
      packet_error (0);
      return 0;
    }

  unsigned int thr = fthr;
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

  packet_error (0);
  return 0;
}

static int
handle_vms_command (unsigned char *pkt, unsigned int len)
{
  const char vms_prefix[] = "MS ";
  const unsigned int prefix_len = sizeof (vms_prefix) - 1;

  if (len <= 1 + prefix_len
      || strncmp ((const char *) pkt + 1, vms_prefix, prefix_len) != 0)
    {
      return 0;
    }

  if (!has_threads)
    {
      packet_error (0);
      return 0;
    }

  char cmd_buf[256];
  unsigned int cmd_len = len - (1 + prefix_len);

  if (cmd_len >= sizeof (cmd_buf))
    {
      packet_error (0);
      return 0;
    }

  memcpy (cmd_buf, pkt + 1 + prefix_len, cmd_len);
  cmd_buf[cmd_len] = '\0';
  stub_pthread_debug_cmd (cmd_buf);
  packet_ok ();
  return 0;
}

static int
handle_packet (unsigned char *pkt, unsigned int len)
{
  gdb_buf[0] = '$';
  gdb_blen = 1;

  if (len == 0)
    {
      return 0;
    }

  unsigned int pos = 1;

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
	  excp_regs.psr.v &= ~(unsigned __int64) PSR$M_SS;
	  return 1;
	}
      packet_error (0);
      return 0;
    case 'g':
      if (len == 1)
	{
	  struct ia64_all_regs *regs = get_selected_regs ();
	  unsigned char *p = regs->gr[0].b;
	  gdb_blen = 1;
	  for (unsigned int i = 0; i < 8 * 32; i++)
	    {
	      byte2hex (gdb_buf + gdb_blen, p[i]);
	      gdb_blen += 2;
	    }
	  return 0;
	}
      break;
    case 'H':
      return handle_set_thread (pkt, len);
    case 'k':
      SYS$EXIT (SS$_NORMAL);
      break;
    case 'm':
      return handle_read_memory (pkt, len, &pos);
    case 'M':
      return handle_write_memory (pkt, len, &pos);
    case 'p':
      return handle_read_single_register (pkt, len, &pos);
    case 'q':
      handle_q_packet (pkt, len);
      return 0;
    case 's':
      if (len == 1)
	{
	  excp_regs.psr.v |= (unsigned __int64) PSR$M_SS;
	  return 1;
	}
      packet_error (0);
      return 0;
    case 'T':
      return handle_thread_alive (pkt, len, &pos);
    case 'v':
      return handle_v_packet (pkt, len);
    case 'V':
      return handle_vms_command (pkt, len);
    default:
      if (trace_pkt)
	{
	  term_puts ("unknown <: ");
	  term_write ((char *) pkt, len);
	  term_putnl ();
	}
      break;
    }
  return 0;
}

/* Raw write to gdb.  */

static void sock_write(const unsigned char *buf, int len)
{
    struct _iosb iosb;
    unsigned int status = sys$qiow(EFN$C_ENF,
                                   conn_channel,
                                   IO$_WRITEVBLK,
                                   &iosb,
                                   0,
                                   0,
                                   (char *)buf,
                                   len,
                                   0,
                                   0,
                                   0,
                                   0);

    if (status & STS$M_SUCCESS)
    {
        status = iosb.iosb$w_status;
    }

    if (!(status & STS$M_SUCCESS))
    {
        term_puts("Failed to write data to gdb\n");
        LIB$SIGNAL(status);
    }
}

/* Compute the checksum and send the packet.  */

static void
send_pkt (void)
{
  const size_t packet_suffix_len = 3;
  size_t total_len;
  unsigned char chksum = 0;
  size_t i;

  if (gdb_blen > GDB_BUF_SIZE - packet_suffix_len)
    {
      return;
    }

  total_len = gdb_blen + packet_suffix_len;

  for (i = 1; i < gdb_blen; i++)
    {
      chksum += gdb_buf[i];
    }

  gdb_buf[gdb_blen] = '#';
  byte2hex (gdb_buf + gdb_blen + 1, chksum);

  if (sock_write (gdb_buf, total_len) != (ssize_t) total_len)
    {
      return;
    }

  if (trace_pkt > 1)
    {
      term_puts (">: ");
      term_write ((char *) gdb_buf, total_len);
      term_putnl ();
    }
}

/* Read and handle one command.  Return 1 is execution must resume.  */

static int
one_command (void)
{
  struct _iosb iosb;
  unsigned int status;
  size_t dollar_pos = 0;
  size_t sharp_pos = 0;

  while (1)
    {
      size_t buf_len = 0;
      int packet_found = 0;

      while (!packet_found)
	{
	  status = sys$qiow (EFN$C_ENF, conn_channel, IO$_READVBLK, &iosb, 0, 0,
			     gdb_buf + buf_len, sizeof (gdb_buf) - buf_len,
			     0, 0, 0, 0);

	  if (status & STS$M_SUCCESS)
	    status = iosb.iosb$w_status;

	  if (!(status & STS$M_SUCCESS))
	    {
	      term_puts ("Failed to read data from connection\n" );
	      LIB$SIGNAL (status);
	    }

#ifdef RAW_DUMP
	  term_puts ("{: ");
	  term_write ((char *)gdb_buf + buf_len, iosb.iosb$w_bcnt);
	  term_putnl ();
#endif

	  const size_t prev_len = buf_len;
	  buf_len += iosb.iosb$w_bcnt;
	  gdb_blen = buf_len;

	  if (prev_len == 0)
	    {
	      unsigned char *dollar_ptr = memchr (gdb_buf, '$', buf_len);
	      if (!dollar_ptr)
		{
		  buf_len = 0;
		  continue;
		}
	      dollar_pos = dollar_ptr - gdb_buf;
	    }

	  if (sharp_pos <= dollar_pos || sharp_pos >= prev_len)
	    {
	      unsigned char *sharp_ptr = memchr (gdb_buf + dollar_pos + 1, '#', buf_len - (dollar_pos + 1));
	      if (sharp_ptr)
		sharp_pos = sharp_ptr - gdb_buf;
	      else
		sharp_pos = 0;
	    }

	  if (sharp_pos > dollar_pos && sharp_pos + 2 < buf_len)
	    {
	      packet_found = 1;
	    }
	  else if (buf_len == sizeof (gdb_buf))
	    {
	      buf_len = 0;
	      dollar_pos = 0;
	      sharp_pos = 0;
	    }
	}

      unsigned char computed_checksum = 0;
      for (size_t i = dollar_pos + 1; i < sharp_pos; i++)
	{
	  computed_checksum += gdb_buf[i];
	}

      if (hex2byte (gdb_buf + sharp_pos + 1) == computed_checksum)
	{
	  sock_write ((const unsigned char *) "+", 1);
	  break;
	}
      else
	{
	  term_puts ("Discard bad checksum packet\n");
	}
    }

  if (trace_pkt > 1)
    {
      term_puts ("<: ");
      term_write ((char *) gdb_buf + dollar_pos, sharp_pos - dollar_pos + 1);
      term_putnl ();
    }

  if (handle_packet (gdb_buf + dollar_pos + 1, sharp_pos - dollar_pos - 1) == 1)
    return 1;

  send_pkt ();
  return 0;
}

/* Display the condition given by SIG64.  */

static void
display_excp (struct chf64$signal_array *sig64, struct chf$mech_array *mech)
{
    enum { MSG_BUFFER_SIZE = 160 };
    char msg_template[MSG_BUFFER_SIZE];
    unsigned short msg_template_len;
    $DESCRIPTOR (msg_template_desc, msg_template);
    unsigned char outadr[4];

    const unsigned int get_status = SYS$GETMSG (sig64->chf64$q_sig_name,
                                                &msg_template_len,
                                                &msg_template_desc, 0, outadr);

    if (get_status & STS$M_SUCCESS)
    {
        char formatted_msg[MSG_BUFFER_SIZE];
        unsigned short formatted_msg_len;
        struct dsc$descriptor_s formatted_msg_desc =
            { sizeof (formatted_msg), DSC$K_DTYPE_T, DSC$K_CLASS_S, formatted_msg };

        msg_template_desc.dsc$w_length = msg_template_len;

        const unsigned int faol_status = SYS$FAOL_64 (&msg_template_desc,
                                                      &formatted_msg_len,
                                                      &formatted_msg_desc,
                                                      &sig64->chf64$q_sig_arg1);
        if (faol_status & STS$M_SUCCESS)
        {
            term_write (formatted_msg, formatted_msg_len);
        }
    }
    else
    {
        term_puts ("no message");
    }

    term_putnl ();

    enum { TRACE_LEVEL_DETAILED = 1 };
    if (trace_excp > TRACE_LEVEL_DETAILED)
    {
        TERM_FAO (" Frame: !XH, Depth: !4SL, Esf: !XH!/",
                  mech->chf$q_mch_frame, mech->chf$q_mch_depth,
                  mech->chf$q_mch_esf_addr);
    }
}

/* Get all registers from current thread.  */

#define IFS_SOF_MASK 0x7f
#define IFS_CFM_MASK 0x3fffffffffull
#define BSP_REG_SHIFT 3
#define BSP_SLOT_MASK 0x3f
#define BSP_RNAT_DIVISOR 0x3f
#define LOG2_BYTES_PER_WORD 3

static unsigned __int64
calculate_adjusted_bsp (unsigned __int64 bsp, unsigned __int64 ifs)
{
  const unsigned int sof = ifs & IFS_SOF_MASK;
  const unsigned int rrb = (bsp >> BSP_REG_SHIFT) & BSP_SLOT_MASK;
  const unsigned int total_slots_for_rnat = rrb + sof;
  const unsigned int rnat_collections = total_slots_for_rnat / BSP_RNAT_DIVISOR;
  return bsp + ((sof + rnat_collections) << LOG2_BYTES_PER_WORD);
}

static void
copy_general_registers (const struct _intstk *intstk)
{
  excp_regs.gr[0].v = 0;
  excp_regs.gr[1].v = intstk->intstk$q_gp;
  excp_regs.gr[2].v = intstk->intstk$q_r2;
  excp_regs.gr[3].v = intstk->intstk$q_r3;
  excp_regs.gr[4].v = intstk->intstk$q_r4;
  excp_regs.gr[5].v = intstk->intstk$q_r5;
  excp_regs.gr[6].v = intstk->intstk$q_r6;
  excp_regs.gr[7].v = intstk->intstk$q_r7;
  excp_regs.gr[8].v = intstk->intstk$q_r8;
  excp_regs.gr[9].v = intstk->intstk$q_r9;
  excp_regs.gr[10].v = intstk->intstk$q_r10;
  excp_regs.gr[11].v = intstk->intstk$q_r11;
  excp_regs.gr[12].v = (unsigned __int64)intstk + intstk->intstk$l_stkalign;
  excp_regs.gr[13].v = intstk->intstk$q_r13;
  excp_regs.gr[14].v = intstk->intstk$q_r14;
  excp_regs.gr[15].v = intstk->intstk$q_r15;
  excp_regs.gr[16].v = intstk->intstk$q_r16;
  excp_regs.gr[17].v = intstk->intstk$q_r17;
  excp_regs.gr[18].v = intstk->intstk$q_r18;
  excp_regs.gr[19].v = intstk->intstk$q_r19;
  excp_regs.gr[20].v = intstk->intstk$q_r20;
  excp_regs.gr[21].v = intstk->intstk$q_r21;
  excp_regs.gr[22].v = intstk->intstk$q_r22;
  excp_regs.gr[23].v = intstk->intstk$q_r23;
  excp_regs.gr[24].v = intstk->intstk$q_r24;
  excp_regs.gr[25].v = intstk->intstk$q_r25;
  excp_regs.gr[26].v = intstk->intstk$q_r26;
  excp_regs.gr[27].v = intstk->intstk$q_r27;
  excp_regs.gr[28].v = intstk->intstk$q_r28;
  excp_regs.gr[29].v = intstk->intstk$q_r29;
  excp_regs.gr[30].v = intstk->intstk$q_r30;
  excp_regs.gr[31].v = intstk->intstk$q_r31;
}

static void
copy_branch_registers (const struct _intstk *intstk)
{
  excp_regs.br[0].v = intstk->intstk$q_b0;
  excp_regs.br[1].v = intstk->intstk$q_b1;
  excp_regs.br[2].v = intstk->intstk$q_b2;
  excp_regs.br[3].v = intstk->intstk$q_b3;
  excp_regs.br[4].v = intstk->intstk$q_b4;
  excp_regs.br[5].v = intstk->intstk$q_b5;
  excp_regs.br[6].v = intstk->intstk$q_b6;
  excp_regs.br[7].v = intstk->intstk$q_b7;
}

static void
read_all_registers (struct chf$mech_array *mech)
{
  if (!mech)
    {
      return;
    }

  struct _intstk *intstk =
    (struct _intstk *)mech->chf$q_mch_esf_addr;
  struct chf64$signal_array *sig64 =
    (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;

  if (!intstk || !sig64)
    {
      return;
    }

  const unsigned int cnt = sig64->chf64$w_sig_arg_count;
  if (cnt < 2)
    {
      return;
    }

  const unsigned __int64 *sig_args = &sig64->chf64$q_sig_name;
  const unsigned __int64 pc = sig_args[cnt - 2];

  excp_regs.ip.v = pc;
  excp_regs.psr.v = intstk->intstk$q_ipsr;
  excp_regs.bsp.v = calculate_adjusted_bsp (intstk->intstk$q_bsp, intstk->intstk$q_ifs);
  excp_regs.cfm.v = intstk->intstk$q_ifs & IFS_CFM_MASK;
  excp_regs.pfs.v = intstk->intstk$q_pfs;
  excp_regs.pr.v = intstk->intstk$q_preds;

  copy_general_registers (intstk);
  copy_branch_registers (intstk);
}

/* Write all registers to current thread.  FIXME: not yet complete.  */

static void
write_all_registers (struct chf$mech_array *mech)
{
  if (!mech)
    {
      return;
    }

  struct _intstk *intstk =
    (struct _intstk *)mech->chf$q_mch_esf_addr;

  if (!intstk)
    {
      return;
    }

  intstk->intstk$q_ipsr = excp_regs.psr.v;
}

/* Do debugging.  Report status to gdb and execute commands.  */

static void
do_debug (struct chf$mech_array *mech)
{
  unsigned int old_ast;
  unsigned int old_sch = 0;
  unsigned int status;

  if (!mech)
    {
      return;
    }

  status = sys$setast (0);
  if (status != SS$_WASSET && status != SS$_WASCLR)
    {
      LIB$SIGNAL (status);
    }
  old_ast = (status == SS$_WASSET);

  if (has_threads)
    {
      old_sch = set_thread_scheduling (0);
    }

  read_all_registers (mech);

  packet_status ();
  send_pkt ();

  while (one_command () == 0)
    {
    }

  write_all_registers (mech);

  if (has_threads)
    {
      set_thread_scheduling (old_sch);
    }

  status = sys$setast (old_ast);
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }
}

/* The condition handler.  That's the core of the stub.  */

static void
trace_debug_info (unsigned int cnt,
		  const struct chf64$signal_array *sig64,
		  const struct chf$mech_array *mech)
{
  struct _intstk *intstk =
    (struct _intstk *) mech->chf$q_mch_esf_addr;

  display_excp (sig64, mech);

  TERM_FAO (" intstk: !XH!/", intstk);
  for (unsigned int i = 0; i < cnt + 1; i++)
    {
      TERM_FAO ("   !XH!/", ((const unsigned __int64 *) sig64)[i]);
    }
}

static void
handle_initial_entry_breakpoint (unsigned __int64 pc)
{
  static unsigned int entry_prot;
  const unsigned int entry_bundle_size = 16;

  if (trace_entry)
    {
      term_puts ("initial entry breakpoint\n");
    }

  page_set_rw (pc, entry_bundle_size, &entry_prot);
  ots$move ((void *) pc, entry_bundle_size, entry_saved);
  __fc (pc);
  page_restore_rw (pc, entry_bundle_size, entry_prot);
}

static int
excp_handler (struct chf$signal_array *sig,
	      struct chf$mech_array *mech)
{
  /* Self protection. FIXME: Should be per thread ? */
  static int in_handler = 0;

  struct chf64$signal_array *sig64 =
    (struct chf64$signal_array *) mech->chf$ph_mch_sig64_addr;
  const unsigned int code = sig->chf$l_sig_name & STS$M_COND_ID;

  if (code == (LIB$_KEYNOTFOU & STS$M_COND_ID))
    {
      return SS$_RESIGNAL_64;
    }

  const unsigned int cnt = sig64->chf64$w_sig_arg_count;
  const unsigned __int64 *sig_args = &sig64->chf64$q_sig_name;
  const unsigned __int64 pc = sig_args[cnt - 2];

  /* Protect against recursion. */
  if (++in_handler > 1)
    {
      if (in_handler == 2)
	{
	  TERM_FAO ("gdbstub: exception in handler (pc=!XH)!!!/", pc);
	}
      sys$exit (sig->chf$l_sig_name);
    }

  if (trace_excp)
    {
      TERM_FAO ("excp_handler: code: !XL, pc=!XH!/", code, pc);
    }

  if (code == (SS$_BREAK & STS$M_COND_ID) && pc == entry_pc && entry_pc != 0)
    {
      handle_initial_entry_breakpoint (pc);
    }

  unsigned int ret;
  bool is_debug_signal;

  switch (code)
    {
    case SS$_ACCVIO & STS$M_COND_ID:
    case SS$_BREAK & STS$M_COND_ID:
    case SS$_OPCDEC & STS$M_COND_ID:
    case SS$_TBIT & STS$M_COND_ID:
    case SS$_DEBUG & STS$M_COND_ID:
      is_debug_signal = true;
      break;
    default:
      is_debug_signal = false;
      break;
    }

  if (is_debug_signal)
    {
      if (trace_excp > 1)
	{
	  trace_debug_info (cnt, sig64, mech);
	}
      else if (code == (SS$_ACCVIO & STS$M_COND_ID))
	{
	  display_excp (sig64, mech);
	}
      do_debug (mech);
      ret = SS$_CONTINUE_64;
    }
  else
    {
      display_excp (sig64, mech);
      ret = SS$_RESIGNAL_64;
    }

  in_handler--;
  /* Discard selected thread registers. */
  sel_regs_pthread = 0;
  return ret;
}

/* Setup internal trace flags according to GDBSTUB$TRACE logical.  */

static void
update_flag_from_name ($DESCRIPTOR * name_desc)
{
  for (int j = 0; j < NBR_DEBUG_FLAGS; j++)
    {
      if (str$case_blind_compare (name_desc, (void *) &debug_flags[j].name) == 0)
	{
	  debug_flags[j].val++;
	  return;
	}
    }
  TERM_FAO ("GDBSTUB$TRACE: unknown directive !AS!/", name_desc);
}

static void
parse_trace_string (char *str, unsigned short len)
{
  char *start = str;
  char *current = str;
  const char *end = str + len;
  $DESCRIPTOR sub_desc;

  for (current = str; current <= end; current++)
    {
      if (current == end || *current == ',' || *current == ';')
	{
	  if (current > start)
	    {
	      sub_desc.dsc$a_pointer = start;
	      sub_desc.dsc$w_length = current - start;
	      update_flag_from_name (&sub_desc);
	    }
	  start = current + 1;
	}
    }
}

static void
print_trace_summary (const char *resstring, unsigned short len)
{
  TERM_FAO ("GDBSTUB$TRACE=!AD ->", len, resstring);
  for (int i = 0; i < NBR_DEBUG_FLAGS; i++)
    {
      if (debug_flags[i].val > 0)
	{
	  TERM_FAO (" !AS=!ZL", &debug_flags[i].name, debug_flags[i].val);
	}
    }
  term_putnl ();
}

static void
trace_init (void)
{
  unsigned int status;
  unsigned short len = 0;
  char resstring[LNM$C_NAMLENGTH];
  static const $DESCRIPTOR (tabdesc, "LNM$DCL_LOGICAL");
  static const $DESCRIPTOR (logdesc, "GDBSTUB$TRACE");
  ILE3 item_lst[2];

  item_lst[0].ile3$w_length = sizeof (resstring);
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;

  status = SYS$TRNLNM (0,
		       (void *) &tabdesc,
		       (void *) &logdesc,
		       0,
		       &item_lst);
  if (status == SS$_NOLOGNAM)
    {
      return;
    }
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }

  parse_trace_string (resstring, len);
  print_trace_summary (resstring, len);
}


/* Entry point.  */

#define ARGS_WHEN_ATTACHED 4
#define INITIAL_BREAKPOINT_SIZE 16

#define LDRISD_FLAG_READ 0x04
#define LDRISD_FLAG_WRITE 0x02
#define LDRISD_FLAG_EXEC 0x01
#define LDRISD_FLAG_PROT 0x01000000
#define LDRISD_FLAG_SHRT 0x04000000
#define LDRISD_FLAG_SHRD 0x08000000

static void
initialize_stub (void)
{
  static int initialized = 0;
  if (initialized)
    {
      term_puts ("gdbstub: re-entry\n");
    }
  else
    {
      initialized = 1;
    }
  term_init ();
  term_puts ("Hello from gdb stub\n");
  trace_init ();
}

static void
trace_program_info (unsigned __int64 *progxfer, EIHD *imghdr, IFD *imgfile)
{
  TERM_FAO ("xfer: !XH, imghdr: !XH, ifd: !XH!/", progxfer, imghdr, imgfile);
  for (int i = -2; i < 8; i++)
    {
      TERM_FAO ("  at !2SW: !XH!/", i, progxfer[i]);
    }
}

static void
find_entry_point (unsigned __int64 *progxfer, int is_attached)
{
  if (is_attached)
    {
      entry_pc = progxfer[0];
      return;
    }

  entry_pc = 0;
  for (int i = 0; progxfer[i] != 0; i++)
    {
      entry_pc = progxfer[i];
    }
}

static const char *
get_image_type_string (unsigned char act_code)
{
  switch (act_code)
    {
    case IMCB$K_MAIN_PROGRAM:
      return "prog";
    case IMCB$K_MERGED_IMAGE:
      return "mrge";
    case IMCB$K_GLOBAL_IMAGE_SECTION:
      return "glob";
    default:
      return "????";
    }
}

static void
trace_image_segments (const LDRIMG * ldrimg)
{
  if ((long) ldrimg < 0 || ldrimg == NULL)
    {
      return;
    }

  LDRISD *ldrisd = ldrimg->ldrimg$l_segments;
  for (unsigned int j = 0; j < ldrimg->ldrimg$l_segcount; j++)
    {
      unsigned int flags = ldrisd[j].ldrisd$i_flags;
      term_puts ("   ");
      term_putc ((flags & LDRISD_FLAG_READ) ? 'R' : '-');
      term_putc ((flags & LDRISD_FLAG_WRITE) ? 'W' : '-');
      term_putc ((flags & LDRISD_FLAG_EXEC) ? 'X' : '-');
      term_puts ((flags & LDRISD_FLAG_PROT) ? " Prot" : "     ");
      term_puts ((flags & LDRISD_FLAG_SHRT) ? " Shrt" : "     ");
      term_puts ((flags & LDRISD_FLAG_SHRD) ? " Shrd" : "     ");
      TERM_FAO (" !XA-!XA!/", ldrisd[j].ldrisd$p_base,
		(unsigned __int64) ldrisd[j].ldrisd$p_base
		+ ldrisd[j].ldrisd$i_len - 1);
    }

  ldrisd = ldrimg->ldrimg$l_dyn_seg;
  if (ldrisd)
    {
      TERM_FAO ("   dynamic            !XA-!XA!/",
		ldrisd->ldrisd$p_base,
		(unsigned __int64) ldrisd->ldrisd$p_base
		+ ldrisd->ldrisd$i_len - 1);
    }
}

static void
trace_image (const IMCB * imcb)
{
  TERM_FAO ("!XA-!XA ", imcb->imcb$l_starting_address,
	    imcb->imcb$l_end_address);
  term_puts (get_image_type_string (imcb->imcb$b_act_code));
  TERM_FAO (" !AD !40AC!/", 1, "KESU" + (imcb->imcb$b_access_mode & 3),
	    imcb->imcb$t_log_image_name);

  if (trace_images >= 2)
    {
      trace_image_segments (imcb->imcb$l_ldrimg);
    }
}

static void
scan_images_and_init_threads (void)
{
  has_threads = 0;
  for (IMCB * imcb = ctl$gl_imglstptr->imcb$l_flink;
       imcb != ctl$gl_imglstptr; imcb = imcb->imcb$l_flink)
    {
      if (ots$strcmp_eql (pthread_rtl_desc.dsc$a_pointer,
			  pthread_rtl_desc.dsc$w_length,
			  imcb->imcb$t_log_image_name + 1,
			  imcb->imcb$t_log_image_name[0]))
	{
	  has_threads = 1;
	}

      if (trace_images)
	{
	  trace_image (imcb);
	}
    }

  if (has_threads)
    {
      threads_init ();
    }
}

static void
set_exception_handler (void)
{
  unsigned int status =
    sys$setexv (0, excp_handler, PSL$C_USER, (__void_ptr32) & prevhnd);
  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
    }
}

static int
set_initial_breakpoint (void)
{
  static const unsigned char initbp[INITIAL_BREAKPOINT_SIZE] = {
    0x01, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00
  };
  unsigned int entry_prot;
  unsigned int status;

  if (entry_pc == 0)
    {
      return 0;
    }

  status = page_set_rw (entry_pc, INITIAL_BREAKPOINT_SIZE, &entry_prot);

  if (!(status & STS$M_SUCCESS))
    {
      if ((status & STS$M_COND_ID) == (SS$_NOT_PROCESS_VA & STS$M_COND_ID))
	{
	  term_puts ("gdbstub: cannot set breakpoint on entry\n");
	  entry_pc = 0;
	}
      else
	{
	  LIB$SIGNAL (status);
	}
    }

  if (entry_pc == 0)
    {
      return 0;
    }

  ots$move (entry_saved, INITIAL_BREAKPOINT_SIZE, (void *) entry_pc);
  ots$move ((void *) entry_pc, INITIAL_BREAKPOINT_SIZE, (void *) initbp);
  __fc (entry_pc);
  page_restore_rw (entry_pc, INITIAL_BREAKPOINT_SIZE, entry_prot);

  return 1;
}

static void
handle_debugger_commands_on_failure (void)
{
  while (one_command () == 0)
    {
    }
}

static int
stub_start (unsigned __int64 *progxfer, void *cli_util,
	    EIHD *imghdr, IFD *imgfile,
	    unsigned int linkflag, unsigned int cliflag)
{
  (void) cli_util;
  (void) linkflag;
  (void) cliflag;

  int cnt;
  va_count (cnt);
  const int is_attached = (cnt == ARGS_WHEN_ATTACHED);

  initialize_stub ();

  if (trace_entry && !is_attached)
    {
      trace_program_info (progxfer, imghdr, imgfile);
    }

  find_entry_point (progxfer, is_attached);

  if (!is_attached && trace_entry)
    {
      if (entry_pc == 0)
	{
	  term_puts ("No entry point\n");
	  return 0;
	}
      else
	{
	  TERM_FAO ("Entry: !XH!/", entry_pc);
	}
    }

  scan_images_and_init_threads ();
  sock_init ();
  set_exception_handler ();

  if (is_attached)
    {
      return excp_handler ((struct chf$signal_array *) progxfer[2],
			   (struct chf$mech_array *) progxfer[3]);
    }

  if (!set_initial_breakpoint ())
    {
      handle_debugger_commands_on_failure ();
    }

  return SS$_CONTINUE;
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
