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
  unsigned long qiow_return_status;
  struct _iosb iosb;
  unsigned long operation_status;

  qiow_return_status = sys$qiow (EFN$C_ENF,
                             term_chan,
                             IO$_WRITEVBLK,
                             &iosb,
                             0,
                             0,
                             (void *)str,
                             len,
                             0, 0, 0, 0);

  if (!(qiow_return_status & STS$M_SUCCESS)) {
    operation_status = qiow_return_status;
  } else {
    operation_status = (unsigned long)iosb.iosb$w_status;
  }

  if (!(operation_status & STS$M_SUCCESS)) {
    LIB$SIGNAL (operation_status);
  }
}

/* Flush the term buffer.  */

static void
term_flush (void)
{
  if (term_buf_len > 0)
    {
      ssize_t bytes_written = term_raw_write(term_buf, term_buf_len);

      if (bytes_written == (ssize_t)term_buf_len)
        {
          term_buf_len = 0;
        }
    }
}

/* Write a single character, without translation.  */

static void
term_raw_putchar (char c)
{
  if (term_buf_len >= sizeof (term_buf))
    term_flush ();
  term_buf[term_buf_len++] = c;
}

/* Write character C.  Translate '\n' to '\n\r'.  */

static const char ASCII_CTRL_MAX = 31;
static const char REPLACEMENT_CHAR = '.';

static void
term_putc (char c)
{
  if (c <= ASCII_CTRL_MAX)
    {
      if (c != '\r' && c != '\n')
        {
          c = REPLACEMENT_CHAR;
        }
    }
  term_raw_putchar (c);
  if (c == '\n')
    {
      term_raw_putchar ('\r');
      term_flush ();
    }
}

/* Write a C string.  */

static void
term_puts (const char *str)
{
  if (str == NULL) {
    return;
  }

  while (*str) {
    term_putc (*str++);
  }
}

/* Write LEN bytes from STR.  */

static void
term_write (const char *str, size_t len)
{
  if (str == NULL && len > 0)
    {
      return;
    }

  for (; len > 0; len--)
    {
      term_putc (*str++);
    }
}

/* Write using FAO formatting.  */

static void
term_fao (const char *str, unsigned int str_len, ...)
{
#define FAO_OUTPUT_BUFFER_SIZE 128

  va_list vargs;
  int initial_arg_count; // Total arguments reported by va_count
  int var_arg_count;     // Number of actual variadic arguments for FAO
  int i;
  __int64 *args_array_ptr; // Pointer to dynamically allocated argument array
  int status;

  // Initialize format string descriptor
  struct dsc$descriptor_s format_descriptor =
    { str_len, DSC$K_DTYPE_T, DSC$K_CLASS_S, (__char_ptr32)str };

  // Output buffer and its descriptor.
  // The $DESCRIPTOR macro for arrays correctly initializes dsc$w_length
  // to the size of the array (FAO_OUTPUT_BUFFER_SIZE).
  char output_buffer[FAO_OUTPUT_BUFFER_SIZE];
  $DESCRIPTOR (output_buffer_descriptor, output_buffer);

  va_start (vargs, str_len);

  // va_count is a non-standard extension (common in OpenVMS C).
  // It returns the total number of arguments passed to the function,
  // including the named parameters (str, str_len).
  va_count (initial_arg_count);

  // Calculate the number of actual variadic arguments for FAO.
  // The first two arguments (str, str_len) are named parameters.
  var_arg_count = initial_arg_count - 2;

  // Allocate memory on the stack for the variadic arguments.
  // __ALLOCA is a platform-specific intrinsic. Its use is maintained
  // to avoid altering the memory management strategy (e.g., to malloc/free)
  // which would change external functionality/resource management.
  // The allocated size is `initial_arg_count * sizeof(__int64)` for robustness,
  // consistent with the original logic where va_count includes all arguments.
  args_array_ptr = (__int64 *) __ALLOCA (initial_arg_count * sizeof (__int64));

  // Populate the argument array from the variable argument list.
  // The loop copies only the variadic arguments into the allocated array,
  // starting from index 0.
  for (i = 0; i < var_arg_count; i++)
    {
      args_array_ptr[i] = va_arg (vargs, __int64);
    }

  // Call the OpenVMS Formatted ASCII Output system service.
  // output_buffer_descriptor.dsc$w_length is used as input for max output length
  // and updated as output to reflect the actual length written by sys$faol_64.
  status = sys$faol_64 (&format_descriptor,
                        &output_buffer_descriptor.dsc$w_length,
                        &output_buffer_descriptor,
                        args_array_ptr);

  // Check the status of the system service call.
  // In OpenVMS, an odd status value typically indicates success.
  if (status & 1)
    {
      // Iterate through the generated buffer and print characters.
      // FAO usually includes its own line feed if requested by the format string.
      // The loop correctly uses the actual length returned by sys$faol_64.
      for (i = 0; i < output_buffer_descriptor.dsc$w_length; i++)
        {
          term_raw_putchar (output_buffer[i]);
          // If a newline character is encountered, flush the terminal output buffer.
          if (output_buffer[i] == '\n')
            {
              term_flush ();
            }
        }
    }
  // If the system service call is not successful, the function silently returns,
  // preserving the original error handling behavior.

  va_end (vargs);
#undef FAO_OUTPUT_BUFFER_SIZE
}

#define TERM_FAO(STR, ...) term_fao (STR, sizeof (STR) - 1, __VA_ARGS__)

/* New line.  */

static void
term_putnl (void)
{
  (void)term_putc ('\n');
}

/* Initialize terminal.  */

#include <rms.h>
#include <lnmdef.h>
#include <iledef.h>
#include <ssdef.h>
#include <starlet.h>
#include <lib$routines.h>

#define ESCAPE_CHARACTER 0x1B
#define HEADER_OFFSET_LENGTH 4

extern unsigned short term_chan; // Declared as an external dependency

static void
term_init (void)
{
  unsigned int status;
  unsigned short len = 0;
  char resstring[LNM$C_NAMLENGTH + 1]; // +1 for potential null terminator

  // Explicitly initialize VMS descriptor for the logical name table.
  static const struct dsc$descriptor_s tabdesc = {
      .dsc$w_length = sizeof("LNM$FILE_DEV") - 1,
      .dsc$b_dtype = DSC$K_DTYPE_T,
      .dsc$b_class = DSC$K_CLASS_S,
      .dsc$a_pointer = "LNM$FILE_DEV"
  };

  // Explicitly initialize VMS descriptor for the logical name.
  static const struct dsc$descriptor_s logdesc = {
      .dsc$w_length = sizeof("SYS$OUTPUT") - 1,
      .dsc$b_dtype = DSC$K_DTYPE_T,
      .dsc$b_class = DSC$K_CLASS_S,
      .dsc$a_pointer = "SYS$OUTPUT"
  };

  struct dsc$descriptor_s term_desc_result; // Descriptor for the translated result string

  ILE3 item_lst[2];

  // Initialize item list for SYS$TRNLNM.
  item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;

  // Terminate the item list explicitly.
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;
  item_lst[1].ile3$ps_bufaddr = NULL;
  item_lst[1].ile3$ps_retlen_addr = NULL;

  /* Translate the logical name. */
  status = SYS$TRNLNM (0,
                       (void *) &tabdesc,
                       (void *) &logdesc,
                       0,
                       item_lst);

  if (!(status & STS$M_SUCCESS))
  {
    LIB$SIGNAL (status);
  }

  // Ensure returned length is within buffer bounds and null-terminate for robustness.
  if (len > LNM$C_NAMLENGTH)
  {
      len = LNM$C_NAMLENGTH;
  }
  resstring[len] = '\0';

  // Initialize the result descriptor with the translated string.
  term_desc_result.dsc$w_length = len;
  term_desc_result.dsc$b_dtype = DSC$K_DTYPE_T;
  term_desc_result.dsc$b_class = DSC$K_CLASS_S;
  term_desc_result.dsc$a_pointer = resstring;

  /* Examine 4-byte header. Skip escape sequence if present and valid. */
  if (len >= HEADER_OFFSET_LENGTH && resstring[0] == ESCAPE_CHARACTER)
  {
    term_desc_result.dsc$w_length -= HEADER_OFFSET_LENGTH;
    term_desc_result.dsc$a_pointer += HEADER_OFFSET_LENGTH;
  }

  /* Assign a channel to the (potentially adjusted) device name. */
  status = sys$assign (&term_desc_result,
                       &term_chan,
                       0,
                       0);

  if (!(status & STS$M_SUCCESS))
  {
    LIB$SIGNAL (status);
  }
}

/* Convert from native endianness to network endianness (and vice-versa).  */

#include <stdint.h>

static unsigned int
wordswap (unsigned int v)
{
  uint16_t val_16 = (uint16_t)v;
  return (unsigned int)(((val_16 & 0x00FFU) << 8) | ((val_16 & 0xFF00U) >> 8));
}

/* Initialize the socket connection, and wait for a client.  */

#define QIOW_CHECK(call_expr, error_msg_str, cleanup_label) \
  do { \
    unsigned int _qiow_sys_status = (call_expr); \
    if ((_qiow_sys_status) & STS$M_SUCCESS) { \
      _qiow_sys_status = iosb.iosb$w_status; \
    } \
    if (!((_qiow_sys_status) & STS$M_SUCCESS)) { \
      term_puts(error_msg_str); \
      status = _qiow_sys_status; \
      goto cleanup_label; \
    } \
  } while(0)

#define SYS_CALL_CHECK(call_expr, error_msg_str, cleanup_label) \
  do { \
    unsigned int _sys_call_status = (call_expr); \
    if (!((_sys_call_status) & STS$M_SUCCESS)) { \
      term_puts(error_msg_str); \
      status = _sys_call_status; \
      goto cleanup_label; \
    } \
  } while(0)

static void
sock_init (void)
{
  unsigned int status = 0;
  struct _iosb iosb;

  unsigned short listen_channel = 0;
  conn_channel = 0;

  struct sockchar listen_sockchar;
  struct sockaddr_in serv_addr;
  struct sockaddr_in cli_addr;

  ILE2 serv_itemlst;
  ILE2 sockopt_itemlst;
  ILE2 reuseaddr_itemlst;
  ILE3 cli_itemlst;

  int optval = 1;
  unsigned short cli_addrlen;

  static const $DESCRIPTOR (inet_device, "TCPIP$DEVICE:");

  listen_sockchar.prot = TCPIP$C_TCP;
  listen_sockchar.type = TCPIP$C_STREAM;
  listen_sockchar.af   = TCPIP$C_AF_INET;

  SYS_CALL_CHECK(sys$assign ((void *) &inet_device, &listen_channel, 0, 0),
                 "Failed to assign listen I/O channel", error_exit);

  SYS_CALL_CHECK(sys$assign ((void *) &inet_device, &conn_channel, 0, 0),
                 "Failed to assign connection I/O channel", error_exit);

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       listen_channel,
                       IO$_SETMODE,
                       &iosb,
                       0, 0,
                       &listen_sockchar,
                       0, 0, 0, 0, 0),
             "Failed to create socket", error_exit);

  reuseaddr_itemlst.ile2$w_length   = sizeof (optval);
  reuseaddr_itemlst.ile2$w_code     = TCPIP$C_REUSEADDR;
  reuseaddr_itemlst.ile2$ps_bufaddr = &optval;

  sockopt_itemlst.ile2$w_length   = sizeof (reuseaddr_itemlst);
  sockopt_itemlst.ile2$w_code     = TCPIP$C_SOCKOPT;
  sockopt_itemlst.ile2$ps_bufaddr = &reuseaddr_itemlst;

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       listen_channel,
                       IO$_SETMODE,
                       &iosb,
                       0, 0,
                       0, 0, 0, 0,
                       (__int64) &sockopt_itemlst,
                       0),
             "Failed to set socket option (REUSEADDR)", error_exit);

  ots$fill (&serv_addr, sizeof (serv_addr), 0);
  serv_addr.sin_family = TCPIP$C_AF_INET;
  serv_addr.sin_port = wordswap (serv_port);
  serv_addr.sin_addr.s_addr = TCPIP$C_INADDR_ANY;

  serv_itemlst.ile2$w_length   = sizeof (serv_addr);
  serv_itemlst.ile2$w_code     = TCPIP$C_SOCK_NAME;
  serv_itemlst.ile2$ps_bufaddr = &serv_addr;

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       listen_channel,
                       IO$_SETMODE,
                       &iosb,
                       0, 0,
                       0, 0,
                       (__int64) &serv_itemlst,
                       0, 0, 0),
             "Failed to bind socket", error_exit);

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       listen_channel,
                       IO$_SETMODE,
                       &iosb,
                       0, 0,
                       0, 0, 0,
                       1,
                       0, 0),
             "Failed to set socket passive", error_exit);

  TERM_FAO ("Waiting for a client connection on port: !ZW!/",
            wordswap (serv_addr.sin_port));

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       listen_channel,
                       IO$_ACCESS|IO$M_ACCEPT,
                       &iosb,
                       0, 0,
                       0, 0, 0,
                       (__int64) &conn_channel,
                       0, 0),
             "Failed to accept client connection", error_exit);

  cli_itemlst.ile3$w_length = sizeof (cli_addr);
  cli_itemlst.ile3$w_code = TCPIP$C_SOCK_NAME;
  cli_itemlst.ile3$ps_bufaddr = &cli_addr;
  cli_itemlst.ile3$ps_retlen_addr = &cli_addrlen;
  ots$fill (&cli_addr, sizeof(cli_addr), 0);

  QIOW_CHECK(sys$qiow (EFN$C_ENF,
                       conn_channel,
                       IO$_SENSEMODE,
                       &iosb,
                       0, 0,
                       0, 0, 0,
                       (__int64) &cli_itemlst,
                       0, 0),
             "Failed to get client name", error_exit);

  TERM_FAO ("Accepted connection from host: !UB.!UB.!UB.!UB, port: !UW!/",
            (cli_addr.sin_addr.s_addr >> 0) & 0xff,
            (cli_addr.sin_addr.s_addr >> 8) & 0xff,
            (cli_addr.sin_addr.s_addr >> 16) & 0xff,
            (cli_addr.sin_addr.s_addr >> 24) & 0xff,
            wordswap (cli_addr.sin_port));

  return;

error_exit:
  if (conn_channel != 0) {
    sys$dassgn(conn_channel);
    conn_channel = 0;
  }
  if (listen_channel != 0) {
    sys$dassgn(listen_channel);
    listen_channel = 0;
  }
  LIB$SIGNAL (status);
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

  if (status & STS$M_SUCCESS)
  {
    status = iosb.iosb$w_status;
  }
  if (!(status & STS$M_SUCCESS))
  {
    term_puts ("Failed to close socket\n");
    LIB$SIGNAL (status);
  }

  status = sys$dassgn (conn_channel);

  if (!(status & STS$M_SUCCESS))
  {
    term_puts ("Failed to deassign I/O channel\n");
    LIB$SIGNAL (status);
  }
}

/* Mark a page as R/W.  Return old rights.  */

#include <stdint.h>

static unsigned int
page_set_rw (uint64_t startva, uint64_t len,
	     unsigned int *oldprot)
{
  unsigned int status;
  uint64_t retva;
  uint64_t retlen;

  status = SYS$SETPRT_64 ((void *)startva, len, PSL$C_USER, PRT$C_UW,
			  (void *)&retva, &retlen, oldprot);

  (void)retva;
  (void)retlen;

  return status;
}

/* Restore page rights.  */

static unsigned int
page_restore_rw (unsigned __int64 startva, unsigned __int64 len,
		unsigned int prot)
{
  unsigned int status;
  unsigned __int64 retva;
  unsigned __int64 retlen;
  unsigned int oldprot;

  status = SYS$SETPRT_64 ((void *)startva, len, PSL$C_USER, prot,
			  (void *)&retva, &retlen, &oldprot);
  
  return status;
}

/* Get the TEB (thread environment block).  */

static pthread_t
get_teb (void)
{
  return pthread_self();
}

/* Enable thread scheduling if VAL is true.  */

static unsigned int
set_thread_scheduling (int val)
{
  if (dbgext_func == NULL)
  {
    return 0;
  }

  struct dbgext_control_block blk;
  blk.dbgext$w_function_code = DBGEXT$K_STOP_ALL_OTHER_TASKS;
  blk.dbgext$w_facility_id = CMA$_FACILITY;
  blk.dbgext$l_stop_value = val;

  unsigned int status = dbgext_func(&blk);

  if (!(status & STS$M_SUCCESS))
  {
    TERM_FAO("set_thread_scheduling error, val=!SL, status=!XL!/", val, blk.dbgext$l_status);
    lib$signal(status);
  }

  return blk.dbgext$l_stop_value;
}

/* Get next thread (after THR).  Start with 0.  */

static unsigned int
thread_next (unsigned int thr)
{
  if (!dbgext_func)
  {
    return 0;
  }

  struct dbgext_control_block blk = {0};

  blk.dbgext$w_function_code = DBGEXT$K_NEXT_TASK;
  blk.dbgext$w_facility_id = CMA$_FACILITY;
  blk.dbgext$l_ada_flags = 0;
  blk.dbgext$l_task_value = thr;

  unsigned int status = dbgext_func(&blk);

  if (!(status & STS$M_SUCCESS))
  {
    lib$signal(status);
  }

  return blk.dbgext$l_task_value;
}

/* Pthread Debug callbacks.  */

static int
read_callback (pthreadDebugClient_t context,
	       pthreadDebugTargetAddr_t addr,
	       pthreadDebugAddr_t buf,
	       size_t size)
{
  // Mark unused parameter explicitly to improve maintainability and silence compiler warnings.
  (void)context;

  // Improve reliability and security: Validate inputs to prevent undefined behavior.
  // If size is 0, no memory access occurs, so NULL pointers for buf/addr are not problematic.
  if (size > 0) {
    if (buf == NULL) {
      // Log an error if the destination buffer is NULL when data transfer is requested.
      // Adhering to existing logging style for consistency.
      if (trace_pthreaddbg) {
        TERM_FAO ("read_callback: ERROR - Destination buffer is NULL (!XH, !XH, !SL)!/", addr, buf, size);
      }
      // Return 0 to maintain external functionality (always returns 0),
      // preventing the potentially dangerous memory operation.
      return 0;
    }
    if (addr == NULL) {
      // Log an error if the source address is NULL when data transfer is requested.
      if (trace_pthreaddbg) {
        TERM_FAO ("read_callback: ERROR - Source address is NULL (!XH, !XH, !SL)!/", addr, buf, size);
      }
      // Return 0 to maintain external functionality,
      // preventing the potentially dangerous memory operation.
      return 0;
    }
  }

  // Original tracing statement. This will now only execute if inputs are valid or size is 0.
  if (trace_pthreaddbg) {
    TERM_FAO ("read_callback (!XH, !XH, !SL)!/", addr, buf, size);
  }

  // Perform the move. This operation is now safe due to the NULL checks for size > 0.
  // If size is 0, ots$move (like memcpy) is expected to do nothing and is safe.
  ots$move (buf, size, addr);

  // Maintain external functionality: always return 0.
  return 0;
}

static int
write_callback (pthreadDebugClient_t context,
		pthreadDebugTargetAddr_t addr,
		pthreadDebugLongConstAddr_t buf,
		size_t size)
{
  (void)context;
  if (trace_pthreaddbg)
    TERM_FAO ("write_callback (!XH, !XH, !SL)!/", addr, buf, size);
  ots$move (addr, size, buf);
  return 0;
}

static int
suspend_callback (pthreadDebugClient_t context)
{
  (void) context; /* Suppress unused parameter warning. */
  /* Always suspended.  */
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
  (void)context; /* Parameter not used in current implementation */
  (void)kid;     /* Parameter not used in current implementation */
  (void)thread_info; /* Parameter not used in current implementation */

  if (trace_pthreaddbg)
    term_puts ("kthinfo_callback");
  return ENOSYS;
}

static int
hold_callback (pthreadDebugClient_t context,
	       pthreadDebugKId_t kid)
{
  (void)context;
  (void)kid;

  if (trace_pthreaddbg)
    term_puts ("hold_callback");
  
  return ENOSYS;
}

static int
unhold_callback (pthreadDebugClient_t context,
		 pthreadDebugKId_t kid)
{
  (void)context;
  (void)kid;

  if (trace_pthreaddbg)
    term_puts ("unhold_callback");
  return ENOSYS;
}

static int
getfreg_callback (pthreadDebugClient_t context,
		  pthreadDebugFregs_t *reg,
		  pthreadDebugKId_t kid)
{
  (void)context;
  (void)reg;
  (void)kid;

  if (trace_pthreaddbg)
    term_puts ("getfreg_callback");
  return ENOSYS;
}

static int
setfreg_callback (pthreadDebugClient_t context,
		  const pthreadDebugFregs_t *reg,
		  pthreadDebugKId_t kid)
{
  (void)context;
  (void)reg;
  (void)kid;

  if (trace_pthreaddbg) {
    term_puts ("setfreg_callback");
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
    term_puts ("getreg_callback");
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

  if (trace_pthreaddbg) {
    term_puts ("setreg_callback");
  }
  return ENOSYS;
}

static int
output_callback (pthreadDebugClient_t context, 
		 pthreadDebugConstString_t line)
{
  (void)context;
  if (line == NULL) {
    return 0;
  }
  term_puts (line);
  term_putnl ();
  return 0;
}

static int
error_callback (pthreadDebugClient_t context, 
		 pthreadDebugConstString_t line)
{
  (void)context;
  term_puts (line);
  term_putnl ();
  return 0;
}

static pthreadDebugAddr_t
malloc_callback (pthreadDebugClient_t caller_context, size_t size)
{
  unsigned int status;
  size_t       total_requested_bytes;
  int          vm_call_size_param;
  unsigned int vm_allocated_raw_address;
  void         *base_allocated_memory_ptr;
  pthreadDebugAddr_t user_returnable_ptr;

  total_requested_bytes = size + 16;

  vm_call_size_param = (int)total_requested_bytes;

  status = lib$get_vm (&vm_call_size_param, &vm_allocated_raw_address, 0);

  if (!(status & STS$M_SUCCESS))
    {
      LIB$SIGNAL (status);
      return NULL;
    }

  base_allocated_memory_ptr = (void *)(uintptr_t)vm_allocated_raw_address;

  if (trace_pthreaddbg)
    TERM_FAO ("malloc_callback (!UL) -> !XA!/", size, base_allocated_memory_ptr);

  *(unsigned int *)base_allocated_memory_ptr = (unsigned int)vm_call_size_param;

  user_returnable_ptr = (pthreadDebugAddr_t)((char *)base_allocated_memory_ptr + 16);

  return user_returnable_ptr;
}

#include <stdint.h>

#define ALLOC_METADATA_OFFSET 16

static void
free_callback (pthreadDebugClient_t caller_context, pthreadDebugAddr_t address)
{
  unsigned int status;
  char *actual_block_ptr;
  unsigned int actual_block_address_val;
  int total_block_size_val;

  actual_block_ptr = (char*)address - ALLOC_METADATA_OFFSET;

  total_block_size_val = (int)*(unsigned int*)actual_block_ptr;

  actual_block_address_val = (unsigned int)(uintptr_t)actual_block_ptr;

  if (trace_pthreaddbg)
    TERM_FAO ("free_callback (!XA)!/", address);

  status = lib$free_vm (&total_block_size_val, &actual_block_address_val, 0);

  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);
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

extern void *debug_context;

typedef struct {
  void *func;
} pthread_debug_entry_t;

extern pthread_debug_entry_t pthread_debug_entries[];

typedef int (*pthread_debug_seq_init_func_t)(void *, pthreadDebugId_t *);

#define PTHREAD_DEBUG_INIT_SEQ_INDEX 1

static int
pthread_debug_thd_seq_init (pthreadDebugId_t *id)
{
  pthread_debug_seq_init_func_t init_func =
    (pthread_debug_seq_init_func_t)pthread_debug_entries[PTHREAD_DEBUG_INIT_SEQ_INDEX].func;

  if (init_func == NULL) {
    return -1;
  }

  return init_func(debug_context, id);
}

static int
pthread_debug_thd_seq_next (pthreadDebugId_t *id)
{
  typedef int (*DebugFuncPtr)(void *context, pthreadDebugId_t *debug_id);

  if (pthread_debug_entries[2].func == NULL) {
    return -1;
  }

  DebugFuncPtr func_ptr = (DebugFuncPtr)pthread_debug_entries[2].func;

  return func_ptr(debug_context, id);
}

#include <stddef.h>

#define PTHREAD_DEBUG_THD_SEQ_DESTROY_INDEX 3

typedef int (*pthread_debug_destroy_func_t)(void *);

static int
pthread_debug_thd_seq_destroy (void)
{
  pthread_debug_destroy_func_t destroy_func =
    (pthread_debug_destroy_func_t)pthread_debug_entries[PTHREAD_DEBUG_THD_SEQ_DESTROY_INDEX].func;

  if (destroy_func == NULL)
    {
      return -1;
    }

  return destroy_func(debug_context);
}

#define PTHREAD_DEBUG_THD_GET_INFO_INDEX 4

typedef int (*pthreadDebugThdGetInfoFunc_t)(void *, pthreadDebugId_t, pthreadDebugThreadInfo_t *);

static int
pthread_debug_thd_get_info (pthreadDebugId_t id,
			    pthreadDebugThreadInfo_t *info)
{
  pthreadDebugThdGetInfoFunc_t func_ptr =
    (pthreadDebugThdGetInfoFunc_t)pthread_debug_entries[PTHREAD_DEBUG_THD_GET_INFO_INDEX].func;

  return func_ptr(debug_context, id, info);
}

typedef struct pthreadDebugThreadInfo pthreadDebugThreadInfo_t;

typedef struct {
    void *func;
} PthreadDebugEntry;

extern void *debug_context;
extern PthreadDebugEntry pthread_debug_entries[];

typedef int (*PthreadDebugGetInfoAddrFunc)(void *debug_ctx, pthread_t thr, pthreadDebugThreadInfo_t *info);

#define PTHREAD_DEBUG_GET_INFO_ADDR_INDEX 5

static int
pthread_debug_thd_get_info_addr (pthread_t thr,
				 pthreadDebugThreadInfo_t *info)
{
  PthreadDebugGetInfoAddrFunc get_info_addr_func =
    (PthreadDebugGetInfoAddrFunc)pthread_debug_entries[PTHREAD_DEBUG_GET_INFO_ADDR_INDEX].func;

  if (get_info_addr_func == NULL) {
    return -1;
  }

  return get_info_addr_func(debug_context, thr, info);
}

typedef int (*pthread_debug_get_reg_func_t)(void *context, pthreadDebugId_t thr, pthreadDebugRegs_t *regs);

#define PTHREAD_DEBUG_GET_REG_ENTRY_IDX 6

static int
pthread_debug_thd_get_reg (pthreadDebugId_t thr,
			   pthreadDebugRegs_t *regs)
{
  void (*raw_func_ptr_generic)(void) = pthread_debug_entries[PTHREAD_DEBUG_GET_REG_ENTRY_IDX].func;
  pthread_debug_get_reg_func_t get_reg_func = (pthread_debug_get_reg_func_t)raw_func_ptr_generic;

  if (get_reg_func == NULL) {
    return -1;
  }

  return get_reg_func(debug_context, thr, regs);
}

typedef int (*pthread_debug_cmd_func_t)(void *context, const char *command);

#define PTHREAD_DEBUG_CMD_INDEX 7

static int
stub_pthread_debug_cmd (const char *cmd)
{
  // It's assumed that pthread_debug_entries is a valid, globally accessible array
  // and PTHREAD_DEBUG_CMD_INDEX is within its bounds.
  // Real-world code might include bounds checking if the array size is known at this point.

  // Ensure the function pointer at the specified index is not NULL before calling it.
  if (pthread_debug_entries[PTHREAD_DEBUG_CMD_INDEX].func == NULL) {
    // Return an error code indicating that the function is not available.
    // -1 is a common convention for general errors.
    return -1;
  }

  // Cast the generic void* function pointer to its specific type for type-safe calling.
  pthread_debug_cmd_func_t debug_func = 
    (pthread_debug_cmd_func_t)pthread_debug_entries[PTHREAD_DEBUG_CMD_INDEX].func;
  
  // Call the function with the appropriate context and command.
  return debug_func(debug_context, cmd);
}

/* Show all the threads.  */

static void
threads_show (void)
{
  pthreadDebugId_t id;
  pthreadDebugThreadInfo_t info;
  int res;

  res = pthread_debug_thd_seq_init (&id);
  if (res != 0)
    {
      TERM_FAO ("seq init failed, res=!SL!/", res);
      return;
    }

  while (1)
    {
      if (pthread_debug_thd_get_info (id, &info) != 0)
	{
	  TERM_FAO ("thd_get_info !SL failed!/", id);
	  goto cleanup;
	}

      if (pthread_debug_thd_seq_next (&id) != 0)
	{
	  goto cleanup;
	}
    }

cleanup:
  pthread_debug_thd_seq_destroy ();
}

/* Initialize pthread support.  */

static void
threads_init (void)
{
  static const $DESCRIPTOR (dbgext_desc, "PTHREAD$DBGEXT");
  static const $DESCRIPTOR (pthread_debug_desc, "PTHREAD$DBGSHR");
  static const $DESCRIPTOR (dbgsymtable_desc, "PTHREAD_DBG_SYMTABLE");
  int status;
  void *dbg_symtable;
  int i;
  void *caller_context = 0;

  typedef int (*pthread_debug_init_func_t)(void **, void *, void *, void *);

  #define PTHREAD_DO_SYMBOL_LOOKUP(image_desc_ptr, symbol_desc_ptr, target_ptr) \
    status = lib$find_image_symbol((void *)(image_desc_ptr), (void *)(symbol_desc_ptr), (int *)(target_ptr)); \
    if (!(status & STS$M_SUCCESS)) { \
      LIB$SIGNAL(status); \
    }

  PTHREAD_DO_SYMBOL_LOOKUP(&pthread_rtl_desc, &dbgext_desc, &dbgext_func);
  
  PTHREAD_DO_SYMBOL_LOOKUP(&pthread_rtl_desc, &dbgsymtable_desc, &dbg_symtable);

  for (i = 0;
       i < sizeof (pthread_debug_entries) / sizeof (pthread_debug_entries[0]);
       i++)
  {
    struct dsc$descriptor_s sym =
      { pthread_debug_entries[i].namelen,
        DSC$K_DTYPE_T, DSC$K_CLASS_S,
        pthread_debug_entries[i].name };
    PTHREAD_DO_SYMBOL_LOOKUP(&pthread_debug_desc, &sym, &pthread_debug_entries[i].func);
  }

  if (trace_pthreaddbg)
  {
    TERM_FAO ("debug symtable: !XH!/", dbg_symtable);
  }

  pthread_debug_init_func_t init_func = (pthread_debug_init_func_t)pthread_debug_entries[0].func;
  status = init_func(&caller_context, &pthread_debug_callbacks, dbg_symtable, &debug_context);

  if (status != 0)
  {
    TERM_FAO ("cannot initialize pthread_debug: !UL!/", status);
  }

  TERM_FAO ("pthread debug done!/", 0);

  #undef PTHREAD_DO_SYMBOL_LOOKUP
}

/* Convert an hexadecimal character to a nibble.  Return -1 in case of
   error.  */

static int
hex2nibble (unsigned char h)
{
  int val = toupper(h);

  if (val >= '0' && val <= '9')
  {
    return val - '0';
  }
  else if (val >= 'A' && val <= 'F')
  {
    return val - 'A' + 10;
  }
  return -1;
}

/* Convert an hexadecimal 2 character string to a byte.  Return -1 in case
   of error.  */

static int
hex2byte (const unsigned char *p)
{
  if (p == NULL) {
    return -1;
  }

  int h = hex2nibble (p[0]);
  int l = hex2nibble (p[1]);

  if (h == -1 || l == -1) {
    return -1;
  }
  return (h << 4) | l;
}

/* Convert a byte V to a 2 character strings P.  */

static const char HEX_DIGITS[] = "0123456789abcdef";

static void
byte2hex (unsigned char *p, unsigned char v)
{
  if (p == NULL) {
    return;
  }

  p[0] = (unsigned char)HEX_DIGITS[v >> 4];
  p[1] = (unsigned char)HEX_DIGITS[v & 0xf];
}

/* Convert a quadword V to a 16 character strings P.  */

#include <stdint.h>
#include <stddef.h>

static const char HEX_DIGITS[] = "0123456789abcdef";

static void
quad2hex (unsigned char *p, uint64_t v)
{
  if (p == NULL)
    {
      return;
    }

  for (int i = 0; i < 16; i++)
    {
      unsigned int nibble = (v >> 60) & 0xF;
      p[i] = (unsigned char)HEX_DIGITS[nibble];
      v <<= 4;
    }
}

static void
long2pkt (unsigned int v)
{
  // Constants for hexadecimal conversion.
  // A hexadecimal digit represents 4 bits.
  const int BITS_PER_HEX_DIGIT = 4;
  // Assuming CHAR_BIT is 8 for typical systems (1 byte = 8 bits).
  const int BITS_PER_BYTE = 8;

  // Calculate the number of hexadecimal characters needed for an unsigned int.
  // Example: for a 32-bit unsigned int (4 bytes), 4 * (8 / 4) = 8 characters.
  const int num_hex_chars = sizeof(unsigned int) * (BITS_PER_BYTE / BITS_PER_HEX_DIGIT);

  // Calculate the initial shift amount to get the most significant nibble.
  // Example: for a 32-bit unsigned int, (4 * 8) - 4 = 28.
  const int initial_msb_shift = (sizeof(unsigned int) * BITS_PER_BYTE) - BITS_PER_HEX_DIGIT;

  for (int i = 0; i < num_hex_chars; i++)
    {
      // Extract the current most significant 4-bit nibble.
      // 'v' is shifted left in each iteration, so the MSB nibble changes.
      unsigned int nibble_value = (v >> initial_msb_shift) & 0x0F;
      gdb_buf[gdb_blen + i] = hex[nibble_value];

      // Shift 'v' left to bring the next nibble into the most significant position.
      v <<= BITS_PER_HEX_DIGIT;
    }
  gdb_blen += num_hex_chars;
}

/* Generate an error packet.  */

static void
packet_error (unsigned int err)
{
  gdb_buf[1] = 'E';
  byte2hex (gdb_buf + 2, (unsigned char)err);
  gdb_blen = 4;
}

/* Generate an OK packet.  */

static void
packet_ok (void)
{
  const int GDB_BUF_OFFSET_O = 1;
  const int GDB_BUF_OFFSET_K = 2;
  const char GDB_CHAR_O = 'O';
  const char GDB_CHAR_K = 'K';
  const int GDB_PACKET_LENGTH = 3;

  gdb_buf[GDB_BUF_OFFSET_O] = GDB_CHAR_O;
  gdb_buf[GDB_BUF_OFFSET_K] = GDB_CHAR_K;
  gdb_blen = GDB_PACKET_LENGTH;
}

/* Append a register to the packet.  */

static void
ireg2pkt (const unsigned char *p)
{
  int i;
  const int NUM_REG_BYTES = 8;
  const int CHARS_PER_BYTE = 2;

  if (gdb_blen + (size_t)(NUM_REG_BYTES * CHARS_PER_BYTE) > GDB_BUF_SIZE)
    {
      return;
    }

  for (i = 0; i < NUM_REG_BYTES; i++)
    {
      byte2hex (gdb_buf + gdb_blen, p[i]);
      gdb_blen += CHARS_PER_BYTE;
    }
}

/* Append a C string (ASCIZ) to the packet.  */

static void
str2pkt (const char *str)
{
  if (str == NULL) {
    return;
  }

  while (*str != '\0' && gdb_blen < GDB_BUF_MAX_SIZE) {
    gdb_buf[gdb_blen++] = (unsigned char)*str++;
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
mem2bin (const unsigned char *b, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      unsigned char current_char = b[i];
      size_t required_bytes;

      switch (current_char)
        {
        case '#':
        case '$':
        case '}':
        case '*':
        case 0:
          required_bytes = 2;
          break;
        default:
          required_bytes = 1;
          break;
        }

      if (gdb_blen + required_bytes > GDB_BUF_CAPACITY)
        {
          break;
        }

      switch (current_char)
        {
        case '#':
        case '$':
        case '}':
        case '*':
        case 0:
          gdb_buf[gdb_blen++] = '}';
          gdb_buf[gdb_blen++] = current_char ^ 0x20;
          break;
        default:
          gdb_buf[gdb_blen++] = current_char;
          break;
        }
    }
}

/* Append LEN bytes from B to the current gdb packet (encode in hex).  */

static int
mem2hex (const unsigned char *src_buf, unsigned int src_len,
         char *dest_buf, unsigned int dest_capacity, unsigned int *current_dest_len_ptr)
{
  if (src_buf == NULL || dest_buf == NULL || current_dest_len_ptr == NULL)
    {
      return 1;
    }

  unsigned int current_dest_len = *current_dest_len_ptr;

  if (current_dest_len > dest_capacity)
    {
      return 1;
    }

  unsigned int required_space = src_len * 2;

  if (dest_capacity - current_dest_len < required_space)
    {
      return 1;
    }

  unsigned int i;
  for (i = 0; i < src_len; i++)
    {
      byte2hex (dest_buf + current_dest_len, src_buf[i]);
      current_dest_len += 2;
    }

  *current_dest_len_ptr = current_dest_len;
  return 0;
}

/* Handle the 'q' packet.  */

static const char XFER_UIB_PREFIX[] = "qXfer:uib:read:";
static const unsigned int XFER_UIB_PREFIX_LEN = (sizeof(XFER_UIB_PREFIX) - 1);

static const char QFTHREADINFO_CMD[] = "qfThreadInfo";
static const unsigned int QFTHREADINFO_CMD_LEN = (sizeof(QFTHREADINFO_CMD) - 1);

static const char QSTHREADINFO_CMD[] = "qsThreadInfo";
static const unsigned int QSTHREADINFO_CMD_LEN = (sizeof(QSTHREADINFO_CMD) - 1);

static const char QTHREADEXTRAINFO_PREFIX[] = "qThreadExtraInfo,";
static const unsigned int QTHREADEXTRAINFO_PREFIX_LEN = (sizeof(QTHREADEXTRAINFO_PREFIX) - 1);

static const char QSUPPORTED_PREFIX[] = "qSupported:";
static const unsigned int QSUPPORTED_PREFIX_LEN = (sizeof(QSUPPORTED_PREFIX) - 1);

#define UIB_DATA_SIZE 0x20

static unsigned int first_thread;
static unsigned int last_thread;

static void init_gdb_response(char type_char)
{
  gdb_buf[0] = '$';
  gdb_buf[1] = type_char;
  gdb_blen = 2;
}

static void handle_current_thread_packet(void)
{
  init_gdb_response('Q');
  gdb_buf[2] = 'C';
  gdb_blen = 3;
  if (has_threads)
    long2pkt((unsigned long)get_teb());
}

static void handle_xfer_uib_packet(const unsigned char *pkt, unsigned int pktlen)
{
  unsigned __int64 pc;
  unsigned int pos = XFER_UIB_PREFIX_LEN;
  unsigned int off;
  unsigned int len;
  union {
    unsigned char bytes[UIB_DATA_SIZE];
    struct {
      unsigned __int64 code_start_va;
      unsigned __int64 code_end_va;
      unsigned __int64 uib_start_va;
      unsigned __int64 gp_value;
    } data;
  } uei;
  int res;

  packet_error(0);

  if (pos >= pktlen) return;
  pc = pkt2val(pkt, &pos);

  if (pos >= pktlen || pkt[pos] != ':') return;
  pos++;

  if (pos >= pktlen) return;
  off = pkt2val(pkt, &pos);

  if (pos >= pktlen || pkt[pos] != ',' || off != 0) return;
  pos++;

  if (pos >= pktlen) return;
  len = pkt2val(pkt, &pos);

  if (pos >= pktlen || pkt[pos] != '#' || len != UIB_DATA_SIZE) return;

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

  init_gdb_response('l');
  mem2bin(uei.bytes, sizeof(uei.bytes));
}

static void handle_qfthreadinfo_request(void)
{
  init_gdb_response('m');

  if (!has_threads)
  {
    gdb_buf[1] = 'l';
    return;
  }
  first_thread = thread_next(0);
  last_thread = first_thread;
  long2pkt(first_thread);
}

static void handle_qsthreadinfo_request(void)
{
  init_gdb_response('m');

  while (dbgext_func)
  {
    unsigned int res;
    
    const unsigned int MIN_SPACE_FOR_LONG_AND_COMMA = 17;
    const unsigned int MIN_SPACE_FOR_LONG = 16;           

    if (gdb_blen > 2)
    {
      if (gdb_blen >= sizeof(gdb_buf) - MIN_SPACE_FOR_LONG_AND_COMMA)
      {
        break;
      }
      gdb_buf[gdb_blen++] = ',';
    }
    else
    {
      if (gdb_blen >= sizeof(gdb_buf) - MIN_SPACE_FOR_LONG)
      {
        break;
      }
    }

    res = thread_next(last_thread);
    if (res == first_thread)
      break;

    long2pkt(res);
    last_thread = res;

    if (gdb_blen > sizeof(gdb_buf) - 16)
      break;
  }

  if (gdb_blen == 2)
    gdb_buf[1] = 'l';
}

static void handle_qthreadextrainfo_request(const unsigned char *pkt, unsigned int pktlen)
{
  pthread_t thr;
  unsigned int pos = QTHREADEXTRAINFO_PREFIX_LEN;
  pthreadDebugThreadInfo_t info;
  int res;

  packet_error(0);
  if (!has_threads)
    return;

  if (pos >= pktlen) return;
  thr = (pthread_t)pkt2val(pkt, &pos);

  if (pos >= pktlen || pkt[pos] != '#') return;

  res = pthread_debug_thd_get_info_addr(thr, &info);
  if (res != 0)
  {
    TERM_FAO("qThreadExtraInfo (!XH) failed: !SL!/", thr, res);
    return;
  }

  gdb_buf[0] = '$';
  gdb_blen = 1;
  mem2hex((const unsigned char *)"VMS-thread", sizeof("VMS-thread") - 1);
}

static void handle_qsupported_request(void)
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

static void
handle_q_packet(const unsigned char *pkt, unsigned int pktlen)
{
  if (pktlen == 2 && pkt[1] == 'C')
  {
    handle_current_thread_packet();
  }
  else if (pktlen >= XFER_UIB_PREFIX_LEN
           && ots$strcmp_eql(pkt, XFER_UIB_PREFIX_LEN, XFER_UIB_PREFIX, XFER_UIB_PREFIX_LEN))
  {
    handle_xfer_uib_packet(pkt, pktlen);
  }
  else if (pktlen == QFTHREADINFO_CMD_LEN
           && ots$strcmp_eql(pkt, QFTHREADINFO_CMD_LEN, QFTHREADINFO_CMD, QFTHREADINFO_CMD_LEN))
  {
    handle_qfthreadinfo_request();
  }
  else if (pktlen == QSTHREADINFO_CMD_LEN
           && ots$strcmp_eql(pkt, QSTHREADINFO_CMD_LEN, QSTHREADINFO_CMD, QSTHREADINFO_CMD_LEN))
  {
    handle_qsthreadinfo_request();
  }
  else if (pktlen >= QTHREADEXTRAINFO_PREFIX_LEN
           && ots$strcmp_eql(pkt, QTHREADEXTRAINFO_PREFIX_LEN, QTHREADEXTRAINFO_PREFIX, QTHREADEXTRAINFO_PREFIX_LEN))
  {
    handle_qthreadextrainfo_request(pkt, pktlen);
  }
  else if (pktlen >= QSUPPORTED_PREFIX_LEN
           && ots$strcmp_eql(pkt, QSUPPORTED_PREFIX_LEN, QSUPPORTED_PREFIX, QSUPPORTED_PREFIX_LEN))
  {
    handle_qsupported_request();
  }
  else
  {
    handle_unknown_packet(pkt, pktlen);
  }
}

/* Handle the 'v' packet.  */

static int
handle_v_packet (const unsigned char *pkt, unsigned int pktlen)
{
  static const char vcontq[] = "vCont?";
#define VCONTQ_LEN (sizeof (vcontq) - 1)

  if (pktlen == VCONTQ_LEN && memcmp(pkt, vcontq, VCONTQ_LEN) == 0)
    {
      gdb_buf[0] = '$';
      gdb_blen = 1;
      str2pkt ("vCont;c;s");
    }
  else if (trace_pkt)
    {
      term_puts ("unknown <: ");
      term_write ((char *)pkt, pktlen);
      term_putnl ();
    }
  return 0;
}

/* Get regs for the selected thread.  */

static struct ia64_all_regs *
get_selected_regs (void)
{
  pthreadDebugRegs_t regs;

  if (selected_thread == 0 || selected_thread == get_teb ())
    return &excp_regs;

  if (selected_thread == sel_regs_pthread)
    return &sel_regs;

  if (pthread_debug_thd_get_reg (selected_id, &regs) != 0)
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

static void
packet_status (void)
{
  static const char *const THREAD_STATUS_PREFIX = "$T05thread:";
  static const char *const NO_THREAD_STATUS = "$S05";
  static const char THREAD_SEPARATOR = ';';

  gdb_blen = 0;

  if (has_threads)
    {
      str2pkt (THREAD_STATUS_PREFIX);
      long2pkt ((unsigned long) get_teb ());
      gdb_buf[gdb_blen++] = THREAD_SEPARATOR;
    }
  else
    {
      str2pkt (NO_THREAD_STATUS);
    }
}

/* Return 1 to continue.  */

static int handle_get_general_registers(void) {
    struct ia64_all_regs *regs = get_selected_regs();
    unsigned char *p = regs->gr[0].b;
    unsigned int i;

    for (i = 0; i < (8 * 32); i++) { // 8 bytes/register * 32 general registers
        byte2hex(gdb_buf + 1 + 2 * i, p[i]);
    }
    gdb_blen += 2 * (8 * 32);
    return 0;
}

static int handle_Hg_command(unsigned char *pkt, unsigned int len, unsigned int *pkt_pos_ptr) {
    unsigned __int64 val;
    pthreadDebugThreadInfo_t info;
    int res;

    (*pkt_pos_ptr)++; // Consume 'g'

    val = pkt2val(pkt, pkt_pos_ptr);

    if (*pkt_pos_ptr != len) {
        packet_error(0);
        return 0;
    }

    if (val == 0) {
        selected_thread = get_teb();
        selected_id = 0;
    } else if (!has_threads) {
        packet_error(0);
        return 0;
    } else {
        res = pthread_debug_thd_get_info_addr((pthread_t)val, &info);
        if (res != 0) {
            TERM_FAO("qThreadExtraInfo (!XH) failed: !SL!/", val, res);
            packet_error(0);
            return 0;
        }
        selected_thread = info.teb;
        selected_id = info.sequence;
    }
    packet_ok();
    return 0;
}

static int handle_Hc_command(unsigned char *pkt, unsigned int len) {
    // Silently accept 'Hc0' (len=3) and 'Hc-1' (len=4)
    if ((len == 3 && pkt[2] == '0') || (len == 4 && pkt[2] == '-' && pkt[3] == '1')) {
        packet_ok();
        return 0;
    }
    packet_error(0);
    return 0;
}

// Replicating original memory access check logic
static int check_memory_read_access(unsigned __int64 addr, unsigned int l) {
    unsigned __int64 paddr = addr & (~(VMS_PAGE_SIZE - 1));
    unsigned int current_length_to_check = l + (addr & (VMS_PAGE_SIZE - 1));

    while (1) {
        if (__prober(paddr, 0) != 1) {
            return 0; // Access denied
        }
        if (current_length_to_check < VMS_PAGE_SIZE) {
            break;
        }
        current_length_to_check -= VMS_PAGE_SIZE;
        paddr += VMS_PAGE_SIZE;
    }
    return 1; // All pages accessible
}

static int handle_memory_read(unsigned char *pkt, unsigned int len, unsigned int *pkt_pos_ptr) {
    unsigned __int64 addr;
    unsigned int l;
    unsigned int i;

    addr = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr >= len || pkt[*pkt_pos_ptr] != ',') {
        packet_error(0);
        return 0;
    }
    (*pkt_pos_ptr)++; // Consume ','

    l = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr >= len || pkt[*pkt_pos_ptr] != '#') {
        packet_error(0);
        return 0;
    }
    // '#' is end delimiter, not consumed by pkt_pos_ptr for subsequent parsing.

    if (!check_memory_read_access(addr, l)) {
        packet_error(2); // EIO error
        return 0;
    }

    for (i = 0; i < l; i++) {
        byte2hex(gdb_buf + 1 + 2 * i, ((unsigned char *)addr)[i]);
    }
    gdb_blen += 2 * l;
    return 0;
}

// Replicating original memory access check logic
static int check_memory_write_access(unsigned __int64 addr, unsigned int l, unsigned int *oldprot) {
    unsigned __int64 paddr = addr & (~(VMS_PAGE_SIZE - 1));
    unsigned int current_length_to_check = l + (addr & (VMS_PAGE_SIZE - 1));

    page_set_rw(addr, l, oldprot); // Attempt to set R/W permissions

    while (1) {
        if (__probew(paddr, 0) != 1) {
            return 0; // Access denied
        }
        if (current_length_to_check < VMS_PAGE_SIZE) {
            break;
        }
        current_length_to_check -= VMS_PAGE_SIZE;
        paddr += VMS_PAGE_SIZE;
    }
    return 1; // All pages accessible
}

static int handle_memory_write(unsigned char *pkt, unsigned int len, unsigned int *pkt_pos_ptr) {
    unsigned __int64 addr;
    unsigned int l;
    unsigned int i;
    unsigned int oldprot = 0; // Initialize for safety

    addr = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr >= len || pkt[*pkt_pos_ptr] != ',') {
        packet_error(0);
        return 0;
    }
    (*pkt_pos_ptr)++; // Consume ','

    l = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr >= len || pkt[*pkt_pos_ptr] != ':') {
        packet_error(0);
        return 0;
    }
    (*pkt_pos_ptr)++; // Consume ':'

    if (!check_memory_write_access(addr, l, &oldprot)) {
        page_restore_rw(addr, l, oldprot); // Restore permissions on failure
        packet_error(2); // EIO error
        return 0;
    }

    for (i = 0; i < l; i++) {
        if ((*pkt_pos_ptr + 1) >= len) { // Ensure two characters for hex2byte
            page_restore_rw(addr, l, oldprot);
            packet_error(0); // Malformed packet (truncated hex data)
            return 0;
        }
        int v = hex2byte(pkt + *pkt_pos_ptr);
        // hex2byte might not indicate failure directly, assuming valid input or 0 for invalid
        // If hex2byte can fail, additional error check needed here.
        *pkt_pos_ptr += 2;
        ((unsigned char *)addr)[i] = (unsigned char)v;
    }

    for (i = 0; i < l; i += 15) { // Assuming 15 is a hardware-specific value
        __fc(addr + i);
    }
    __fc(addr + l); // Flush last block

    page_restore_rw(addr, l, oldprot);
    packet_ok();
    return 0;
}

static int handle_get_specific_register(unsigned char *pkt, unsigned int len, unsigned int *pkt_pos_ptr) {
    unsigned int reg_num = 0;
    struct ia64_all_regs *regs = get_selected_regs();

    reg_num = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr != len) {
        packet_error(0); // Malformed packet
        return 0;
    }

    switch (reg_num) {
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
            TERM_FAO("gdbserv: unhandled reg !UW!/", reg_num);
            packet_error(0);
            return 0; // Unhandled register, error sent
    }
    return 0; // Success
}

static int handle_thread_status(unsigned char *pkt, unsigned int len, unsigned int *pkt_pos_ptr) {
    unsigned __int64 target_thread_id;
    unsigned int first_thread_id, current_thread_id;

    if (!has_threads) {
        packet_ok();
        return 0;
    }

    target_thread_id = pkt2val(pkt, pkt_pos_ptr);
    if (*pkt_pos_ptr != len) {
        packet_error(0); // Malformed packet
        return 0;
    }

    first_thread_id = thread_next(0); // Get the first thread ID
    if (first_thread_id == 0) { // No threads or error getting first thread
        packet_error(0);
        return 0;
    }

    current_thread_id = first_thread_id;
    do {
        if (target_thread_id == current_thread_id) {
            packet_ok();
            return 0; // Thread found
        }
        current_thread_id = thread_next(current_thread_id);
    } while (current_thread_id != 0 && current_thread_id != first_thread_id);

    packet_error(0); // Thread not found after iterating, or error during iteration
    return 0;
}

static int handle_vms_extension(unsigned char *pkt, unsigned int len) {
    const unsigned int VMS_PREFIX_LEN = 4; // Length of "VMS "
    // Check if packet is long enough for "VMS " plus at least one command char
    if (len <= VMS_PREFIX_LEN) {
        packet_error(0);
        return 0;
    }

    // Check for "VMS " prefix after initial 'V'
    if (pkt[1] == 'M' && pkt[2] == 'S' && pkt[3] == ' ') {
        if (has_threads) {
            unsigned char original_char_at_len = pkt[len]; // Save char at end
            pkt[len] = 0; // Temporarily null-terminate
            stub_pthread_debug_cmd((char *)pkt + VMS_PREFIX_LEN); // Command starts after 'VMS '
            pkt[len] = original_char_at_len; // Restore original char
            packet_ok();
        } else {
            packet_error(0);
        }
    } else {
        packet_error(0); // Malformed 'V' command
    }
    return 0;
}

static int
handle_packet (unsigned char *pkt, unsigned int len)
{
  unsigned int pkt_pos;

  gdb_buf[0] = '$';
  gdb_blen = 1;

  if (len == 0) {
      packet_error(0); // Empty packet
      return 0;
  }

  pkt_pos = 1; // Start parsing after the command character pkt[0]
  switch (pkt[0])
    {
    case '?':
      if (len == 1) {
	  packet_status();
	  return 0;
      }
      // Fall through to default for malformed '?' packet (e.g., "?extra")
      break;
    case 'c':
      if (len == 1) {
	  excp_regs.psr.v &= ~((unsigned __int64)1 << 17); // PSR$M_SS
	  return 1;
      } else {
	  packet_error(0);
      }
      break;
    case 'g':
      if (len == 1) {
	  return handle_get_general_registers();
      }
      // Fall through to default for malformed 'g' packet
      break;
    case 'H':
      if (len < 2) { // Minimum length for 'H' commands like 'Hg' or 'Hc'
          packet_error(0);
          return 0;
      }
      if (pkt[1] == 'g') {
	  return handle_Hg_command(pkt, len, &pkt_pos);
      } else if (pkt[1] == 'c') {
	  return handle_Hc_command(pkt, len);
      } else {
	  packet_error(0);
	  return 0;
      }
    case 'k':
      SYS$EXIT(SS$_NORMAL);
      break; // SYS$EXIT typically doesn't return, but add break for safety
    case 'm':
      if (len < 5) { // Minimum 'm' + 1_addr + ',' + 1_len + '#'
          packet_error(0);
          return 0;
      }
      return handle_memory_read(pkt, len, &pkt_pos);
    case 'M':
      if (len < 7) { // Minimum 'M' + 1_addr + ',' + 1_len + ':' + 2_data
          packet_error(0);
          return 0;
      }
      return handle_memory_write(pkt, len, &pkt_pos);
    case 'p':
      if (len < 2) { // Minimum 'p' + 1_reg_num
          packet_error(0);
          return 0;
      }
      return handle_get_specific_register(pkt, len, &pkt_pos);
    case 'q':
      return handle_q_packet(pkt, len);
    case 's':
      if (len == 1) {
	  excp_regs.psr.v |= ((unsigned __int64)1 << 17); // PSR$M_SS
	  return 1;
      } else {
	  packet_error(0);
      }
      break;
    case 'T':
      if (len < 2) { // Minimum 'T' + 1_thread_id
          packet_error(0);
          return 0;
      }
      return handle_thread_status(pkt, len, &pkt_pos);
    case 'v':
      return handle_v_packet (pkt, len);
    case 'V':
      return handle_vms_extension(pkt, len);
    default:
      if (trace_pkt) {
	  term_puts ("unknown <: ");
	  term_write ((char *)pkt, len);
	  term_putnl ();
      }
      break;
    }
  return 0;
}

/* Raw write to gdb.  */

static void
sock_write (const unsigned char *buf, int len)
{
  struct _iosb iosb;
  unsigned int qiow_return_status;  /* Status returned by the sys$qiow system call */
  unsigned int final_operation_status; /* The ultimate status representing success or failure of the write operation */

  /* Write data to connection.  */
  qiow_return_status = sys$qiow (EFN$C_ENF,           /* Event flag.  */
		                     conn_channel,        /* I/O channel.  */
		                     IO$_WRITEVBLK,       /* I/O function code.  */
		                     &iosb,               /* I/O status block.  */
		                     0,                   /* Ast service routine.  */
		                     0,                   /* Ast parameter.  */
		                     (char *)buf,         /* P1 - buffer address.  */
		                     len,                 /* P2 - buffer length.  */
		                     0, 0, 0, 0);

  if (qiow_return_status & STS$M_SUCCESS)
    {
      /* The I/O request was successfully queued. Now, retrieve the actual operation's completion status. */
      final_operation_status = iosb.iosb$w_status;
    }
  else
    {
      /* The sys$qiow call itself failed to queue the request. This is the primary error. */
      final_operation_status = qiow_return_status;
    }

  /* Check if the final determined status indicates an error. */
  if (!(final_operation_status & STS$M_SUCCESS))
    {
      term_puts ("Failed to write data to gdb\n");
      LIB$SIGNAL (final_operation_status);
    }
}

/* Compute the checksum and send the packet.  */

static void
send_pkt (void)
{
  unsigned char checksum = 0;
  unsigned int packet_total_length;

  for (unsigned int i = GDB_CHECKSUM_START_INDEX; i < gdb_blen; i++) {
    checksum += gdb_buf[i];
  }

  gdb_buf[gdb_blen] = GDB_CHECKSUM_DELIMITER_CHAR;
  byte2hex(gdb_buf + gdb_blen + 1, checksum);

  packet_total_length = gdb_blen + 1 + GDB_CHECKSUM_HEX_LENGTH;

  sock_write(gdb_buf, packet_total_length);

  if (trace_pkt >= GDB_TRACE_LEVEL_VERBOSE_MIN) {
    term_puts(">: ");
    term_write((char *)gdb_buf, packet_total_length);
    term_putnl();
  }
}

/* Read and handle one command.  Return 1 is execution must resume.  */

static int
read_socket_data_chunk(void)
{
  struct _iosb iosb;
  unsigned int status;
  unsigned int bytes_read_this_chunk;

  if (gdb_blen >= sizeof(gdb_buf)) {
      term_puts("Internal error: Attempted to write to full buffer when already full.\n");
      return 1;
  }

  status = sys$qiow(EFN$C_ENF,
                    conn_channel,
                    IO$_READVBLK,
                    &iosb,
                    0, 0,
                    gdb_buf + gdb_blen,
                    sizeof(gdb_buf) - gdb_blen,
                    0, 0, 0, 0);

  if (status & STS$M_SUCCESS) {
    status = iosb.iosb$w_status;
  }

  if (!(status & STS$M_SUCCESS)) {
    term_puts("Failed to read data from connection\n");
    LIB$SIGNAL(status);
    return 1;
  }

  bytes_read_this_chunk = iosb.iosb$w_bcnt;

  if (bytes_read_this_chunk == 0 && (sizeof(gdb_buf) - gdb_blen > 0)) {
    term_puts("Connection closed or no data received.\n");
    return 1;
  }

#ifdef RAW_DUMP
  term_puts("{: ");
  term_write((char *)gdb_buf + gdb_blen, bytes_read_this_chunk);
  term_putnl();
#endif

  gdb_blen += bytes_read_this_chunk;
  return 0;
}

static int
find_gdb_packet_markers(unsigned int *dollar_idx_ptr, unsigned int *sharp_idx_ptr)
{
  unsigned int current_dollar = *dollar_idx_ptr;
  unsigned int current_sharp = *sharp_idx_ptr;
  unsigned int i;

  if (current_dollar == 0) {
    for (i = 0; i < gdb_blen; i++) {
      if (gdb_buf[i] == '$') {
        current_dollar = i;
        *dollar_idx_ptr = i;
        current_sharp = 0;
        *sharp_idx_ptr = 0;
        break;
      }
    }
  }

  if (current_dollar == 0) {
    if (gdb_blen >= sizeof(gdb_buf)) {
      term_puts("Buffer full, '$' not found. Discarding.\n");
      return -1;
    }
    return 1;
  }

  unsigned int search_start_for_sharp = current_dollar + 1;
  if (current_sharp > search_start_for_sharp) {
      search_start_for_sharp = current_sharp;
  }

  for (i = search_start_for_sharp; i < gdb_blen; i++) {
    if (gdb_buf[i] == '#') {
      current_sharp = i;
      *sharp_idx_ptr = i;
      break;
    }
  }

  if (current_sharp == 0 || current_sharp >= gdb_blen) {
    if (gdb_blen >= sizeof(gdb_buf)) {
      term_puts("Buffer full, '$' found but '#' not complete. Discarding.\n");
      return -1;
    }
    return 1;
  }

  if (current_sharp + 2 <= gdb_blen) {
    return 0;
  } else {
    if (gdb_blen >= sizeof(gdb_buf)) {
        term_puts("Buffer full, '#' found but checksum incomplete. Discarding.\n");
        return -1;
    }
    return 1;
  }
}

static int
validate_gdb_checksum(unsigned int dollar_idx, unsigned int sharp_idx)
{
  unsigned char calculated_chksum = 0;
  unsigned int i;
  int received_chksum_val;

  for (i = dollar_idx + 1; i < sharp_idx; i++) {
    calculated_chksum += gdb_buf[i];
  }

  received_chksum_val = hex2byte(gdb_buf + sharp_idx + 1);

  if (received_chksum_val == -1) {
      term_puts("Malformed checksum characters in packet, discarding.\n");
      return 1;
  }

  if ((unsigned char)received_chksum_val != calculated_chksum) {
    term_puts("Discard bad checksum packet\n");
    return 1;
  }

  return 0;
}

static int
one_command (void)
{
  unsigned int dollar_idx;
  unsigned int sharp_idx;
  int marker_status;

  while (1)
    {
      gdb_blen = 0;
      dollar_idx = 0;
      sharp_idx = 0;

      while (1)
        {
          if (read_socket_data_chunk() != 0) {
            return 1;
          }

          marker_status = find_gdb_packet_markers(&dollar_idx, &sharp_idx);

          if (marker_status == 0) {
            break;
          } else if (marker_status == -1) {
            goto next_packet_attempt;
          }
        }

      if (validate_gdb_checksum(dollar_idx, sharp_idx) != 0) {
        goto next_packet_attempt;
      } else {
        sock_write((const unsigned char *)"+", 1);
        break;
      }

    next_packet_attempt:;
    }

  unsigned int cmd_offset = dollar_idx + 1;
  unsigned int cmd_length = sharp_idx - dollar_idx - 1;

  if (trace_pkt > 1)
    {
      term_puts("<: ");
      term_write((char *)gdb_buf + dollar_idx, sharp_idx - dollar_idx + 1);
      term_putnl();
    }

  if (handle_packet(gdb_buf + cmd_offset, cmd_length) == 1) {
    return 1;
  }

  send_pkt();
  return 0;
}

/* Display the condition given by SIG64.  */

#include <string.h>

static const unsigned short MESSAGE_BUFFER_SIZE = 160;

static void
display_excp (struct chf64$signal_array *sig64, struct chf$mech_array *mech)
{
  unsigned int status;
  char msg[MESSAGE_BUFFER_SIZE];
  unsigned short msglen;

  (void)memset(msg, 0, sizeof(msg));

  struct dsc$descriptor_s msg_desc =
    { MESSAGE_BUFFER_SIZE, DSC$K_DTYPE_T, DSC$K_CLASS_S, msg };

  unsigned char outadr[4];

  status = SYS$GETMSG (sig64->chf64$q_sig_name, &msglen, &msg_desc, 0, outadr);

  if (status & STS$M_SUCCESS)
    {
      char msg2[MESSAGE_BUFFER_SIZE];
      unsigned short msg2len;

      (void)memset(msg2, 0, sizeof(msg2));

      struct dsc$descriptor_s msg2_desc =
	{ MESSAGE_BUFFER_SIZE, DSC$K_DTYPE_T, DSC$K_CLASS_S, msg2};

      msg_desc.dsc$w_length = msglen;

      status = SYS$FAOL_64 (&msg_desc, &msg2len, &msg2_desc,
			    &sig64->chf64$q_sig_arg1);
      if (status & STS$M_SUCCESS)
	{
	  term_write (msg2, msg2len);
	}
    }
  else
    {
      term_puts ("no message");
    }
  term_putnl ();

  if (trace_excp > 1)
    {
      TERM_FAO (" Frame: !XH, Depth: !4SL, Esf: !XH!/",
		mech->chf$q_mch_frame, mech->chf$q_mch_depth,
		mech->chf$q_mch_esf_addr);
    }
}

/* Get all registers from current thread.  */

static void
read_all_registers (struct chf$mech_array *mech)
{
  struct _intstk *intstk =
    (struct _intstk *)mech->chf$q_mch_esf_addr;
  struct chf64$signal_array *sig64 =
    (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;

  const unsigned int SOF_BITS_MASK = 0x7f;
  const unsigned int BSP_ALIGN_SHIFT = 3;
  const unsigned int BSP_DELTA_MASK = 0x3f;
  const unsigned __int64 CFM_VALUE_MASK = 0x3fffffffffULL;

  unsigned int cnt = sig64->chf64$w_sig_arg_count;
  unsigned __int64 pc = (&sig64->chf64$q_sig_name)[cnt - 2];

  excp_regs.ip.v = pc;
  excp_regs.psr.v = intstk->intstk$q_ipsr;

  {
    unsigned __int64 bsp = intstk->intstk$q_bsp;
    unsigned int sof = intstk->intstk$q_ifs & SOF_BITS_MASK;
    unsigned int delta = ((bsp >> BSP_ALIGN_SHIFT) & BSP_DELTA_MASK) + sof;
    excp_regs.bsp.v = bsp + ((sof + delta / BSP_DELTA_MASK) << BSP_ALIGN_SHIFT);
  }
  
  excp_regs.cfm.v = intstk->intstk$q_ifs & CFM_VALUE_MASK;
  excp_regs.pfs.v = intstk->intstk$q_pfs;
  excp_regs.pr.v = intstk->intstk$q_preds;

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
  
  excp_regs.br[0].v = intstk->intstk$q_b0;
  excp_regs.br[1].v = intstk->intstk$q_b1;
  excp_regs.br[2].v = intstk->intstk$q_b2;
  excp_regs.br[3].v = intstk->intstk$q_b3;
  excp_regs.br[4].v = intstk->intstk$q_b4;
  excp_regs.br[5].v = intstk->intstk$q_b5;
  excp_regs.br[6].v = intstk->intstk$q_b6;
  excp_regs.br[7].v = intstk->intstk$q_b7;
}

/* Write all registers to current thread.  FIXME: not yet complete.  */

struct chf_mech_array {
  void *chf_q_mch_esf_addr;
};

struct _intstk {
  unsigned int intstk_q_ipsr;
};

struct {
  struct {
    unsigned int v;
  } psr;
} excp_regs;

static void
write_all_registers (struct chf_mech_array *mech)
{
  if (mech == NULL) {
    return;
  }

  struct _intstk *intstk_ptr = (struct _intstk *)mech->chf_q_mch_esf_addr;

  if (intstk_ptr == NULL) {
    return;
  }

  intstk_ptr->intstk_q_ipsr = excp_regs.psr.v;
}

/* Do debugging.  Report status to gdb and execute commands.  */

static void
do_debug (struct chf$mech_array *mech)
{
  unsigned int old_ast;
  unsigned int old_sch;
  unsigned int status;

  /* Disable ast.  */
  status = sys$setast (0);
  switch (status)
    {
    case SS$_WASCLR:
      old_ast = 0;
      break;
    case SS$_WASSET:
      old_ast = 1;
      break;
    default:
      /* Should never happen!  */
      lib$signal (status);
    }

  /* Disable thread scheduling.  */
  if (has_threads)
    old_sch = set_thread_scheduling (0);

  read_all_registers (mech);

  /* Send stop reply packet.  */
  packet_status ();
  send_pkt ();

  while (one_command () == 0)
    ;

  write_all_registers (mech);

  /* Re-enable scheduling.  */
  if (has_threads)
    set_thread_scheduling (old_sch);

  /* Re-enable AST.  */
  status = sys$setast (old_ast);
  if (!(status & STS$M_SUCCESS))
    lib$signal (status);
}

/* The condition handler.  That's the core of the stub.  */

#define COND_ID(code) ((code) & STS$M_COND_ID)

static int
excp_handler (struct chf$signal_array *sig,
	      struct chf$mech_array *mech)
{
  struct chf64$signal_array *sig64 =
    (struct chf64$signal_array *)mech->chf$ph_mch_sig64_addr;
  unsigned int code = COND_ID(sig->chf$l_sig_name);
  unsigned int arg_count = sig64->chf64$w_sig_arg_count;
  unsigned __int64 pc = 0; // Initialize PC to 0 for safety before validation
  unsigned int ret_status;
  
  // Self protection against recursion. This static variable is inherently not
  // thread-safe. If this handler can be invoked concurrently by multiple threads,
  // a thread-local storage mechanism should be used instead (e.g., _Thread_local
  // or pthread_getspecific/setspecific). Given the prompt to not alter
  // external functionality, it remains static as in the original code.
  static int in_handler = 0; 

  // Completely ignore some conditions (signaled indirectly by this stub).
  if (code == COND_ID(LIB$_KEYNOTFOU))
    {
      return SS$_RESIGNAL_64;
    }

  // Protect against recursion.
  in_handler++;
  if (in_handler > 1)
    {
      if (in_handler == 2)
	{
	  // Attempt to get PC for logging. If arg_count is insufficient, pc remains 0.
	  const int PC_ARG_OFFSET = 2;
	  if (arg_count >= PC_ARG_OFFSET)
	    {
	      pc = ((unsigned __int64 *)&sig64->chf64$q_sig_name)[arg_count - PC_ARG_OFFSET];
	    }
	  TERM_FAO ("gdbstub: exception in handler (pc=!XH)!!!/", pc);
	}
      sys$exit (sig->chf$l_sig_name); // Exit with the original signal name
    }

  // Retrieve Program Counter (PC) from signal arguments.
  // This requires at least 2 arguments in the signal array for 'pc' to be valid.
  const int PC_ARG_OFFSET = 2;
  if (arg_count < PC_ARG_OFFSET)
    {
      // Malformed signal array: Not enough arguments to extract PC.
      TERM_FAO ("excp_handler: Malformed signal array, arg_count (%u) < %d. Sig: !XL!/", 
                arg_count, PC_ARG_OFFSET, sig->chf$l_sig_name);
      in_handler--; // Decrement before returning for consistency.
      return SS$_RESIGNAL_64; // Re-signal to propagate the error.
    }
  pc = ((unsigned __int64 *)&sig64->chf64$q_sig_name)[arg_count - PC_ARG_OFFSET];


  if (trace_excp)
    TERM_FAO ("excp_handler: code: !XL, pc=!XH!/", code, pc);

  // If break on the entry point, restore the bundle.
  if (code == COND_ID(SS$_BREAK) && pc == entry_pc && entry_pc != 0)
    {
      static unsigned int entry_prot; // Stored protection for entry_pc

      if (trace_entry)
	term_puts ("initial entry breakpoint\n");
      
      page_set_rw (entry_pc, 16, &entry_prot);
      ots$move ((void *)entry_pc, 16, entry_saved);
      __fc (entry_pc); // Flush cache for modified code
      page_restore_rw (entry_pc, 16, entry_prot);
    }

  switch (code)
    {
    case COND_ID(SS$_ACCVIO):
      if (trace_excp <= 1)
	display_excp (sig64, mech);
      // Fall through for SS$_ACCVIO to be handled with other debug-related exceptions.
    case COND_ID(SS$_BREAK):
    case COND_ID(SS$_OPCDEC):
    case COND_ID(SS$_TBIT):
    case COND_ID(SS$_DEBUG):
      if (trace_excp > 1)
	{
	  // _intstk is an internal structure, assume its definition is available.
	  struct _intstk *intstk = (struct _intstk *)mech->chf$q_mch_esf_addr;

	  display_excp (sig64, mech);

	  TERM_FAO (" intstk: !XH!/", intstk);
	  // Loop through signal array elements.
	  // The original loop condition `i < cnt + 1` is preserved,
	  // as is the direct cast `((unsigned __int64 *)sig64)[i]`,
	  // assuming specific memory layout for the signal structure.
	  for (unsigned int i = 0; i < arg_count + 1; i++) 
	    TERM_FAO ("   !XH!/", ((unsigned __int64 *)sig64)[i]);
	}
      do_debug (mech);
      ret_status = SS$_CONTINUE_64;
      break;

    default:
      display_excp (sig64, mech);
      ret_status = SS$_RESIGNAL_64;
      break;
    }

  in_handler--;
  // Discard selected thread registers. This is an external interaction.
  sel_regs_pthread = 0;
  return ret_status;
}

/* Setup internal trace flags according to GDBSTUB$TRACE logical.  */

static void handle_trace_directive(const char *segment_ptr, unsigned short segment_len)
{
  DESCRIPTOR temp_sub_desc;

  temp_sub_desc.dsc$b_dtype = DSC$K_DTYPE_T;
  temp_sub_desc.dsc$b_class = DSC$K_CLASS_S;
  temp_sub_desc.dsc$a_pointer = (char *)segment_ptr;
  temp_sub_desc.dsc$w_length = segment_len;

  for (int j = 0; j < NBR_DEBUG_FLAGS; j++)
  {
    if (str$case_blind_compare(&temp_sub_desc, (void *)&debug_flags[j].name) == 0)
    {
      debug_flags[j].val++;
      return;
    }
  }
  TERM_FAO("GDBSTUB$TRACE: unknown directive !AS!/", &temp_sub_desc);
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
  item_lst[0].ile3$w_length = LNM$C_NAMLENGTH;
  item_lst[0].ile3$w_code = LNM$_STRING;
  item_lst[0].ile3$ps_bufaddr = resstring;
  item_lst[0].ile3$ps_retlen_addr = &len;
  item_lst[1].ile3$w_length = 0;
  item_lst[1].ile3$w_code = 0;

  status = SYS$TRNLNM (0,
                       (void *)&tabdesc,
                       (void *)&logdesc,
                       0,
                       item_lst);

  if (status == SS$_NOLOGNAM)
    return;
  if (!(status & STS$M_SUCCESS))
    LIB$SIGNAL (status);

  unsigned int start = 0;
  for (unsigned int i = 0; i <= len; i++)
  {
    const int is_boundary = (i == len || resstring[i] == ',' || resstring[i] == ';');

    if (is_boundary)
    {
      if (i > start)
      {
        handle_trace_directive(resstring + start, i - start);
      }
      start = i + 1;
    }
  }

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


/* Entry point.  */

static int
stub_start (unsigned __int64 *progxfer, void *cli_util,
	    EIHD *imghdr, IFD *imgfile,
	    unsigned int linkflag, unsigned int cliflag)
{
  static int initialized;
  int i;
  int cnt;
  int is_attached;
  IMCB *imcb;
  unsigned __int64 entry_pc = 0;

  static const int ATTACHED_ARG_COUNT = 4;
  static const int ENTRY_TRACE_START_OFFSET = -2;
  static const int ENTRY_TRACE_END_OFFSET = 8;
  static const unsigned int SEG_FLAG_READ = 0x04;
  static const unsigned int SEG_FLAG_WRITE = 0x02;
  static const unsigned int SEG_FLAG_EXECUTE = 0x01;
  static const unsigned int SEG_FLAG_PROTECTED = 0x01000000;
  static const unsigned int SEG_FLAG_SHORT = 0x04000000;
  static const unsigned int SEG_FLAG_SHARED = 0x08000000;
  static const int BREAKPOINT_SIZE = 16;
  static const unsigned char INITIAL_BREAKPOINT_INSTRUCTIONS[BREAKPOINT_SIZE] =
      { 0x01, 0x08, 0x00, 0x40, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x00 };
  static const char *IMAGE_ACCESS_MODE_CHARS = "KESU";

  if (initialized) {
    term_puts ("gdbstub: re-entry\n");
  } else {
    initialized = 1;
  }

  va_count (cnt);
  is_attached = cnt == ATTACHED_ARG_COUNT;

  term_init ();
  term_puts ("Hello from gdb stub\n");
  trace_init ();

  if (trace_entry && !is_attached) {
    TERM_FAO ("xfer: !XH, imghdr: !XH, ifd: !XH!/",
              progxfer, imghdr, imgfile);
    for (i = ENTRY_TRACE_START_OFFSET; i < ENTRY_TRACE_END_OFFSET; i++) {
      TERM_FAO ("  at !2SW: !XH!/", i, progxfer[i]);
    }
  }

  if (!is_attached) {
    for (i = 0; progxfer[i]; i++) {
      entry_pc = progxfer[i];
    }

    if (trace_entry) {
      if (entry_pc == 0) {
        term_puts ("No entry point\n");
        return 0;
      }
      TERM_FAO ("Entry: !XH!/", entry_pc);
    }
  } else {
    entry_pc = progxfer[0];
  }

  has_threads = 0;
  for (imcb = ctl$gl_imglstptr->imcb$l_flink;
       imcb != ctl$gl_imglstptr;
       imcb = imcb->imcb$l_flink)
    {
      if (ots$strcmp_eql (pthread_rtl_desc.dsc$a_pointer,
			  pthread_rtl_desc.dsc$w_length,
			  imcb->imcb$t_log_image_name + 1,
			  imcb->imcb$t_log_image_name[0])) {
	has_threads = 1;
      }
			  
      if (trace_images) {
	    unsigned int j;
	    LDRIMG *ldrimg = imcb->imcb$l_ldrimg;
	    LDRISD *ldrisd;

	    TERM_FAO ("!XA-!XA ",
		      imcb->imcb$l_starting_address,
		      imcb->imcb$l_end_address);

	    switch (imcb->imcb$b_act_code) {
	    case IMCB$K_MAIN_PROGRAM:
	      term_puts ("prog");
	      break;
	    case IMCB$K_MERGED_IMAGE:
	      term_puts ("mrge");
	      break;
	    case IMCB$K_GLOBAL_IMAGE_SECTION:
	      term_puts ("glob");
	      break;
	    default:
	      term_puts ("????");
	      break;
	    }
	    TERM_FAO (" !AD !40AC!/",
		      1, IMAGE_ACCESS_MODE_CHARS + (imcb->imcb$b_access_mode & 3),
		      imcb->imcb$t_log_image_name);

	    if ((long) ldrimg < 0 || trace_images < 2) {
	      continue;
	    }
	    ldrisd = ldrimg->ldrimg$l_segments;
	    for (j = 0; j < ldrimg->ldrimg$l_segcount; j++) {
	      unsigned int flags = ldrisd[j].ldrisd$i_flags;
	      term_puts ("   ");
	      term_putc (flags & SEG_FLAG_READ ? 'R' : '-');
	      term_putc (flags & SEG_FLAG_WRITE ? 'W' : '-');
	      term_putc (flags & SEG_FLAG_EXECUTE ? 'X' : '-');
	      term_puts (flags & SEG_FLAG_PROTECTED ? " Prot" : "     ");
	      term_puts (flags & SEG_FLAG_SHORT ? " Shrt" : "     ");
	      term_puts (flags & SEG_FLAG_SHARED ? " Shrd" : "     ");
	      TERM_FAO (" !XA-!XA!/",
			ldrisd[j].ldrisd$p_base,
			(unsigned __int64) ldrisd[j].ldrisd$p_base 
			+ ldrisd[j].ldrisd$i_len - 1);
	    }
	    ldrisd = ldrimg->ldrimg$l_dyn_seg;
	    if (ldrisd) {
	      TERM_FAO ("   dynamic            !XA-!XA!/",
			ldrisd->ldrisd$p_base,
			(unsigned __int64) ldrisd->ldrisd$p_base 
			+ ldrisd->ldrisd$i_len - 1);
	    }
      }
    }

  if (has_threads) {
    threads_init ();
  }

  sock_init ();

  {
    unsigned int status;
    status = sys$setexv (0, excp_handler, PSL$C_USER, (__void_ptr32) &prevhnd);
    if (!(status & STS$M_SUCCESS)) {
      LIB$SIGNAL (status);
    }
  }

  if (is_attached) {
    return excp_handler ((struct chf$signal_array *) progxfer[2],
			   (struct chf$mech_array *) progxfer[3]);
  }

  {
    unsigned int entry_prot;
    unsigned int status;
    
    status = page_set_rw (entry_pc, BREAKPOINT_SIZE, &entry_prot);

    if (!(status & STS$M_SUCCESS)) {
	if ((status & STS$M_COND_ID) == (SS$_NOT_PROCESS_VA & STS$M_COND_ID)) {
	    entry_pc = 0;
	    term_puts ("gdbstub: cannot set breakpoint on entry\n");
	} else {
	    LIB$SIGNAL (status);
	}
    }
    
    if (entry_pc != 0) {
	ots$move (entry_saved, BREAKPOINT_SIZE, (void *)entry_pc);
	ots$move ((void *)entry_pc, BREAKPOINT_SIZE, (void *)INITIAL_BREAKPOINT_INSTRUCTIONS);
	__fc (entry_pc);
	page_restore_rw (entry_pc, BREAKPOINT_SIZE, entry_prot);
    }
  }

  if (entry_pc == 0) {
    while (one_command () == 0);
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
