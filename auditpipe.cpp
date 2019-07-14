/*
  usage:
  sudo %s [flags] | praudit
  sudo %s [flags] > log

  docs:
  man audit_class audit_event audit_control

  example:
  sudo %s +pc,fc,-fr | praudit
*/

#include <bsm/libbsm.h>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <security/audit/audit_ioctl.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

static auto config_failure() {
  perror("error: could not configure /dev/auditpipe");
  return EXIT_FAILURE;
}

static bool keep_running = true;
static void stop_running(int _signal) { keep_running = false; }

#define break_or_fail(MESSAGE)                                                 \
  if (errno == EINTR) {                                                        \
    break;                                                                     \
  }                                                                            \
  perror(MESSAGE);                                                             \
  return EXIT_FAILURE;

int main(int argc, char **argv) {
  if (argc != 2 || strcmp(argv[1], "-h") == 0) {
    fprintf(stderr, "usage: %s <event-classes>\n", argv[0]);
    return EXIT_FAILURE;
  }

  const auto event_classes = argv[1];
  au_mask_t masks;
  if (getauditflagsbin(event_classes, &masks)) {
    perror("error: unknown event class");
    return EXIT_FAILURE;
  }

  if (geteuid() != 0) {
    // Re-exec with sudo.
    char *cmd[] = {"sudo", argv[0], argv[1], nullptr};
    execvp("sudo", cmd);
  }

  if (isatty(STDOUT_FILENO)) {
    fprintf(stderr, "error: cannot print to stdout, try piping to praudit\n");
    return EXIT_FAILURE;
  }

  auto pipe = open("/dev/auditpipe", O_RDONLY);
  if (not pipe) {
    perror("error: could not open /dev/auditpipe");
    return EXIT_FAILURE;
  }

  //
  // See man auditpipe for details on these auditpipe ioctls.

  int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
  if (ioctl(pipe, AUDITPIPE_SET_PRESELECT_MODE, &mode)) {
    return config_failure();
  }

  // Increase the event queue to the largest maximum size.
  u_int max_qlimit;
  if (ioctl(pipe, AUDITPIPE_GET_QLIMIT_MAX, &max_qlimit) ||
      ioctl(pipe, AUDITPIPE_SET_QLIMIT, &max_qlimit)) {
    return config_failure();
  }

  if (ioctl(pipe, AUDITPIPE_SET_PRESELECT_FLAGS, &masks)) {
    return config_failure();
  }

  u_int max_audit_record_size;
  if (ioctl(pipe, AUDITPIPE_GET_MAXAUDITDATA, &max_audit_record_size)) {
    return config_failure();
  }

  struct sigaction act;
  act.sa_handler = stop_running;
  sigaction(SIGINT, &act, nullptr);

  auto buffer_size = max_audit_record_size * max_qlimit;
  auto buffer = new char[buffer_size];

  while (keep_running) {
    auto read_size = read(pipe, buffer, buffer_size);
    if (read_size == -1) {
      break_or_fail("error: failed to read from /dev/auditpipe");
    }

    auto write_size = write(STDOUT_FILENO, buffer, read_size);
    if (write_size == -1) {
      break_or_fail("error: failed to write to stdout");
    }

    if (write_size != read_size) {
      fprintf(stderr, "error: incomplete write to stdout");
      return EXIT_FAILURE;
    }
  }

  delete[] buffer;

  u_int64_t drop_count;
  if (ioctl(pipe, AUDITPIPE_GET_DROPS, &drop_count) == 0) {
    if (drop_count > 0) {
      // Use \n prefix because the interrupt has printed a bare "^C".
      fprintf(stderr, "\nwarning: %llu dropped audit events\n", drop_count);
    }
  }

  return EXIT_SUCCESS;
}
