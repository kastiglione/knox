#include <bsm/libbsm.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string>
#include <unordered_set>
#include <libgen.h>

using file_unique_ptr = std::unique_ptr<FILE, decltype(&fclose)>;

static file_unique_ptr file_open(const char *path, const char *mode) {
  return {fopen(path, mode), &fclose};
}

static file_unique_ptr auditpipe() {
  auto pipe = file_open("/dev/auditpipe", "r");
  file_unique_ptr null_file{nullptr, &fclose};
  if (not pipe) {
    return null_file;
  }

  //
  // Setup the `ex` event class. This is a hypothetical optimization.
  //
  // By default, the `pc` class includes the two events we want, `execve` and
  // `posix_spawn`, while the `ex` event class includes only `execve`. However,
  // the `pc` event class includes many other event's we're not interested in,
  // while the `ex` event class has very few events.
  {
    auto event_num = getauevnonam("AUE_POSIX_SPAWN");
    if (not event_num) {
      return null_file;
    }

    au_evclass_map_t evc_map{};
    evc_map.ec_number = *event_num;
    if (audit_get_class(&evc_map, sizeof(evc_map))) {
      return null_file;
    }

    auto class_ent = getauclassnam("ex");
    if (not class_ent) {
      return null_file;
    }

    auto current_mask = evc_map.ec_class;
    evc_map.ec_class |= class_ent->ac_class;
    if (evc_map.ec_class != current_mask) {
      if (audit_set_class(&evc_map, sizeof(evc_map))) {
        return null_file;
      }
    }
  }

  //
  // See man auditpipe for details on these auditpipe ioctls.
  {
    auto fd = fileno(pipe.get());
    int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode)) {
      return null_file;
    }

    // Increase the event queue to the largest maximum size.
    u_int max_qlimit;
    if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &max_qlimit) ||
        ioctl(fd, AUDITPIPE_SET_QLIMIT, &max_qlimit)) {
      return null_file;
    }

    au_mask_t masks;
    if (getauditflagsbin((char *)"+ex", &masks)) {
      return null_file;
    }

    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &masks)) {
      return null_file;
    }
  }

  return pipe;
}

int main(int argc, char **argv) {
  if (argc <= 1) {
    fprintf(stderr, "usage: %s <command-name> [<command-name>...]\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (geteuid() != 0) {
    // Re-exec with sudo.
    const char *cmd[argc + 2];
    cmd[0] = "sudo";
    for (int i = 0; i < argc; ++i) {
      cmd[i + 1] = argv[i];
    }
    cmd[argc + 1] = nullptr;
    execvp("sudo", (char **)cmd);
  }

  const std::unordered_set<std::string> waitCommands{argv + 1, argv + argc};

  file_unique_ptr input = auditpipe();
  if (not input) {
    perror("error");
    return EXIT_FAILURE;
  }

  while (feof(input.get()) == 0) {
    // Read an audit event, which is a buffer of tokens.
    u_char *buffer = nullptr;
    const auto record_size = au_read_rec(input.get(), &buffer);
    if (record_size == 0) {
      // End of input.
      break;
    }

    // Scan through the buffer token by token.
    auto cursor = buffer;
    auto remaining = record_size;
    while (remaining > 0) {
      tokenstr_t token;
      au_fetch_tok(&token, cursor, remaining);
      remaining -= token.len;
      cursor += token.len;

      if (token.id == AUT_EXEC_ARGS) {
        auto &exec_args = token.tt.execarg;
        auto command = basename(exec_args.text[0]);
        if (waitCommands.find(command) != waitCommands.end()) {
          // Could return the pid here.
          return EXIT_SUCCESS;
        } else {
          // This audit event is not a match, stop scanning these tokens.
          break;
        }
      }
    }

    free(buffer);
  }

  return EXIT_SUCCESS;
}
