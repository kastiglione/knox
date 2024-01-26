#include <bsm/libbsm.h>
#include <iostream>
#include <security/audit/audit_ioctl.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

static void shellAppend(std::string &string, char* arg) {
  if (strchr(arg, ' ')) {
    string.push_back('"');
    string.append(arg);
    string.push_back('"');
  } else {
    string.append(arg);
  }
}

static std::string shellJoin(char **strings, int count) {
  if (count <= 0) {
    return "";
  }

  std::string result{};
  shellAppend(result, strings[0]);
  for (auto i = 1; i < count; ++i) {
    result.push_back(' ');
    shellAppend(result, strings[i]);
  }
  return result;
}

static std::string shellJoin(const std::string &path, char **strings, int count) {
  if (path.empty()) {
    return shellJoin(strings, count);
  }

  auto args = shellJoin(&strings[1], count - 1);
  return path + ' ' + args;
}

using unique_file_ptr = std::unique_ptr<FILE, decltype(&fclose)>;

static unique_file_ptr file_open(const char *path, const char *mode) {
  return {fopen(path, mode), &fclose};
}

static unique_file_ptr auditpipe() {
  auto pipe = file_open("/dev/auditpipe", "r");
  unique_file_ptr null_file{nullptr, &fclose};
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
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
#pragma clang diagnostic pop

    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &masks)) {
      return null_file;
    }
  }

  return pipe;
}

int main(int argc, char **argv) {
  if (argc == 1 && not isatty(STDIN_FILENO)) {
    std::cerr << "usage: " << argv[0] << " [<audit-log>]" << std::endl;
    return EXIT_FAILURE;
  }

  if (geteuid() != 0) {
    std::cout << "Re-running as root" << std::endl;
    // TODO: This doesn't need to be in the uncommon case of reading from audit
    // log files owned by the user.
    const char *cmd[argc + 2];
    cmd[0] = "sudo";
    for (int i = 0; i < argc; ++i) {
      cmd[i + 1] = argv[i];
    }
    cmd[argc + 1] = nullptr;
    execvp("sudo", (char **)cmd);
  }

  unique_file_ptr input = argc > 1 ? file_open(argv[1], "r") : auditpipe();
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

    au_execenv_t exec_env{};
    au_path_t path{};
    au_execarg_t exec_args{};

    // Scan through the buffer token by token.
    auto ptr = buffer;
    tokenstr_t tok;
    for (auto left = record_size; left > 0; left -= tok.len, ptr += tok.len) {
      au_fetch_tok(&tok, ptr, left);
      switch (tok.id) {
      case AUT_EXEC_ENV:
        exec_env = tok.tt.execenv;
        break;
      case AUT_PATH:
        path = tok.tt.path;
        break;
      case AUT_EXEC_ARGS:
        // Expects the last path to be the final resolved path.
        //
        // Audit events can contain more than one `au_path_t` token, and they
        // appear to show the command path being resolved step by step. From
        // relative to absolute, and from symlink to real path.
        exec_args = tok.tt.execarg;
        break;
      }
    }

    // If the audit tokens had exec args, print them (and optionally env too).
    if (exec_args.count > 0) {
      if (exec_env.count > 0) {
        auto env = shellJoin(exec_env.text, std::min<uint32_t>(exec_env.count, AUDIT_MAX_ENV));
        std::cout << env << " ";
      }
      std::string full_path{path.path, path.len};
      auto args = shellJoin(full_path, exec_args.text, std::min<uint32_t>(exec_args.count, AUDIT_MAX_ARGS));
      std::cout << args;
      bool truncated = exec_env.count >= AUDIT_MAX_ENV || exec_args.count >= AUDIT_MAX_ARGS;
      if (truncated) {
        std::cout << " [[WARNING - TRUNCATED]]";
      }
      std::cout << std::endl;
    }

    free(buffer);
  }

  return EXIT_SUCCESS;
}
