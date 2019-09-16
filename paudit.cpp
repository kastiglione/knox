#include <bsm/libbsm.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

static pid_t
_eventPid(const std::unordered_multimap<u_char, tokenstr_t> &tokens) {
  // Generally the pid comes from the subject token. However for posix_spawn,
  // the subject pid is the parent process, the one that called posix_spawn. The
  // child pid comes from one of the arg tokens, the one named "child PID".
  for (auto it = tokens.find(AUT_ARG32); it != tokens.end(); ++it) {
    auto &arg = it->second.tt.arg32;
    if (arg.len > 0 && strcmp(arg.text, "child PID") == 0) {
      return arg.val;
    }
  }

  for (auto it = tokens.find(AUT_SUBJECT32); it != tokens.end(); ++it) {
    return it->second.tt.subj32.pid;
  }

  return 0;
}

int main(int argc, char **argv) {
  std::unordered_set<std::string> watchedCommands{argv + 1, argv + argc};
  std::unordered_set<pid_t> watchedPids{};

  std::unordered_multimap<u_char, tokenstr_t> tokens;
  auto input = stdin;
  while (feof(input) == 0) {
    u_char *buffer = nullptr;
    auto record_size = au_read_rec(input, &buffer);
    if (record_size == 0) {
      break;
    }

    auto cursor = buffer;
    auto remaining = record_size;
    tokens.clear();
    while (remaining > 0) {
      tokenstr_t token;
      au_fetch_tok(&token, cursor, remaining);
      tokens.emplace(token.id, token);
      remaining -= token.len;
      cursor += token.len;
    }

    for (const auto &pair : tokens) {
      const auto &token = pair.second;
      bool match = false;

      switch (token.id) {
      case AUT_EXEC_ARGS: {
        auto &exec_arg = token.tt.execarg;
        auto command = basename(exec_arg.text[0]);
        if (watchedCommands.find(command) != watchedCommands.end()) {
          auto pid = _eventPid(tokens);
#ifdef DEBUG
          fprintf(stderr, "found: %s (%d)\n", exec_arg.text[0], pid);
#endif
          watchedPids.insert(pid);
          match = true;
        }
        break;
      }
      case AUT_SUBJECT32: {
        auto &subject = token.tt.subj32;
        if (watchedPids.find(subject.pid) != watchedPids.end()) {
          match = true;
        }
        break;
      }
      case AUT_PROCESS32:
        auto &process = token.tt.proc32;
        if (watchedPids.find(process.pid) != watchedPids.end()) {
          match = true;
        }
        break;
      }

      if (match) {
        write(STDOUT_FILENO, buffer, record_size);
        break;
      }
    }

    free(buffer);
  }

  return 0;
}
