#include <bsm/libbsm.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <string>
#include <sys/sysctl.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static pid_t
_childPid(const std::unordered_multimap<u_char, tokenstr_t> &tokens) {
  // For posix_spawn, the subject pid is the parent process. The child pid comes
  // from one of the arg token named "child PID".
  auto range = tokens.equal_range(AUT_ARG32);
  for (auto it = range.first; it != range.second; ++it) {
    auto &arg = it->second.tt.arg32;
    if (arg.len > 0 && strcmp(arg.text, "child PID") == 0) {
      return arg.val;
    }
  }

  return 0;
}

static std::vector<pid_t>
_eventPids(const std::unordered_multimap<u_char, tokenstr_t> &tokens) {
  std::vector<pid_t> pids;

  {
    auto range = tokens.equal_range(AUT_PROCESS32);
    for (auto it = range.first; it != range.second; ++it) {
      pids.push_back(it->second.tt.proc32.pid);
    }
  }

  {
    auto range = tokens.equal_range(AUT_SUBJECT32);
    for (auto it = range.first; it != range.second; ++it) {
      pids.push_back(it->second.tt.subj32.pid);
    }
  }

  return pids;
}

static char *_pidExecPath(pid_t pid) {
  int argmax_mib[] = {CTL_KERN, KERN_ARGMAX};
  int argmax = ARG_MAX;
  auto argmax_size = sizeof(size_t);
  if (sysctl(argmax_mib, 2, &argmax, &argmax_size, NULL, 0) != 0) {
    return nullptr;
  }

  char *procargs = (char *)malloc(argmax);

  int procargs_mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
  size_t procargs_size = argmax;
  if (sysctl(procargs_mib, 3, procargs, &procargs_size, NULL, 0) != 0) {
    // Can happen if the pid is already gone.
    return nullptr;
  }

  // Skip past argc count.
  procargs += sizeof(int);
  auto *exec_path = procargs;

  return exec_path;
}

int main(int argc, char **argv) {
  std::unordered_set<std::string> watchedCommands{argv + 1, argv + argc};
  std::unordered_set<pid_t> watchedPids{};
  std::unordered_set<pid_t> ignoredPids{};

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

    bool watched = false;
    for (auto pid : _eventPids(tokens)) {
      if (watchedPids.find(pid) != watchedPids.end()) {
        watched = true;
      }
      else if (ignoredPids.find(pid) == ignoredPids.end()) {
        auto exec_path = _pidExecPath(pid);
        if (not exec_path) {
          // No exec_path can mean that the process no longer exists.
          // TODO: Lookup existing pids at start, so that they're already known.
          continue;
        }

        auto command = basename(exec_path);
        if (watchedCommands.find(command) != watchedCommands.end()) {
          watched = true;
          watchedPids.insert(pid);
        } else {
          ignoredPids.insert(pid);
        }
      }
    }

    auto range = tokens.equal_range(AUT_EXEC_ARGS);
    for (auto it = range.first; it != range.second; ++it) {
      auto &exec_args = it->second.tt.execarg;
      auto command = basename(exec_args.text[0]);
      if (watchedCommands.find(command) != watchedCommands.end()) {
        watched = true;
        auto pid = _childPid(tokens);
        if (pid != 0) {
          watchedPids.insert(_childPid(tokens));
        }
      }
    }

    if (watched) {
      write(STDOUT_FILENO, buffer, record_size);
    }

    free(buffer);
  }

  return 0;
}
