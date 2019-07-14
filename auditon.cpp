#include <bsm/libbsm.h>
#include <cstdlib>
#include <unistd.h>

#include <string>
#include <unordered_map>

enum class Command {
  GETPOLICY,
  SETPOLICY,
  UNSETPOLICY,
  GETMASK,
  SETMASK,
  UNSETMASK,
  GETCLASS,
  SETCLASS,
  UNSETCLASS
};

static auto usage() {
  fprintf(stderr, "usage: auditon getpolicy\n"
                  "       auditon setpolicy <policy>\n"
                  "       auditon unsetpolicy <policy>\n"
                  "       auditon getmask <pid>\n"
                  "       auditon setmask <pid> <event-classes>\n"
                  "       auditon unsetmask <pid> <event-classes>\n"
                  "       auditon getclass <event-name>\n"
                  "       auditon setclass <event-name> <event-class>\n"
                  "       auditon unsetclass <event-name> <event-class>\n");
  return EXIT_FAILURE;
}

int main(int argc, char **argv) {
  std::unordered_map<std::string, Command> commands{
      {"getpolicy", Command::GETPOLICY},     {"setpolicy", Command::SETPOLICY},
      {"unsetpolicy", Command::UNSETPOLICY}, {"getmask", Command::GETMASK},
      {"setmask", Command::SETMASK},         {"unsetmask", Command::UNSETMASK},
      {"getclass", Command::GETCLASS},       {"setclass", Command::SETCLASS},
      {"unsetclass", Command::UNSETCLASS},
  };

  if (argc <= 1) {
    return usage();
  }

  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
    return usage();
  }

  const auto command = commands.find(argv[1]);
  if (command == commands.end()) {
    fprintf(stderr, "error: unknown command\n");
    return usage();
  }

  if (geteuid() != 0) {
    // Re-exec with sudo.
    char *cmd[argc + 2];
    cmd[0] = "sudo";
    for (int i = 0; i < argc; ++i) {
      cmd[i + 1] = argv[i];
    }
    cmd[argc + 1] = nullptr;
    execvp("sudo", cmd);
  }

  switch (command->second) {
  case Command::GETPOLICY: {
    int policy;
    if (audit_get_policy(&policy)) {
      perror("error");
      return EXIT_FAILURE;
    }

    // Based on known policy names, 128 should always be enough.
    char buf[128];
    auto size = au_poltostr(policy, 128, buf);
    if (size < 0) {
      perror("error");
      return EXIT_FAILURE;
    }
    printf("%.*s\n", (int)size, buf);
    break;
  }
  case Command::SETPOLICY: {
    if (argc != 3) {
      fprintf(stderr, "usage: auditon setpolicy <policy>\n");
      return EXIT_FAILURE;
    }

    int current_policy;
    if (audit_get_policy(&current_policy)) {
      perror("error");
      return EXIT_FAILURE;
    }

    int new_policy;
    if (au_strtopol(argv[2], &new_policy)) {
      perror("error");
      return EXIT_FAILURE;
    }

    int policy = current_policy | new_policy;
    if (audit_set_policy(&policy)) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  case Command::UNSETPOLICY: {
    if (argc != 3) {
      fprintf(stderr, "usage: auditon unsetpolicy <policy>\n");
      return EXIT_FAILURE;
    }

    int current_policy;
    if (audit_get_policy(&current_policy)) {
      perror("error");
      return EXIT_FAILURE;
    }

    int new_policy;
    if (au_strtopol(argv[2], &new_policy)) {
      perror("error");
      return EXIT_FAILURE;
    }

    int policy = current_policy & ~new_policy;
    if (audit_set_policy(&policy)) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  case Command::GETMASK: {
    if (argc != 3) {
      fprintf(stderr, "usage: auditon getmask <pid>\n");
      return EXIT_FAILURE;
    }

    auditpinfo_t api;
    api.ap_pid = atoi(argv[2]);
    if (audit_get_pinfo(&api, sizeof(api))) {
      perror("error");
      return EXIT_FAILURE;
    }

    // For buffer sizing, see "BUGS" section of `man au_mask`.
    // TODO: I don't think the docs are right.
    const size_t bufsize = 128;
    char buf[bufsize];
    if (getauditflagschar(buf, &api.ap_mask, 0)) {
      perror("error");
      return EXIT_FAILURE;
    }
    printf("%s\n", buf);
    break;
  }
  case Command::SETMASK: {
    if (argc != 4) {
      fprintf(stderr, "usage: auditon setmask <pid> <event-classes>\n");
      return EXIT_FAILURE;
    }

    auditpinfo_t api;
    api.ap_pid = atoi(argv[2]);
    if (audit_get_pinfo(&api, sizeof(api))) {
      perror("error");
      return EXIT_FAILURE;
    }

    auto new_mask = api.ap_mask;
    if (getauditflagsbin(argv[3], &new_mask)) {
      perror("error");
      return EXIT_FAILURE;
    }

    api.ap_mask.am_success |= new_mask.am_success;
    api.ap_mask.am_failure |= new_mask.am_failure;
    if (audit_set_pmask(&api, sizeof(api))) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  case Command::UNSETMASK: {
    if (argc != 4) {
      fprintf(stderr, "usage: auditon unsetmask <pid> <event-classes>\n");
      return EXIT_FAILURE;
    }

    auditpinfo_t api;
    api.ap_pid = atoi(argv[2]);
    if (audit_get_pinfo(&api, sizeof(api))) {
      perror("error");
      return EXIT_FAILURE;
    }

    auto new_mask = api.ap_mask;
    if (getauditflagsbin(argv[3], &new_mask)) {
      perror("error");
      return EXIT_FAILURE;
    }

    api.ap_mask.am_success &= ~new_mask.am_success;
    api.ap_mask.am_failure &= ~new_mask.am_failure;
    if (audit_set_pmask(&api, sizeof(api))) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  case Command::GETCLASS: {
    if (argc != 3) {
      fprintf(stderr, "usage: auditon getclass <event-name>\n");
      return EXIT_FAILURE;
    }

    au_evclass_map_t evc_map;
    const auto event_name = argv[2];
    auto event_num = getauevnonam(event_name);
    if (not event_num) {
      perror("error");
      return EXIT_FAILURE;
    }

    evc_map.ec_number = *event_num;
    if (audit_get_class(&evc_map, sizeof(evc_map))) {
      perror("error");
      return EXIT_FAILURE;
    }

    // This function starts an iteration over all class_ent records.
    setauclass();
    bool match = false;
    for (auto class_ent = getauclassent(); class_ent != nullptr;
         class_ent = getauclassent()) {
      auto mask = class_ent->ac_class;
      // Only check singular masks, for example not the "all" mask.
      if (__builtin_popcount(mask) != 1) {
        continue;
      }

      if (evc_map.ec_class & mask) {
        match = true;
        printf("%s,", class_ent->ac_name);
      }
    }
    endauclass();

    if (not match) {
      fprintf(stderr, "error: %s does not belong to any classes\n", event_name);
      return EXIT_FAILURE;
    }

    // This "\b " overwrites the trailing ','
    printf("\b \n");
    break;
  }
  case Command::SETCLASS: {
    if (argc != 4) {
      fprintf(stderr, "usage: auditon setclass <event-name> <event-classes>\n");
      return EXIT_FAILURE;
    }

    au_evclass_map_t evc_map;
    auto event_num = getauevnonam(argv[2]);
    if (not event_num) {
      perror("error");
      return EXIT_FAILURE;
    }

    evc_map.ec_number = *event_num;
    if (audit_get_class(&evc_map, sizeof(evc_map))) {
      perror("error");
      return EXIT_FAILURE;
    }

    const auto class_name = argv[3];
    auto class_ent = getauclassnam(class_name);
    if (not class_ent) {
      perror("error");
      return EXIT_FAILURE;
    }

    evc_map.ec_class |= class_ent->ac_class;
    if (audit_set_class(&evc_map, sizeof(evc_map))) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  case Command::UNSETCLASS: {
    if (argc != 4) {
      fprintf(stderr,
              "usage: auditon unsetclass <event-name> <event-classes>\n");
      return EXIT_FAILURE;
    }

    au_evclass_map_t evc_map;
    auto event_num = getauevnonam(argv[2]);
    if (not event_num) {
      perror("error");
      return EXIT_FAILURE;
    }

    evc_map.ec_number = *event_num;
    if (audit_get_class(&evc_map, sizeof(evc_map))) {
      perror("error");
      return EXIT_FAILURE;
    }

    const auto class_name = argv[3];
    auto class_ent = getauclassnam(class_name);
    if (not class_ent) {
      perror("error");
      return EXIT_FAILURE;
    }

    evc_map.ec_class &= ~class_ent->ac_class;
    if (audit_set_class(&evc_map, sizeof(evc_map))) {
      perror("error");
      return EXIT_FAILURE;
    }
    break;
  }
  }

  return EXIT_SUCCESS;
}
