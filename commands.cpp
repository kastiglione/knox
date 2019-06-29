#include <bsm/libbsm.h>
#include <cstdlib>

// Print the strings in a given au_execarg_t or au_execenv_t record.
template <typename T>
static void printStrings(const T &strings, const char *term) {
  printf("%s", strings.text[0]);
  for (auto i = 1; i < strings.count; ++i) {
    printf(" %s", strings.text[i]);
  }
  printf("%s", term);
}

int main(int argc, char **argv) {
  while (true) {
    // Read an audit event, which is a buffer of tokens.
    u_char *buffer = nullptr;
    const auto record_size = au_read_rec(stdin, &buffer);
    if (record_size == 0) {
      // End of input.
      break;
    }

    au_execarg_t exec_args{};
    au_execenv_t exec_env{};

    // Scan through the buffer token by token.
    auto ptr = buffer;
    tokenstr_t tok;
    for (auto left = record_size; left > 0; left -= tok.len, ptr += tok.len) {
      au_fetch_tok(&tok, ptr, left);
      if (tok.id == AUT_EXEC_ARGS) {
        exec_args = tok.tt.execarg;
      } else if (tok.id == AUT_EXEC_ENV) {
        exec_env = tok.tt.execenv;
      }
    }

    // If the audit tokens had exec args, print them (and optionally env too).
    if (exec_args.count > 0) {
      if (exec_env.count > 0) {
        printStrings(exec_env, " ");
      }
      printStrings(exec_args, "\n");
    }

    free(buffer);
  }

  return EXIT_SUCCESS;
}
