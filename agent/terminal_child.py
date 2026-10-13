"""Fresh child process setup avoids preexec_fn in the threaded agent."""
import os
import sys

if __name__ == '__main__':
    descriptor = int(sys.argv[1])
    argv = sys.argv[2:]
    os.login_tty(descriptor)
    os.execvpe(argv[0], argv, os.environ)
