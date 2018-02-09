# Contributing

## Required Skill-set
   - An understanding of the Storj network and [SIP5](https://github.com/Storj/sips/blob/master/sip-0005.md)
   - Practical understanding of cryptographic concepts
   - Experience with some C-like language
   - Understanding of asynchronous programming and event loops
   - An understanding of networking protocols, such as TCP/HTTP
   - Familiarity with unit, integration and e2e testing
   - Familiarity with autotools
   - An understanding of `git` for version control and collaboration
   - Debugging experience

## Share Early, Share Often

It's highly recommended to announce your plans before you start work. Once started, commit your changes in small, clear and atomic commits (see commit messages below). This has several benefits:
   - Avoids duplicate work
   - Get feedback and help to achieve your goals
   - Requires less rebasing or merging from master
   - Improves ability to rebase changes

## Compiling, Debugging and Testing

We strive to do test driven development and cover all critical sections of code.

The test suite is composed of a mix of unit and integration tests. All dependent network components are mocked with reproducible behaviors.

There should not be any known leaks when running `valgrind --leak-check=full ./test/tests`, and there shouldn't be compile warnings with either `gcc` or `clang`.

Using `gdb` is recommended to be used to help identify issues, this can become more tricky on systems such as Windows. However it's possible to compile `gdb` for Windows using Cygwin. Almost all development for Windows can be done using Mingw and Wine, with results then verified on a Windows virtual machine. Please see the [README for details on cross compilation](README.md#cross-compiling-dependencies-from-ubuntu-1604).

## Memory Ownership & Threads

To avoid issues with multi-threaded memory conflicts, it's necessary to make it clear where memory is allocated, free'd, and if it's safe to modify in a thread. This is handled by making it unnecessary to get locks before modifying variables. For an example of this, the `state` types for uploads and downloads can be modified in the main event loop, however should not be modified in the worker pool threads. There is a specific data type for work in the thread pool, that is for the purpose of moving memory between threads.

## Coding Style

- Naming and comments are important, think about yourself after a few months away
- 4 spaces
- Always use brackets, and keep on the same line, except for functions
- The pointer `*` goes next to the name not the type
- Types are defined with a `_t` for example `storj_download_state_t`

## Commit Messages

It's recommended to make atomic commits for each change. This improves the ability to rebase and review changes.

An example commit message:

```
Short description of the changes

More detailed description of changes and potentially the
rational for the changes and any other information that
would help someone looking back at the history may want
to know.
```

## Contributor License Agreement

By submitting pull requests, you agree that your work may be licensed under one of:

    GNU Affero General Public License Version 3 (or later)
    GNU Lesser General Public License Version 2.1 (or later)

You also assert that you have completed the [Contributor License Agreement](https://docs.google.com/forms/d/e/1FAIpQLSdVzD5W8rx-J_jLaPuG31nbOzS8yhNIIu4yHvzonji6NeZ4ig/viewform)
