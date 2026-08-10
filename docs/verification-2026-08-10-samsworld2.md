# SamsWorld2 integration verification — v1.9.21 (2026-08-10)

Evidence for the Task 6 acceptance run. Commands were run in the SamsWorld2 worktree
`/Users/RASHEEM/orca/workspaces/SamsWorld2/proguard`.

## Build

```
./gradlew lwjgl3:proguardJar        # ProGuard config: -optimizationpasses 2
BUILD SUCCESSFUL
Output: lwjgl3/build/lib/SamsWorld2-obfuscated-0.1.jar (modified 2026-08-10 15:13)
```

## Leak grep (acceptance bar = 0 hits)

```bash
cd lwjgl3/build/lib
unzip -p SamsWorld2-obfuscated-0.1.jar '*.class' | strings | grep -cE 'setGameMap Start:|setGameMap Ende:|Failed to remove disconnected slot|Controller .* generation .* is not current'
# → 0

unzip -p SamsWorld2-obfuscated-0.1.jar '*.class' | strings | grep -c 'SMOKE_'
# → 0
```

Remaining `generation` occurrences are NOT template leaks:
- `generation` ×2 — the obfuscated field name (`getGeneration-AUrn3Ow` → field), a legitimate identifier.
- `$Impossible JSON generation exception` — inside `com.dropbox.core.stone.StoneSerializer` (Dropbox SDK library class, never transformed by the plugin). Out of scope.

## Smoke test

```bash
java -jar lwjgl3/build/lib/SamsWorld2-obfuscated-0.1.jar   # 60s run, then SIGTERM
```
Result: ran 60s without crash. Log contained only benign JVM/LWJGL warnings
(`sun.misc.Unsafe` deprecation, `System.load` native-access) — standard for Java 25 + LWJGL.
No `VerifyError`, no `NoClassDefFoundError`, no `BootstrapMethodError`.

## Related commits

- Plugin repo: `1be2e04 fix: rewrite templates via MethodNode to keep stack map frames valid`
  (root cause of the initial `Value in slot 11 ... SOME_REFERENCE expected, but found: i`
  ProGuard failure: `LocalVariablesSorter` produced verifier-invalid StackMapTable frames for
  methods with branch targets; fixed via ASM tree API allocating fresh locals above maxLocals).
- SamsWorld2 worktree: `e8809699a chore: bump Cryptor plugin to v1.9.21`,
  `d9f5ecaee perf: reduce proguard optimization passes from 8 to 2`.

---

## v1.9.22 re-verification (2026-08-10)

Follow-up release fixing the final-review finding: `getCommonSuperClass` now resolves frame
merges via (1) the project hierarchy map, (2) ASM's Class.forName fallback, (3) Object.
`COMPUTE_FRAMES` runs only on classes containing a StringConcatFactory indy.

- Plugin tests: 19/19 pass (added frame-merge hierarchy resolution, float/double/boolean/char
  args, try/catch with executed handler, oversized-literal 65535-guard fallback).
- SamsWorld2 `proguard` worktree bumped to v1.9.22; `lwjgl3:proguardJar` rebuilt
  (SamsWorld2-obfuscated-0.1.jar, modified 2026-08-10 16:47).
- Leak grep: template hits = 0, SMOKE_ = 0 (identical commands as above).
- Smoke test: 45s crash-free run, no verifier/classloading/bootstrap errors.
- SamsWorld2 main + SamsWorld pushed; feature worktrees (proguard-fork, mp-fixes, lanternfish)
  bumped locally (mp-fixes swept-in refactor separated back into uncommitted work).
