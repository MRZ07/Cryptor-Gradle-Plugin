# Kotlin String Template Encryption — Design

> **Acceptance bar (set by user):** implement, verify against SamsWorld2 (desktop build + obfuscated JAR run),
> and only then publish a new plugin version.

**Date:** 2026-08-10
**Plugin version:** `v1.9.20` → `v1.9.21` in `build.gradle.kts`
**Status:** Approved design — awaiting implementation plan

---

## Problem

Kotlin string templates such as

```kotlin
"setGameMap Start: $mapLoadType"
```

compile to:

```
aload_1
invokedynamic #7 makeConcatWithConstants:(Lcom/xera/samsworld2/core/screens/play/MapLoadingType;)Ljava/lang/String;
```

with the literal part stored in a **recipe string** in the constant pool:

```
BootstrapMethods:
  7: REF_invokeStatic java/lang/invoke/StringConcatFactory.makeConcatWithConstants
    Method arguments:
      #499 setGameMap Start: \u0001
```

The plugin's `EncryptingMethodVisitor.visitLdcInsn` only sees `LDC` instructions, so the literal
parts of templates are never encrypted. The plaintext templates remain greppable in BOTH the
pre-obfuscation fat JAR and the final obfuscated JAR:

- `GameScreen.class` — `setGameMap Start:`, `setGameMap Ende:`, `Failed to remove disconnected slot`
- `SmokeUiDriver.class` — `SMOKE_* mode=`, `screen=`, `step=` …

Plain `ldc` literals (e.g. `SW2_SMOKE_OK`, `sw2smoke.marker`) ARE encrypted correctly — proof the
existing mechanism works; only `makeConcatWithConstants` sites leak.

## Approach: rewrite `makeConcatWithConstants` indy → `StringBuilder` sequence

Add an `EncryptingMethodVisitor.visitInvokeDynamicInsn` override that replaces the single
`invokedynamic` instruction with an equivalent straight-line `StringBuilder` sequence where each
literal segment passes through the *existing* encrypted-LDC path.

### Why this approach

1. **Universal** — fixes Kotlin templates *and* Java `+` concatenation (both emit
   `StringConcatFactory` indy on JDK 9+), plus any precompiled dependency in the app.
2. **Pool fully cleaned** — two mechanisms combine. (a) The rewrite removes the only reference to
   the bootstrap method, so the `BootstrapMethods` entry is dropped. (b) **Verified during
   prototyping:** ASM's reader-copy mode (`ClassWriter(reader, COMPUTE_MAXS)`) *keeps* dead
   constant-pool entries — the recipe string and old plaintext ldcs survive as unreferenced Utf8s.
   Switching to a non-copy writer (`ClassWriter(COMPUTE_MAXS)` + `ClassReader.EXPAND_FRAMES`)
   rebuilds the pool from references only, pruning those dead entries. The literal text is then
   gone from the class entirely, not just from the obfuscated JAR (ProGuard would also strip the
   dead entries in the final artifact).
3. **No toolchain coupling** — works identically for desktop (ProGuard) and Android (R8 + D8
   desugaring); no reliance on Kotlin compiler flags.
4. **Crash-safe by construction** — see Failure handling below.

### The recipe grammar (verified)

The recipe string in the bootstrap method arguments of `makeConcatWithConstants` is:

| Character       | Meaning                                              |
|-----------------|------------------------------------------------------|
| `\u0001` (`\1`) | **Next** dynamic argument (sequential — not an index) |
| `\u0002` (`\2`) | **Next** constant from `bsmArgs[1..]`                 |
| any other       | literal character (including `\n`, `\t`)              |

Confirmed three ways: JDK 25 `StringConcatFactory.parseRecipe` (only `TAG_ARG='\u0001'`,
`TAG_CONST='\u0002'`), javap output of real SamsWorld2 bytecode (`setGameMap Start: \u0001`,
`Failed to remove disconnected slot \u0001: \u0001`), and an actual runtime run of a recipe
containing a literal `\n`.

`makeConcat` (the simple variant) is handled too: its recipe is implicitly `"\u0001"` repeated
`parameterCount()` times, no constants.

### Per-segment codegen

The method is buffered into an ASM `MethodNode` (tree API); the rewrite is applied in `visitEnd`
once the full instruction list and `maxLocals` are known. `LocalVariablesSorter` was rejected
during integration: its mid-method `newLocal` renumbers pre-existing locals inconsistently and
produces verifier-invalid StackMapTable frames for methods that already have branch targets
(ProGuard `Value in slot N of type SOME_REFERENCE expected, but found: i`). Fresh locals are
instead allocated starting at the method's original `maxLocals`, so they can never collide with
the pre-existing local space; the downstream writer uses `COMPUTE_FRAMES` to rebuild all frames
from the rewritten code.

1. **Prologue** — every dynamic argument is on the operand stack at the indy site. Save each into
   a fresh local starting at `maxLocals` (each local's slot count = its `Type.size`). Arg
   `argTypes[n-1]` is on **top**, so store in reverse index order (`argTypes.indices.reversed()`):
   pop arg0→`slots[0]` last, meaning each slot holds its own argument and loads can proceed in
   forward order.
2. `NEW java/lang/StringBuilder;` `DUP;` `INVOKESPECIAL <init>()V`
3. For each segment:
   - **Literal run** → `LDC(encrypted)` + `invokestatic <decryptor>.<decrypt>(String)String` +
     `INVOKEVIRTUAL StringBuilder.append:(Ljava/lang/String;)Ljava/lang/StringBuilder;`
     — the exact same emission the existing `visitLdcInsn` produces, extracted into a shared helper.
   - **Arg tag `\1`** → load the saved local with the type-matching load opcode, then
     `append` with the descriptor-matched overload: `String`→`(String)`, `Object`→`(Object)`,
     `int`→`(I)`, `long`→`(J)`, `float`→`(F)`, `double`→`(D)`, `char`→`(C)`, `boolean`→`(Z)`,
     `byte`/`short`→`(I)` (widened like String.valueOf).
   - **Constant tag `\2`** → `String.valueOf(constants[i])` baked at build time as an encrypted
     literal run (same as a literal). These are static metadata (e.g. `char`/`int`), so the value
     is known at transform time.
4. `INVOKEVIRTUAL StringBuilder.toString:()Ljava/lang/String;`

Net stack effect: consume N argument slots, push one `String` — identical to the original indy.

### Safety properties

- **Stack-neutral straight-line block, no branch targets** → `ClassWriter.COMPUTE_MAXS` (already
  in use) recomputes `maxStack`; existing `StackMapTable` frames remain valid because verifier
  state at every frame boundary is unchanged.
- **`LocalVariablesSorter`** (asm-commons, already a dependency) assigns non-colliding locals and
  remaps the original code's own local indices consistently with the method access/descriptor.
- **Fail-open**: any shape the parser does not fully understand (param count ≠ `\1` count,
  constants array too short, unknown tag) → **leave the indy untouched + log a warning**. Never
  throw, never corrupt a class. This is the "without crashing" guarantee.
- **65535 guard**: each encrypted literal reuses the existing `modifiedUtf8Length > 65535`
  guard → oversized literals fall back to plaintext LDC so the Utf8 constant limit is never hit.
- **Exclusions honored**: `isExcluded(...)` (kotlin/, java/, android/, StringDecryptor…) already
  skips JDK/stdlib classes before the visitor runs — unchanged.

### Verification / test strategy

**Plugin unit tests** (`src/test/kotlin/`, JUnit 5 pattern already used by `CryptorAudioWrapperTest`):

- Build fixture classes with ASM containing several `makeConcatWithConstants` shapes:
  literal+arg, two args, arg-only (no literal), primitive arg, literal containing `\n`/`\t`,
  a `\2`-constant segment, and a `makeConcat` site.
- Run `transformClass(...)`, inject the decryptor, load via a child-first ClassLoader, invoke
  each fixture method reflectively, assert the decrypted output matches the plaintext expectation.
- Negative case: an intentionally malformed recipe (arg-count mismatch) is left as an indy and
  produces no exception.

**SamsWorld2 integration** (the real acceptance run):

1. Point SamsWorld2 at the local plugin build (dev-local include, not a published version).
2. `./gradlew lwjgl3:proguardJar`.
3. Grep the obfuscated JAR for the previously-leaked templates (`setGameMap Start:`,
   `setGameMap Ende:`, `Failed to remove disconnected slot`, `SMOKE_` template fragments) →
   **expect 0 hits**.
4. Run the obfuscated JAR and confirm it boots without `VerifyError` (plus the existing smoke
   harness keeps passing).
5. Android: class-level leak analysis over the R8 pipeline remains valid (same class files enter
   R8 after encryption); full AAB verification only if an SDK is available.

**Publish** only after 1–4 are green: bump `build.gradle.kts` to `v1.9.21`, commit, tag.

---

## Detailed ASM emission

Pseudo-code for the `visitInvokeDynamicInsn` override (`EncryptingMethodVisitor`):

```
override fun visitInvokeDynamicInsn(name, descriptor, bsm, vararg bsmArgs) {
    if (bsm.owner != "java/lang/invoke/StringConcatFactory") { super.(...); return }
    if (bsm.name !in setOf("makeConcatWithConstants", "makeConcat")) { super.(...); return }

    val argTypes = Type.getArgumentTypes(descriptor)              // dynamic arg types
    val recipe = if (bsm.name == "makeConcat") {
        "\u0001".repeat(argTypes.size)
    } else {
        checkBsmRecipe(bsmArgs[0]) ?: return failOpen(super.(...))
    }
    val constants = bsmArgs.drop(1)                                // \2 metadata
    val segments = parseRecipe(recipe, argTypes.size, constants) ?: return failOpen(super.(...))

    // 1. Save args: descriptor order argTypes[0..n-1], on stack argTypes[n-1] deepest.
    val slots = argTypes.map { sorter.newLocal(it) }
    for (i in argTypes.indices.reversed()) {
        emitVarInsn(argTypes[i].getOpcode(ISTORE), slots[i])
    }

    // 2. StringBuilder
    emitTypeInsn(NEW, "java/lang/StringBuilder")
    emitInsn(DUP)
    emitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)

    // 3. Segments
    for (seg in segments) when (seg) {
        is Literal(run) -> emitEncryptedLdc(mv, run); emitAppend(String)     // shared helper
        is Arg(slot)    -> emitVarInsn(load, slots[slot]); emitAppend(match) // desc-matched
        is Const(value) -> emitEncryptedLdc(mv, String.valueOf(value)); emitAppend(String)
    }

    // 4. toString
    emitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
}
```

`emitEncryptedLdc` is the current `visitLdcInsn` String-body extracted so both paths share the
encryption + 65535-guard + decryptor-call emission.

## Open items (resolved during implementation)

- ~~`LocalVariablesSorter` must wrap the method visitor before `EncryptingMethodVisitor`~~ →
  **rejected during integration** (see Per-segment codegen): mid-method `newLocal` renumbers
  existing locals inconsistently and breaks StackMapTable frames for methods with branch targets.
  Replaced with the `MethodNode` tree API allocating fresh locals above `maxLocals` +
  `COMPUTE_FRAMES`.
- `\2` constants: enforce the same count invariant the JDK enforces; mismatch → fail-open.
- Long templates with many segments: fine, each literal is independently guarded.